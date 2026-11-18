// SPDX-License-Identifier: Apache-2.0
/*
 * Aegis post-quantum attestation as an OP-TEE trusted application on the Zynq UltraScale+ (docs/zynqmp-key-design.md).
 *
 * The protocol code is the one the RW612's TF-M partition runs (endpoints/rw612/prover/src/aegis_proto.c): PQKEY,
 * PQCHAL, PQKEMINIT, PQKEMFIN, PQHB, PQSESSION, one line in and one line out. Linux only carries the lines
 * (endpoints/zynqmp/optee/bridge): it never holds the key, the seed or the session.
 *
 * Keys: seed and provisioning root come from OP-TEE's system PTA (PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY), that is from the
 * hardware unique key (HUK) and this TA's UUID. Phase A: the HUK is OP-TEE's default (zero on this platform), so the
 * key is the same on every chip and the profile says so ("-devhuk"); phase B gives OP-TEE a HUK derived in the FSBL
 * from the PUF-protected device key.
 *
 * Measurements: phase A has no hand-off from the boot chain yet. The claims carry one component, BOOTCHAIN, with a
 * zero value and the description "not measured", so a verifier cannot mistake it for a measurement.
 */
#include <string.h>
#include <stdio.h>
#include <tee_internal_api.h>
#include <pta_system.h>

#include "aegis_ta.h"
#include "user_ta_header_defines.h"
#include "aegis_proto.h"
#include "gateway_pk.h"

#ifndef AEGIS_ZYNQMP_PROFILE
#define AEGIS_ZYNQMP_PROFILE "aegis-zynqmp-optee-devhuk-v1"
#endif

static const uint8_t gateway_pk[1952] = AEGIS_GATEWAY_PK;
static int ready;
static uint32_t served;
static char line[AEGIS_TA_LINE_MAX + 1];
static char reply[AEGIS_TA_REPLY_MAX];

static int s_random(uint8_t *out, size_t n)
{
	TEE_GenerateRandom(out, n);
	return 0;
}

static void s_measure_unused(uint8_t out[32], size_t *len)
{
	memset(out, 0, 32);
	*len = 0;
}

static uint32_t s_uptime_s(void)
{
	TEE_Time t = { };

	TEE_GetSystemTime(&t);
	return t.seconds;
}

static size_t s_measure_all(struct aegis_measurement *m, size_t max)
{
	if (max < 1)
		return 0;
	m[0].label = "BOOTCHAIN";
	memset(m[0].value, 0, sizeof(m[0].value));
	snprintf(m[0].desc, sizeof(m[0].desc), "not measured (phase A: no boot hand-off)");
	return 1;
}

static int s_status(char *buf, size_t cap)
{
	return snprintf(buf, cap, "requests=%u;fw=zynqmp-optee-%s", (unsigned int)served, TA_VERSION);
}

static const struct aegis_proto_platform platform = {
	.random = s_random,
	.measure = s_measure_unused,
	.uptime_s = s_uptime_s,
	.profile = AEGIS_ZYNQMP_PROFILE,
	.measure_all = s_measure_all,
	.status = s_status,
};

/* 32 bytes from the HUK and this TA's UUID, bound to a label (OP-TEE's huk_subkey_derive) */
static TEE_Result derive(const char *label, uint8_t out[32])
{
	static const TEE_UUID sys = PTA_SYSTEM_UUID;
	TEE_TASessionHandle s = TEE_HANDLE_NULL;
	TEE_Param p[TEE_NUM_PARAMS] = { };
	uint32_t ro = 0;
	TEE_Result res;

	res = TEE_OpenTASession(&sys, TEE_TIMEOUT_INFINITE, 0, NULL, &s, &ro);
	if (res != TEE_SUCCESS)
		return res;
	p[0].memref.buffer = (void *)label;
	p[0].memref.size = strlen(label);
	p[1].memref.buffer = out;
	p[1].memref.size = 32;
	res = TEE_InvokeTACommand(s, TEE_TIMEOUT_INFINITE, PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY,
				  TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
						  TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE),
				  p, &ro);
	TEE_CloseTASession(s);
	if (res == TEE_SUCCESS && p[1].memref.size != 32)
		res = TEE_ERROR_GENERIC;
	return res;
}

TEE_Result TA_CreateEntryPoint(void)
{
	uint8_t seed[32], root[32];
	TEE_Result res;

	res = derive("aegis-zynqmp-mldsa65-seed-v1", seed);
	if (res == TEE_SUCCESS)
		res = derive("aegis-zynqmp-provision-root-v1", root);
	if (res == TEE_SUCCESS && aegis_proto_init(&platform, seed, root, gateway_pk) != 0)
		res = TEE_ERROR_GENERIC;
	TEE_MemFill(seed, 0, sizeof(seed));
	TEE_MemFill(root, 0, sizeof(root));
	ready = (res == TEE_SUCCESS);
	if (ready)
		IMSG("Aegis TA: key ready");
	else
		EMSG("Aegis TA: key FAILED");
	return res;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t pt, TEE_Param params[TEE_NUM_PARAMS], void **sess)
{
	(void)pt;
	(void)params;
	(void)sess;
	return ready ? TEE_SUCCESS : TEE_ERROR_BAD_STATE;
}

void TA_CloseSessionEntryPoint(void *sess)
{
	(void)sess;
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess, uint32_t cmd, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS])
{
	const uint32_t want = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT,
					      TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	size_t n;
	int r;

	(void)sess;
	if (cmd != AEGIS_TA_CMD_LINE || pt != want)
		return TEE_ERROR_BAD_PARAMETERS;
	n = params[0].memref.size;
	if (n > AEGIS_TA_LINE_MAX)
		return TEE_ERROR_SHORT_BUFFER;
	/* copy in first: the shared buffer stays writable by Linux while the TA works */
	memcpy(line, params[0].memref.buffer, n);
	line[n] = '\0';
	served++;
	r = aegis_proto_handle(line, reply, sizeof(reply));
	if (r < 0 || (size_t)r > sizeof(reply))
		return TEE_ERROR_GENERIC;
	if (params[1].memref.size < (size_t)r) {
		params[1].memref.size = (size_t)r;
		return TEE_ERROR_SHORT_BUFFER;
	}
	memcpy(params[1].memref.buffer, reply, (size_t)r);
	params[1].memref.size = (size_t)r;
	return TEE_SUCCESS;
}
