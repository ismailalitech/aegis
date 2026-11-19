// SPDX-License-Identifier: Apache-2.0
/*
 * Aegis post-quantum attestation as an OP-TEE trusted application on the Zynq UltraScale+ (docs/zynqmp-key-design.md).
 *
 * The protocol code is the one the RW612's TF-M partition runs (endpoints/rw612/prover/src/aegis_proto.c): PQKEY,
 * PQCHAL, PQKEMINIT, PQKEMFIN, PQHB, PQSESSION, one line in and one line out. Linux only carries the lines
 * (endpoints/zynqmp/optee/bridge): it never holds the key, the seed or the session.
 *
 * Keys: seed and provisioning root come from OP-TEE's system PTA (PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY), that is from the
 * hardware unique key (HUK) and this TA's UUID. Where the HUK comes from is asked of OP-TEE's "aegis.boot" PTA
 * (aegis_boot_pta.h, added by ../os-patches), and the profile follows:
 *   aegis-zynqmp-optee-v1         the FSBL handed over a seed derived under the PUF-protected device key (flags
 *                                 SEED_VALID and KEY_BH_BLACK) and OP-TEE made its HUK from it: the key belongs to
 *                                 the chip;
 *   aegis-zynqmp-optee-devhuk-v1  anything else (no hand-off, no such seed, or an OP-TEE without the PTA): the HUK
 *                                 is OP-TEE's default (zero on this platform), the same on every chip.
 *
 * Session clock (docs/endpoint-expiry.md): TEE_GetSystemTime. OP-TEE on this platform derives it from the physical
 * counter (CNTPCT_EL0 / CNTFRQ_EL0, CFG_SECURE_TIME_SOURCE_CNTPCT): the normal world can neither write the counter nor
 * its frequency register (CNTVOFF_EL2 moves only the virtual counter it sees itself). The TA asks OP-TEE for the
 * time's protection level once and, below 1000 (a time taken from Linux), reports no clock: no session then starts.
 *
 * Measurements: the hand-off's list, as the FSBL took it. Without a hand-off the claims carry one component,
 * BOOTCHAIN, with a zero value and the description "not measured", so a verifier cannot mistake it for a
 * measurement.
 */
#include <string.h>
#include <stdio.h>
#include <tee_internal_api.h>
#include <pta_system.h>

#include "aegis_ta.h"
#include "user_ta_header_defines.h"
#include "aegis_boot_pta.h"
#include "aegis_proto.h"
#include "gateway_pk.h"

#define PROFILE_CHIP   "aegis-zynqmp-optee-v1"
#define PROFILE_DEVHUK "aegis-zynqmp-optee-devhuk-v1"

/* every entry of the hand-off is reported, and the claims fit their buffer (aegis_proto.c writes them without a
 * length check): 121 bytes with the longer profile name, then per component 81 with a 5-character version, a label
 * of up to 15 and a description of up to 63 characters behind a 2-byte head */
_Static_assert(AEGIS_MAX_MEASUREMENTS >= AEGIS_HANDOFF_MAX_MEAS, "measurements");
_Static_assert(sizeof(PROFILE_DEVHUK) - 1 <= 28 && sizeof(AEGIS_DEVICE_VERSION) - 1 <= 23, "claims header");
_Static_assert(AEGIS_CLAIMS_MAX >= 121 + AEGIS_MAX_MEASUREMENTS * (76 + sizeof(AEGIS_DEVICE_VERSION) - 1 + 15 + 2 + 63),
	       "claims buffer");
_Static_assert(AEGIS_REPLY_MAX >= 2 * (AEGIS_CLAIMS_MAX + 3309) + 64, "PQCHAL reply");

static const uint8_t gateway_pk[1952] = AEGIS_GATEWAY_PK;
/* what OP-TEE kept of the FSBL's hand-off; all zero (AEGIS_BOOT_HO_ABSENT) when there is none */
static struct {
	uint32_t status, flags, bh_key_src, csu_status, count, huk;
	struct aegis_ho_meas meas[AEGIS_HANDOFF_MAX_MEAS];
} boot;
static int ready;
static int clock_trusted;
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

static int s_monotonic(uint64_t *now)
{
	TEE_Time t = { };

	if (!clock_trusted)
		return -1;
	TEE_GetSystemTime(&t);
	*now = t.seconds;
	return 0;
}

static size_t s_measure_all(struct aegis_measurement *m, size_t max)
{
	size_t n;

	if (max < 1)
		return 0;
	if (boot.status != AEGIS_BOOT_HO_VALID || boot.count == 0) {
		m[0].label = "BOOTCHAIN";
		memset(m[0].value, 0, sizeof(m[0].value));
		snprintf(m[0].desc, sizeof(m[0].desc), "not measured (%s)",
			 boot.status == AEGIS_BOOT_HO_VALID ? "the boot hand-off has no measurement" :
			 boot.status == AEGIS_BOOT_HO_REJECTED ? "boot hand-off rejected" :
			 "phase A: no boot hand-off");
		return 1;
	}
	for (n = 0; n < boot.count && n < max; n++) {
		m[n].label = boot.meas[n].label;
		memcpy(m[n].value, boot.meas[n].value, sizeof(m[n].value));
		snprintf(m[n].desc, sizeof(m[n].desc), "SHA3-384/256 of partition %s as stored (%u bytes)",
			 boot.meas[n].label, (unsigned int)boot.meas[n].length);
	}
	return n;
}

static int s_status(char *buf, size_t cap)
{
	return snprintf(buf, cap, "requests=%u;fw=zynqmp-optee-%s", (unsigned int)served, TA_VERSION);
}

static struct aegis_proto_platform platform = {
	.random = s_random,
	.measure = s_measure_unused,
	.uptime_s = s_uptime_s,
	.monotonic_s = s_monotonic,
	.profile = PROFILE_DEVHUK, /* query_boot() decides */
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

/* Ask OP-TEE's aegis.boot PTA for the hand-off. An OP-TEE without it (TEE_ERROR_ITEM_NOT_FOUND) or any failure
 * leaves "no hand-off". */
static void query_boot(void)
{
	static const TEE_UUID pta = PTA_AEGIS_BOOT_UUID;
	const uint32_t need = AEGIS_HO_SEED_VALID | AEGIS_HO_KEY_BH_BLACK;
	TEE_TASessionHandle s = TEE_HANDLE_NULL;
	TEE_Param p[TEE_NUM_PARAMS] = { };
	uint32_t ro = 0;
	TEE_Result res;

	memset(&boot, 0, sizeof(boot));
	platform.profile = PROFILE_DEVHUK;
	res = TEE_OpenTASession(&pta, TEE_TIMEOUT_INFINITE, 0, NULL, &s, &ro);
	if (res != TEE_SUCCESS) {
		IMSG("Aegis TA: no aegis.boot PTA (%#x)", (unsigned int)res);
		return;
	}
	p[3].memref.buffer = boot.meas;
	p[3].memref.size = sizeof(boot.meas);
	res = TEE_InvokeTACommand(s, TEE_TIMEOUT_INFINITE, PTA_AEGIS_BOOT_CMD_GET_INFO,
				  TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
						  TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT),
				  p, &ro);
	TEE_CloseTASession(s);
	if (res != TEE_SUCCESS || p[2].value.a > AEGIS_HANDOFF_MAX_MEAS ||
	    p[3].memref.size != p[2].value.a * sizeof(boot.meas[0])) {
		EMSG("Aegis TA: aegis.boot failed (%#x)", (unsigned int)res);
		memset(&boot, 0, sizeof(boot));
		return;
	}
	boot.status = p[0].value.a;
	boot.flags = p[0].value.b;
	boot.bh_key_src = p[1].value.a;
	boot.csu_status = p[1].value.b;
	boot.count = p[2].value.a;
	boot.huk = p[2].value.b;
	for (uint32_t i = 0; i < AEGIS_HANDOFF_MAX_MEAS; i++)
		boot.meas[i].label[sizeof(boot.meas[i].label) - 1] = '\0';
	if (boot.status == AEGIS_BOOT_HO_VALID && boot.huk == AEGIS_BOOT_HUK_SEED && (boot.flags & need) == need)
		platform.profile = PROFILE_CHIP;
}

TEE_Result TA_CreateEntryPoint(void)
{
	uint8_t seed[32], root[32];
	uint32_t level = 0;
	TEE_Result res;

	/* 1000: a hardware counter the normal world cannot change; 100: a time it controls */
	clock_trusted = TEE_GetPropertyAsU32(TEE_PROPSET_TEE_IMPLEMENTATION, "gpd.tee.systemTime.protectionLevel",
					     &level) == TEE_SUCCESS && level >= 1000;
	query_boot();
	res = derive("aegis-zynqmp-mldsa65-seed-v1", seed);
	if (res == TEE_SUCCESS)
		res = derive("aegis-zynqmp-provision-root-v1", root);
	if (res == TEE_SUCCESS && aegis_proto_init(&platform, seed, root, gateway_pk) != 0)
		res = TEE_ERROR_GENERIC;
	TEE_MemFill(seed, 0, sizeof(seed));
	TEE_MemFill(root, 0, sizeof(root));
	ready = (res == TEE_SUCCESS);
	if (ready)
		IMSG("Aegis TA: key ready, profile %s, hand-off status %u flags %#x bh_key_src %#x csu_status %#x, "
		     "%u measurements, session clock %s (level %u)", platform.profile, (unsigned int)boot.status,
		     (unsigned int)boot.flags, (unsigned int)boot.bh_key_src, (unsigned int)boot.csu_status,
		     (unsigned int)boot.count, clock_trusted ? "trusted" : "NOT trusted: no sessions",
		     (unsigned int)level);
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
