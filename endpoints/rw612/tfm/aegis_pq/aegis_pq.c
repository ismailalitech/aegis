/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis post-quantum attestation partition for TF-M on the NXP RW612 (FRDM-RW612), NXP's TF-M fork v2.1.4.
 *
 * PSA-RoT, SFN model, one stateless service AEGIS_PQ_SERVICE (SID 0xAE10), non-secure clients allowed.
 *
 * At initialisation, before the non-secure image runs:
 *   seed, prov_root = ELS: HMAC-SHA256(CKDF(die master key in slot 0), label)   (aegis_els.c; the die key and the
 *                     temporary key stay inside ELS, which TF-M makes secure-privileged only)
 *   (pk, sk)        = ML-DSA-65.KeyGen_internal(seed); the seed is wiped
 *   SPE             = SHA-256 of the whole secure partition in flash   (0x18001000 .. 0x1809FFFF, 0x9F000 bytes)
 *   NSPE            = SHA-256 of the whole non-secure partition        (0x180A0000 .. 0x1839FFFF, 0x300000 bytes)
 *   Whole partitions, not image lengths: nothing can hide after a declared end, and the reference value is the
 *   image padded with 0xFF (the flashing script erases both partitions first).
 *
 * Service, message type AEGIS_PQ_LINE (1):
 *   in[0]  = one request line of the Aegis line protocol (PQKEY, PQCHAL, PQKEMINIT, PQKEMFIN, PQHB, PQSESSION)
 *   out[0] <- the reply line
 *   The protocol code is the one the Zephyr prover and the PC tests use (endpoints/rw612/prover/src/aegis_proto.c),
 *   so the non-secure image is only a network pipe: it never holds a key, a seed or the session, and it cannot
 *   change a measurement.
 */
#include <stdio.h>
#include <string.h>

#include "psa/service.h"
#include "psa_manifest/aegis_pq.h"
#include "fsl_device_registers.h"
#include "fsl_clock.h"
#include "fsl_reset.h"
#include "pin_mux.h"
#include <mcuxClEls.h>
#include <mcuxClCore_FunctionIdentifiers.h>
#include <mcuxCsslFlowProtection.h>

#include "aegis_els.h"
#include "aegis_proto.h"
#include "aegis_pq_defs.h"
#include "gateway_pk.h"
#include "aegis_sha256.h"
#include "tfm_sp_log.h"

#define S_PART_BASE  0x18001000u
#define S_PART_SIZE  0x0009F000u
#define NS_PART_BASE 0x180A0000u /* the non-secure partition, read through the secure alias */
#define NS_PART_SIZE 0x00300000u

static const uint8_t gateway_pk[1952] = AEGIS_GATEWAY_PK;
static struct aegis_measurement meas[2];
static int ready, key_tried, key_rc;
static uint32_t served;
static char line[AEGIS_LINE_MAX + 1];
static char reply[AEGIS_REPLY_MAX];

/* The partition's stack (auto_generated/intermedia_aegis_pq.c; its size is stack_size in aegis_pq.yaml). At
 * initialisation the part below the current frame is filled with a pattern; the status reports how much of the
 * stack has ever been used, so every heartbeat carries the high-water mark to the gateway. TF-M sets the stack limit
 * register to the stack's base, so an overflow faults rather than writing past it; this shows the margin. */
extern uint8_t tfm_sp_aegis_pq_stack[];
#define AEGIS_PQ_STACK_SIZE 0x8000u
#define STACK_FILL 0xA5u
static int stack_filled;

static uintptr_t current_sp(void)
{
	uintptr_t sp;

	__asm volatile("mov %0, sp" : "=r"(sp));
	return sp;
}

static void stack_fill(void)
{
	uintptr_t lo = (uintptr_t)tfm_sp_aegis_pq_stack, sp = current_sp();
	volatile uint8_t *p = tfm_sp_aegis_pq_stack;

	if (sp < lo + 512u || sp > lo + AEGIS_PQ_STACK_SIZE) {
		return; /* not running on the partition's stack: report nothing rather than a wrong number */
	}
	for (uintptr_t i = 0; i < sp - 256u - lo; i++) {
		p[i] = STACK_FILL;
	}
	stack_filled = 1;
}

static unsigned stack_used(void)
{
	size_t untouched = 0;

	while (untouched < AEGIS_PQ_STACK_SIZE && tfm_sp_aegis_pq_stack[untouched] == STACK_FILL) {
		untouched++;
	}
	return (unsigned)(AEGIS_PQ_STACK_SIZE - untouched);
}

static void flash_cache_invalidate(void)
{
	CACHE64_CTRL0->CCR |= CACHE64_CTRL_CCR_INVW1_MASK | CACHE64_CTRL_CCR_INVW0_MASK;
	CACHE64_CTRL0->CCR |= CACHE64_CTRL_CCR_GO_MASK;
	while ((CACHE64_CTRL0->CCR & CACHE64_CTRL_CCR_GO_MASK) != 0U) {
	}
}

static void measure_region(struct aegis_measurement *m, const char *label, uint32_t base, uint32_t size,
			   const char *what)
{
	m->label = label;
	sha256((const uint8_t *)(uintptr_t)base, size, m->value);
	snprintf(m->desc, sizeof(m->desc), "SHA256 of the %s partition (%u bytes)", what, (unsigned)size);
}

/* Hedged ML-DSA: 32 fresh bytes from the ELS DRBG in every signature. */
static int s_random(uint8_t *out, size_t n)
{
	int ok;

	if (n == 0 || n % 4 != 0) {
		return -1;
	}
	MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r1, t1, mcuxClEls_Rng_DrbgRequest_Async(out, n));
	ok = (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_Rng_DrbgRequest_Async) == t1) && (r1 == MCUXCLELS_STATUS_OK_WAIT);
	MCUX_CSSL_FP_FUNCTION_CALL_END();
	if (!ok) {
		return -1;
	}
	MCUX_CSSL_FP_FUNCTION_CALL_BEGIN(r2, t2, mcuxClEls_WaitForOperation(MCUXCLELS_ERROR_FLAGS_CLEAR));
	ok = (MCUX_CSSL_FP_FUNCTION_CALLED(mcuxClEls_WaitForOperation) == t2) && (r2 == MCUXCLELS_STATUS_OK);
	MCUX_CSSL_FP_FUNCTION_CALL_END();
	return ok ? 0 : -1;
}

static size_t s_measure_all(struct aegis_measurement *m, size_t max)
{
	size_t n = max < 2 ? max : 2;

	memcpy(m, meas, n * sizeof(*m));
	return n;
}

static int s_status(char *buf, size_t cap)
{
	if (!stack_filled) {
		return snprintf(buf, cap, "requests=%u;stack=na;fw=%s-%s", (unsigned)served, AEGIS_DEVICE_FW,
				AEGIS_DEVICE_VERSION);
	}
	return snprintf(buf, cap, "requests=%u;stack=%u/%u;fw=%s-%s", (unsigned)served, stack_used(),
			(unsigned)AEGIS_PQ_STACK_SIZE, AEGIS_DEVICE_FW, AEGIS_DEVICE_VERSION);
}

static void s_measure_unused(uint8_t out[32], size_t *len)
{
	memset(out, 0, 32);
	*len = 0;
}

static uint32_t s_uptime_unused(void)
{
	return 0;
}

static const struct aegis_proto_platform platform = {
	.random = s_random,
	.measure = s_measure_unused,
	.uptime_s = s_uptime_unused,
	.profile = AEGIS_TFM_PROFILE,
	.measure_all = s_measure_all,
	.status = s_status,
};

/* The ML-DSA key is made at the first request, not at initialisation: TF-M's crypto partition sets ELS up during its
 * own initialisation (ELS_PowerDownWakeupInit), which may run after this partition's. Using ELS before that worked
 * but left the chip resetting moments later; at the first request the set-up is done. */
static int make_key(void)
{
	uint8_t seed[32], root[32];
	int rc;

#if defined(AEGIS_BISECT_NO_ELS)
	memset(seed, 0x11, sizeof(seed)); /* DEBUG BUILD ONLY: fixed seed, not a device key */
	memset(root, 0x22, sizeof(root));
	rc = 0;
#else
	rc = aegis_els_init();
	if (rc == 0) {
		rc = aegis_els_derive("aegis-rw612-mldsa65-seed-v1", seed);
	}
	if (rc == 0) {
		rc = aegis_els_derive("aegis-rw612-provision-root-v1", root);
	}
#endif
	if (rc == 0 && aegis_proto_init(&platform, seed, root, gateway_pk) != 0) {
		rc = -10;
	}
	memset(seed, 0, sizeof(seed));
	memset(root, 0, sizeof(root));
	return rc;
}

/* RSTCTL0, CLKCTL0, SYSCTL2 and the pin mux are secure-only in the Aegis target_cfg.c (they hold the ELS reset and
 * clock, and the pin mux could take the flash pins away from FlexSPI), so the non-secure prover cannot set up its own
 * Ethernet controller: do it here, once, before it runs. */
static void ns_ethernet_clocks(void)
{
	BOARD_InitNETPins(); /* ENET RMII pins, the PHY reset and interrupt pins as GPIO */
	CLOCK_EnableClock(kCLOCK_TddrMciEnetClk); /* 50 MHz RMII reference clock for the PHY */
	CLOCK_EnableClock(kCLOCK_EnetIpg);
	CLOCK_EnableClock(kCLOCK_EnetIpgS);
	RESET_PeripheralReset(kENET_IPG_RST_SHIFT_RSTn);
	RESET_PeripheralReset(kENET_IPG_S_RST_SHIFT_RSTn);
}

/* The measurements are taken here, before the non-secure image runs. */
psa_status_t aegis_pq_init(void)
{
	stack_fill();
	ns_ethernet_clocks();
	flash_cache_invalidate();
	measure_region(&meas[0], "SPE", S_PART_BASE, S_PART_SIZE, "secure");
	measure_region(&meas[1], "NSPE", NS_PART_BASE, NS_PART_SIZE, "non-secure");
	LOG_INFFMT("[Aegis] partitions measured (SPE, NSPE); the key is made at the first request\r\n");
	return PSA_SUCCESS;
}

psa_status_t aegis_pq_service_sfn(const psa_msg_t *msg)
{
	size_t n;
	int r;

	if (!ready && !key_tried) {
		key_tried = 1; /* one attempt per boot: a failure is not retried */
		key_rc = make_key();
		ready = (key_rc == 0);
		LOG_INFFMT("[Aegis] key from ELS: rc=%d\r\n", key_rc);
	}
	if (!ready) {
		return PSA_ERROR_BAD_STATE;
	}
	if (msg->type != AEGIS_PQ_LINE) {
		return PSA_ERROR_NOT_SUPPORTED;
	}
	n = msg->in_size[0];
	if (n == 0 || n > AEGIS_LINE_MAX || msg->out_size[0] == 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, line, n) != n) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	line[n] = '\0';
	served++;
	r = aegis_proto_handle(line, reply, sizeof(reply));
	if (r < 0 || (size_t)r >= sizeof(reply)) {
		return PSA_ERROR_GENERIC_ERROR;
	}
	if ((size_t)r > msg->out_size[0]) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}
	psa_write(msg->handle, 0, reply, (size_t)r);
	return PSA_SUCCESS;
}
