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
 *   The session clock is started: the secure SysTick (see "the session clock" below, docs/endpoint-expiry.md).
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

/* ---- the session clock: the secure SysTick ---------------------------------------------------------------------
 * A session must end on a clock the non-secure image cannot set, slow or stop. ARMv8-M gives the secure state its
 * own SysTick: its registers are banked, so non-secure code cannot reach them, and TF-M sets AIRCR.PRIS, so no
 * non-secure exception or mask can hold back its interrupt (priority below 0x80). It counts down from 2^24 - 1 and
 * SysTick_Handler below counts the wraps; the time is wraps * 2^24 plus the current count, divided by the clock's
 * frequency.
 *
 * The clock, in order of preference:
 *   "ref"  the SysTick function clock, main clock / 256 (about 1 MHz, a wrap every 16.5 s). Mux and divider are in
 *          CLKCTL0, which the Aegis target_cfg.c makes secure-only. Secure code that masks interrupts (TF-M's flash
 *          driver does, for a whole erase) would have to hold them for two wraps, 33 s, to lose one.
 *   "cpu"  the processor clock (a wrap every 64.5 ms at 260 MHz), if the function clock does not count at the
 *          expected rate. A flash erase longer than a wrap then loses time, so a non-secure image that keeps TF-M's
 *          storage erasing can stretch a session; the heartbeat status says which clock runs (clk=ref or clk=cpu).
 * The rate of "ref" is checked once against the processor clock, counted by the non-secure SysTick before the
 * non-secure image runs (then put back to its reset state). The main clock, its dividers and the PLL are in CLKCTL0,
 * SYSCTL2 and the PMU, all secure-only; deep sleep is made a secure decision (SCR.SLEEPDEEPS). Every reading checks
 * that the configuration is still the one made here; if not, there is no clock, the session ends and none starts.
 * A debugger halting the core stops the count, as does a reset (which also ends the session: it is in RAM). */
#define SCLK_PERIOD 0x1000000u /* counts per wrap: LOAD + 1 */
#define SCLK_PRIO   (1UL << (__NVIC_PRIO_BITS - 2)) /* below TF-M's SVC and faults (0), above PendSV; < 0x80 */
static volatile uint32_t sclk_wraps_lo, sclk_wraps_hi;
static uint32_t sclk_hz;   /* 0: no clock */
static uint32_t sclk_ctrl; /* the SysTick CTRL value set here */
static const char *sclk_name = "none";

void SysTick_Handler(void) /* the secure SysTick: replaces the weak default of TF-M's start-up file */
{
	if (++sclk_wraps_lo == 0u) {
		sclk_wraps_hi++;
	}
}

static void sclk_run(uint32_t ctrl)
{
	SysTick->CTRL = 0;
	SysTick->LOAD = SCLK_PERIOD - 1u;
	SysTick->VAL = 0; /* any write clears the count and COUNTFLAG */
	sclk_ctrl = ctrl | SysTick_CTRL_TICKINT_Msk | SysTick_CTRL_ENABLE_Msk;
	SysTick->CTRL = sclk_ctrl;
}

/* Does the secure SysTick count, at core_hz / ratio? The non-secure SysTick, on the processor clock, is the measure. */
static int sclk_rate_ok(uint32_t ratio)
{
	uint32_t s0, n0, ds = 0, dn = 0;

	SysTick_NS->CTRL = 0;
	SysTick_NS->LOAD = SCLK_PERIOD - 1u;
	SysTick_NS->VAL = 0;
	SysTick_NS->CTRL = SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_ENABLE_Msk;
	n0 = SysTick_NS->VAL;
	s0 = SysTick->VAL;
	/* for 2^16 processor cycles (256 counts of "ref"); the loop bound only ends a measure that does not count */
	for (uint32_t i = 0; i < 400000u && dn < 0x10000u; i++) {
		ds = (s0 - SysTick->VAL) & (SCLK_PERIOD - 1u);
		dn = (n0 - SysTick_NS->VAL) & (SCLK_PERIOD - 1u);
	}
	SysTick_NS->CTRL = 0; /* as after reset, for the non-secure image */
	SysTick_NS->LOAD = 0;
	SysTick_NS->VAL = 0;
	if (dn < 0x10000u) {
		return 0; /* the measure itself did not count */
	}
	/* dn / ds must be the ratio, within an eighth (a secure count that stands still gives ds = 0 and fails) */
	return (uint64_t)dn * 8u >= (uint64_t)ds * ratio * 7u && (uint64_t)dn * 8u <= (uint64_t)ds * ratio * 9u;
}

static int sclk_ref_configured(void)
{
	return (CLKCTL0->SYSTICKFCLKSEL & CLKCTL0_SYSTICKFCLKSEL_SEL_MASK) == CLKCTL0_SYSTICKFCLKSEL_SEL(0) &&
	       (CLKCTL0->SYSTICKFCLKDIV & (CLKCTL0_SYSTICKFCLKDIV_DIV_MASK | CLKCTL0_SYSTICKFCLKDIV_HALT_MASK |
					   CLKCTL0_SYSTICKFCLKDIV_REQFLAG_MASK)) == CLKCTL0_SYSTICKFCLKDIV_DIV(255);
}

static void sclk_start(void)
{
	uint32_t core_hz = CLOCK_GetCoreSysClkFreq(), ref_hz;

	SCB->SCR |= SCB_SCR_SLEEPDEEPS_Msk; /* deep sleep, which stops the clocks, is the secure side's decision */
	NVIC_SetPriority(SysTick_IRQn, SCLK_PRIO);
	if (core_hz == 0u) {
		return;
	}
	if ((SysTick->CALIB & SysTick_CALIB_NOREF_Msk) == 0u) {
		CLKCTL0->SYSTICKFCLKDIV |= CLKCTL0_SYSTICKFCLKDIV_RESET_MASK;
		CLKCTL0->SYSTICKFCLKDIV = CLKCTL0_SYSTICKFCLKDIV_DIV(255);
		for (uint32_t i = 0; i < 100000u && (CLKCTL0->SYSTICKFCLKDIV & CLKCTL0_SYSTICKFCLKDIV_REQFLAG_MASK); i++) {
		}
		CLKCTL0->SYSTICKFCLKSEL = CLKCTL0_SYSTICKFCLKSEL_SEL(0);
		ref_hz = CLOCK_GetSystickClkFreq();
		sclk_run(0);
		if (sclk_ref_configured() && ref_hz != 0u && core_hz / ref_hz >= 4u &&
		    sclk_rate_ok((core_hz + ref_hz / 2u) / ref_hz)) {
			sclk_hz = ref_hz;
			sclk_name = "ref";
			return;
		}
	}
	sclk_run(SysTick_CTRL_CLKSOURCE_Msk);
	if (sclk_rate_ok(1)) {
		sclk_hz = core_hz;
		sclk_name = "cpu";
		return;
	}
	SysTick->CTRL = 0;
}

/* Seconds since sclk_start(). -1: no clock, or its configuration is no longer the one made there. */
static int s_monotonic(uint64_t *now)
{
	uint32_t primask, lo, hi, val;
	int ref = (sclk_ctrl & SysTick_CTRL_CLKSOURCE_Msk) == 0u;

	if (sclk_hz == 0u ||
	    (SysTick->CTRL & (SysTick_CTRL_CLKSOURCE_Msk | SysTick_CTRL_TICKINT_Msk | SysTick_CTRL_ENABLE_Msk)) != sclk_ctrl ||
	    SysTick->LOAD != SCLK_PERIOD - 1u || NVIC_GetPriority(SysTick_IRQn) != SCLK_PRIO ||
	    (SCB->SCR & SCB_SCR_SLEEPDEEPS_Msk) == 0u || (ref && !sclk_ref_configured()) ||
	    (ref ? CLOCK_GetSystickClkFreq() : CLOCK_GetCoreSysClkFreq()) != sclk_hz) {
		sclk_hz = 0;
		sclk_name = "none";
		return -1;
	}
	primask = __get_PRIMASK();
	__disable_irq();
	lo = sclk_wraps_lo;
	hi = sclk_wraps_hi;
	val = SysTick->VAL;
	if (SCB->ICSR & SCB_ICSR_PENDSTSET_Msk) { /* wrapped since interrupts were masked: count it, read again */
		if (++lo == 0u) {
			hi++;
		}
		val = SysTick->VAL;
	}
	__set_PRIMASK(primask);
	*now = ((((uint64_t)hi << 32 | lo) << 24) + (SCLK_PERIOD - 1u - val)) / sclk_hz;
	return 0;
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
		return snprintf(buf, cap, "requests=%u;stack=na;clk=%s;fw=%s-%s", (unsigned)served, sclk_name,
				AEGIS_DEVICE_FW, AEGIS_DEVICE_VERSION);
	}
	return snprintf(buf, cap, "requests=%u;stack=%u/%u;clk=%s;fw=%s-%s", (unsigned)served, stack_used(),
			(unsigned)AEGIS_PQ_STACK_SIZE, sclk_name, AEGIS_DEVICE_FW, AEGIS_DEVICE_VERSION);
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
	.monotonic_s = s_monotonic,
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
	sclk_start();
	ns_ethernet_clocks();
	flash_cache_invalidate();
	measure_region(&meas[0], "SPE", S_PART_BASE, S_PART_SIZE, "secure");
	measure_region(&meas[1], "NSPE", NS_PART_BASE, NS_PART_SIZE, "non-secure");
	LOG_INFFMT("[Aegis] partitions measured (SPE, NSPE); the key is made at the first request\r\n");
	LOG_INFFMT("[Aegis] session clock: %s, %u Hz\r\n", sclk_name, (unsigned)sclk_hz);
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
