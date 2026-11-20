/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aegis post-quantum attestation partition for TF-M on the STM32H573: the Prover SDK's port to this chip.
 *
 * The protocol is the SDK's core (sdk/src/aegis_proto.c, the source every Aegis device builds; its head gives the
 * constructions, sdk/include/aegis_sdk.h the interface). This file is the platform layer and the transport:
 *   identity     seed = AES-256-ECB(DHUK, LABEL): the STM32H5's derived hardware unique key, used inside SAES; the DHUK
 *                itself never leaves SAES. The core makes the ML-DSA-65 key pair from the seed (FIPS 204,
 *                mldsa-native, reduced RAM); the seed is wiped right after. The same chip and boot flow give the same
 *                key pair on every boot; another chip gives another key. A second DHUK-derived secret is the
 *                exchange root.
 *   evidence     TF-M's PSA initial attestation token for the challenge (from the attestation service: the boot
 *                measurements of the S and NS images, as BL2 recorded them). The core signs it as it is.
 *   randomness   TF-M's crypto service: this build's psa_generate_random reads the STM32H5's RNG peripheral directly
 *                (MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG; TF-M's RNG_GetBytes, which gives nothing when the peripheral
 *                reports a seed or clock error).
 *   time         the RTC on the LSI, made secure here ("the session clock" below), 250 counts a second.
 *   transport    PSA messages to the stateless service AEGIS_PQ_SERVICE, one per operation of the core:
 *
 *   type 1 GET_PUBKEY: out[0] <- pk (1952 bytes)
 *   type 2 QUOTE:      in[0] = 32-byte challenge
 *                      out[0] <- the PSA initial attestation token for that challenge
 *                      out[1] <- ML-DSA-65 signature over "aegis-endpoint-quote-v1\0" || token
 *                                (hedged ML-DSA: 32 fresh random bytes in every signature; empty context.
 *                                AEGIS_DETERMINISTIC_SIGNING=1 builds the deterministic variant, rnd = 0)
 *   type 3 KEM_INIT:   in[0] = 32-byte gateway nonce
 *                      a fresh ML-KEM-768 key pair for this exchange (32 bytes from the random number generator go
 *                      into it; if the generator fails or gives zero bytes, the message is refused with
 *                      PSA_ERROR_INSUFFICIENT_ENTROPY or the crypto service's code, and no exchange is pending)
 *                      out[0] <- encapsulation key ek (1184 bytes)
 *                      out[1] <- ML-DSA-65 signature over "aegis-kem-init-v1\0" || nonce || ek, or, when the nonce is
 *                                the challenge of the last QUOTE, over "aegis-kem-init-v2\0" || T2 (one transcript)
 *   type 4 KEM_FINISH: in[0] = ML-KEM ciphertext (1088), in[1] = credential issued by the gateway
 *                      out[0] <- the confirmation tag (32 bytes)
 *                      PSA_ERROR_BAD_STATE without a pending exchange; PSA_ERROR_HARDWARE_FAILURE without a session
 *                      clock (the exchange stays pending); PSA_ERROR_INVALID_SIGNATURE for a credential that is not
 *                      the pinned gateway key's (gateway_pk.h) or does not name this ciphertext, this exchange's key
 *                      and, for an exchange that continues a quote, its transcript; PSA_ERROR_NOT_PERMITTED for one
 *                      without a lifetime of 1 to 86400 seconds. A refused exchange leaves an established session
 *                      alone. The credential's body is limited to 1214 bytes (the work buffer, AEGIS_WORK_MIN).
 *   type 5 SESSION:    out[0] <- SHA3-256("aegis-session-id-v1" || session) || SHA3-256(credential)
 *   type 6 HEARTBEAT:  in[0] = 32-byte gateway nonce, in[1] = up to 128 bytes of NS status data, which must not
 *                      contain "sstack=" or "ttl=" (those keys are the partition's)
 *                      status = data || ";sstack=<used>/<size>" (the high-water mark of this partition's stack, in
 *                               bytes; ";sstack=na" if the stack could not be filled at initialisation)
 *                               || ";ttl=<seconds the session has left on this side's clock>"
 *                      out[0] <- counter (8 bytes LE, increases every call)
 *                                || KMAC256(K = session, X = nonce || counter || status, L = 256,
 *                                           S = "aegis-hb-v2")   (NIST SP 800-185, sdk/src/aegis_kmac.c)
 *                      out[1] <- status (at most HB_STATUS_MAX = 162 bytes; a nonzero out[1] smaller than the
 *                                status is refused with PSA_ERROR_BUFFER_TOO_SMALL). The non-secure side shows this
 *                                text, as MACed.
 *                      Without out[1] (out_size[1] == 0: provers up to 0.5.0) status = data, as before.
 *                      AEGIS_HB_KMAC=0 builds the first version instead (SHA3-256, "aegis-hb-v1").
 *
 * Messages, sizes, status codes and every byte answered are those of the partition before it was moved onto the
 * core (SPE 3183f74a); tests/host/test_sdk_golden.py holds it to that. Two of its ways differ from the other
 * devices' and are kept through the core's compatibility flags: the heartbeat counter runs from boot across
 * sessions, and a credential need not name the device's key.
 *
 * What a transcript says and does not say here: the token's measurements are the ones BL2 recorded at boot (nothing
 * is measured again, at QUOTE or at KEM_INIT). The quote is kept in this partition's RAM, so after a reset there is
 * none to continue: a transcript shows that one boot of this partition signed exactly that token and then made this
 * key for it. A secure image that holds this key and signs a transcript for a quote it did not make could still
 * lie; the key would have to depend on the measured code to prevent that (it does not: it comes from the DHUK).
 *
 * The session ends on this side's clock (docs/endpoint-expiry.md). Every message first reads the session clock; a
 * session older than its credential's lifetime plus a sixteenth is wiped, as is one whose age the clock can no
 * longer give. SESSION and HEARTBEAT answer PSA_ERROR_BAD_STATE before the first session and after a reset, and
 * PSA_ERROR_DOES_NOT_EXIST once a session has ended that way, until the next one starts.
 * The Non-Secure world can ask for quotes and run provisioning but never sees the seed, the
 * secret keys, K or the session key.
 */
#include <stdint.h>
#include <string.h>

#include "psa/client.h"
#include "psa/crypto.h"
#include "psa/service.h"
#include "psa_manifest/aegis_pq_attest.h"
#include "psa_manifest/sid.h"
#include "stm32h5xx_hal.h"
#include "tfm_attest_defs.h"
/* the pinned gateway key; the PC tests (tests/fuzz/stm32) point this at a test key */
#ifndef AEGIS_GATEWAY_PK_HEADER
#define AEGIS_GATEWAY_PK_HEADER "gateway_pk.h"
#endif
#include AEGIS_GATEWAY_PK_HEADER
#include "aegis_sdk.h"

#define AEGIS_PQ_GET_PUBKEY 1
#define AEGIS_PQ_QUOTE      2
#define AEGIS_PQ_KEM_INIT   3
#define AEGIS_PQ_KEM_FINISH 4
#define AEGIS_PQ_SESSION    5
#define AEGIS_PQ_HEARTBEAT  6
#define TOKEN_MAX           0x250u

static const uint8_t seed_label[32] = "aegis-stm32h5-mldsa65-seed-v1...";
static const uint8_t prov_label[32] = "aegis-stm32h5-provision-root-v1.";

/* The core's context, its work buffer (the smallest: this partition's RAM is what TF-M's secure data region has
 * left), and what a message's inputs are read into. */
static struct aegis_prover core;
static uint8_t work[AEGIS_WORK_MIN];
static uint8_t kem_ct[AEGIS_KEM_CT_LEN];
static uint8_t cred[AEGIS_CRED_MAX];
static uint8_t msg_nonce[AEGIS_CHALLENGE_LEN]; /* a challenge or a nonce: public */
static const uint8_t gateway_pk[AEGIS_PK_LEN] = AEGIS_GATEWAY_PK;
static int key_ready;
/* what the services answered during this message, for the status returned when the core refuses */
static psa_status_t rng_status, token_status;

/* The partition's stack (generated/aegis_pq_attest/auto_generated/intermedia_aegis_pq_attest.c; its size is stack_size
 * in aegis_pq_attest.yaml). At initialisation the part below the current frame is filled with a pattern; every
 * heartbeat reports how much of the stack has ever been used (as the RW612 partition does). TF-M sets the stack limit
 * register to the stack's base, so an overflow faults rather than writing past it; this shows the margin. The PC
 * tests (tests/fuzz/stm32) define AEGIS_TEST_SP and their own stack array. */
extern uint8_t tfm_sp_aegis_pq_stack[];
#define AEGIS_PQ_STACK_SIZE 0x6800u
#define STACK_FILL          0xA5u
#define HB_DATA_MAX         128u
#define HB_SSTACK_MAX       (sizeof(";sstack=65535/65535") - 1u)
#define HB_STATUS_MAX       (HB_DATA_MAX + HB_SSTACK_MAX + AEGIS_HB_TTL_MAX)
static int stack_filled;

/* The session clock (below). The LSI is an RC oscillator, good to a few per cent: the sixteenth the core adds to a
 * credential's lifetime covers it, so a session does not end here before the gateway's own expiry. */
#define SCLK_HZ             250u /* the session clock's counts per second: LSI 32 kHz / 128 */
#define SCLK_PREDIV_A       127u
/* polls before a flag is given up: far beyond the 2 RTC clock periods a flag takes, or the 4 ms of one count */
#if !defined(SCLK_WAIT)
#define SCLK_WAIT           4000000u
#endif
/* PC tests (tests/fuzz/stm32): lets the stand-in registers react between two accesses */
#if !defined(AEGIS_TEST_HW_STEP)
#define AEGIS_TEST_HW_STEP() ((void)0)
#endif
static int sclk_ok;          /* the counter was started here and has not been found changed since */
static uint32_t sclk_epoch;  /* the times the 32-bit counter was seen to have passed zero (once in 198 days) */
static int msg_clock_read;   /* this message's clock reading: taken once, whatever the core asks */
static int msg_clock_rc;
static uint64_t msg_clock;

static int derive_from_dhuk(const uint8_t label[32], uint8_t out[32])
{
	CRYP_HandleTypeDef h;
	int rc = -1;

	memset(&h, 0, sizeof(h));
	__HAL_RCC_RNG_CLK_ENABLE();   /* SAES needs the RNG clocked */
	__HAL_RCC_SAES_CLK_ENABLE();
	h.Instance = SAES;
	h.Init.DataType = CRYP_NO_SWAP;
	h.Init.KeySize = CRYP_KEYSIZE_256B;
	h.Init.pKey = NULL;
	h.Init.Algorithm = CRYP_AES_ECB;
	h.Init.DataWidthUnit = CRYP_DATAWIDTHUNIT_BYTE;
	h.Init.KeyIVConfigSkip = CRYP_KEYIVCONFIG_ALWAYS;
	h.Init.KeyMode = CRYP_KEYMODE_NORMAL;
	h.Init.KeySelect = CRYP_KEYSEL_HW;
	h.Init.KeyProtection = CRYP_KEYPROT_DISABLE;
	if (HAL_CRYP_Init(&h) == HAL_OK &&
	    HAL_CRYP_Encrypt(&h, (uint32_t *)(uintptr_t)label, 32, (uint32_t *)out, 100) == HAL_OK) {
		rc = 0;
	}
	(void)HAL_CRYP_DeInit(&h);
	return rc;
}

#if defined(AEGIS_TEST_SP)
#define current_sp() ((uintptr_t)(AEGIS_TEST_SP))
#else
static uintptr_t current_sp(void)
{
	uintptr_t sp;

	__asm volatile("mov %0, sp" : "=r"(sp));
	return sp;
}
#endif

/* Fill the stack below the current frame, keeping 256 bytes of margin under it. */
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

/* The stack grows down from the top, so the lowest byte that lost the pattern bounds the deepest use. */
static unsigned stack_used(void)
{
	size_t untouched = 0;

	while (untouched < AEGIS_PQ_STACK_SIZE && tfm_sp_aegis_pq_stack[untouched] == STACK_FILL) {
		untouched++;
	}
	return (unsigned)(AEGIS_PQ_STACK_SIZE - untouched);
}

static size_t st_text(char *out, const char *t)
{
	size_t n = strlen(t);

	memcpy(out, t, n);
	return n;
}

static size_t st_uint(char *out, unsigned v)
{
	char d[10];
	size_t n = 0, k = 0;

	do {
		d[n++] = (char)('0' + v % 10u);
		v /= 10u;
	} while (v);
	while (n) {
		out[k++] = d[--n];
	}
	return k;
}

/* ";sstack=<used>/<size>" or ";sstack=na"; at most HB_SSTACK_MAX bytes (both numbers are at most 0x6800) */
static size_t sstack_field(char out[HB_SSTACK_MAX])
{
	size_t k = st_text(out, ";sstack=");

	if (!stack_filled) {
		return k + st_text(out + k, "na");
	}
	k += st_uint(out + k, stack_used());
	out[k++] = '/';
	return k + st_uint(out + k, AEGIS_PQ_STACK_SIZE);
}

/* ---- the session clock ---------------------------------------------------------------------------------------
 * The RTC in binary mode: RTC_SSR is then a free-running 32-bit down-counter clocked by the RTC clock divided by
 * PREDIV_A + 1. With the LSI (32 kHz) and 128 that is 250 counts a second and a wrap every 198 days.
 *
 * Why this counter: it runs from its own oscillator, in every power mode, whatever the system clock does. TF-M's
 * platform code leaves the clock tree (RCC), the power controller and the timers to the non-secure image and locks
 * the peripheral security settings before a partition runs, so a timer on the system clock could be slowed or
 * stopped from there, and SysTick and the cycle counter stop in Stop mode (the cycle counter is also writable
 * from the non-secure side). The RTC and the LSI have their own security bits, set here at every start:
 *   RTC_SECCFGR.SEC, RTC_PRIVCFGR.PRIV   the RTC's registers writable by secure privileged code only; with the RTC
 *                                        secure, its clock selection, enable and the backup-domain reset in RCC_BDCR
 *                                        are secure too
 *   RCC_SECCFGR.LSISEC                   the LSI's enable bit secure
 * TF-M's BL2 already starts the RTC on the LSI at every boot (calendar mode); this only changes the mode.
 *
 * Every reading checks that all of this is still as set here. If not, or if the counter does not count at start,
 * there is no clock: the session ends and none starts (PSA_ERROR_HARDWARE_FAILURE at KEM_FINISH).
 * What the non-secure image cannot do is stop or set it; a debugger can (DBGMCU can freeze the RTC while the core is
 * halted), and a reset of the backup domain, which needs the secure side or a power loss, restarts it. */
static int sclk_wait(volatile uint32_t *reg, uint32_t mask, uint32_t want)
{
	for (uint32_t i = 0; i < SCLK_WAIT; i++) {
		AEGIS_TEST_HW_STEP();
		if ((*reg & mask) == want) {
			return 1;
		}
	}
	return 0;
}

/* The counter, read until two readings agree (it is in another clock domain). */
static uint32_t sclk_count(void)
{
	uint32_t a = RTC->SSR, b = RTC->SSR;

	for (int i = 0; i < 4 && a != b; i++) {
		a = b;
		b = RTC->SSR;
	}
	(void)RTC->DR; /* reading RTC_SSR holds the calendar's shadow registers until the date is read */
	return b;
}

static int sclk_config_ok(void)
{
	const uint32_t bdcr = RCC_BDCR_LSION | RCC_BDCR_LSIRDY | RCC_BDCR_RTCEN | RCC_BDCR_RTCSEL;

	RCC->APB3ENR |= RCC_APB3ENR_RTCAPBEN; /* the RTC's register clock, whatever happened to it */
	(void)RCC->APB3ENR;
	return (RCC->BDCR & bdcr) == (RCC_BDCR_LSION | RCC_BDCR_LSIRDY | RCC_BDCR_RTCEN | RCC_BDCR_RTCSEL_1) &&
	       (RCC->SECCFGR & RCC_SECCFGR_LSISEC) != 0u && (RTC->SECCFGR & RTC_SECCFGR_SEC) != 0u &&
	       (RTC->PRIVCFGR & RTC_PRIVCFGR_PRIV) != 0u &&
	       (RTC->ICSR & (RTC_ICSR_BIN | RTC_ICSR_BCDU | RTC_ICSR_INIT | RTC_ICSR_INITF)) == RTC_ICSR_BIN_0 &&
	       (RTC->PRER & RTC_PRER_PREDIV_A) == (SCLK_PREDIV_A << RTC_PRER_PREDIV_A_Pos);
}

static void sclk_start(void)
{
	uint32_t first;

	sclk_ok = 0;
	sclk_epoch = 0;
	RCC->APB3ENR |= RCC_APB3ENR_RTCAPBEN;
	(void)RCC->APB3ENR;
	PWR->DBPCR |= PWR_DBPCR_DBP; /* write access to the backup domain (RCC_BDCR, the RTC) */
	RCC->BDCR |= RCC_BDCR_LSION;
	if (!sclk_wait(&RCC->BDCR, RCC_BDCR_LSIRDY, RCC_BDCR_LSIRDY)) {
		return;
	}
	if ((RCC->BDCR & RCC_BDCR_RTCSEL) == 0u) {
		RCC->BDCR |= RCC_BDCR_RTCSEL_1; /* no RTC clock chosen yet: the LSI, as BL2 chooses */
	}
	if ((RCC->BDCR & RCC_BDCR_RTCSEL) != RCC_BDCR_RTCSEL_1) {
		return; /* another source can only be replaced by resetting the backup domain: not done here */
	}
	RCC->BDCR |= RCC_BDCR_RTCEN;
	/* the sequence of the HAL's HAL_RTC_Init: unlock, initialisation mode, prescaler and mode, leave, wait for the
	 * shadow registers, lock */
	RTC->WPR = 0xCAu;
	RTC->WPR = 0x53u;
	RTC->ICSR |= RTC_ICSR_INIT;
	if (sclk_wait(&RTC->ICSR, RTC_ICSR_INITF, RTC_ICSR_INITF)) {
		RTC->PRER = (SCLK_PREDIV_A << RTC_PRER_PREDIV_A_Pos) | 249u;
		RTC->ICSR = (RTC->ICSR & ~(RTC_ICSR_BIN | RTC_ICSR_BCDU)) | RTC_ICSR_BIN_0;
	}
	RTC->ICSR &= ~RTC_ICSR_INIT;
	RTC->ICSR &= ~RTC_ICSR_RSF;
	(void)sclk_wait(&RTC->ICSR, RTC_ICSR_RSF | RTC_ICSR_INITF, RTC_ICSR_RSF);
	RTC->WPR = 0xFFu;
	RTC->SCR = RTC_SCR_CSSRUF;
	RTC->SECCFGR = RTC_SECCFGR_SEC;
	RTC->PRIVCFGR = RTC_PRIVCFGR_PRIV;
	RCC->SECCFGR |= RCC_SECCFGR_LSISEC;
	if (!sclk_config_ok()) {
		return;
	}
	first = sclk_count(); /* it must count: one count takes 4 ms */
	for (uint32_t i = 0; i < SCLK_WAIT; i++) {
		AEGIS_TEST_HW_STEP();
		if (sclk_count() != first) {
			sclk_ok = 1;
			return;
		}
	}
}

/* The clock now, in counts, for the core: the counts in this epoch, and above them the wraps seen, two to the 33rd
 * each. The flag says that the counter wrapped, not how often, so a session must not survive a wrap: with this step
 * a reading after one lies further from every reading before it than any session may live (at most 91800 s, 23
 * million counts), and the core ends the session as overdue. Within an epoch the differences are the counter's.
 * Nonzero if there is no clock (any more). */
static int sclk_now(uint64_t *ticks)
{
	uint32_t count;

	AEGIS_TEST_HW_STEP();
	if (!sclk_ok || !sclk_config_ok()) {
		sclk_ok = 0;
		return -1;
	}
	for (int i = 0; i < 2; i++) {
		if ((RTC->SR & RTC_SR_SSRUF) != 0u) { /* the counter passed zero since the last look */
			PWR->DBPCR |= PWR_DBPCR_DBP;
			RTC->SCR = RTC_SCR_CSSRUF;
			sclk_epoch++;
			if (!sclk_wait(&RTC->SR, RTC_SR_SSRUF, 0u)) {
				break; /* the flag does not clear */
			}
		}
		count = 0xFFFFFFFFu - sclk_count();
		if ((RTC->SR & RTC_SR_SSRUF) == 0u) {
			*ticks = (uint64_t)sclk_epoch << 33 | count;
			return 0;
		}
	}
	sclk_ok = 0; /* a flag that stays, or a second wrap within one reading: not a clock */
	return -1;
}

/* ---- the platform layer (struct aegis_platform) ---------------------------------------------------------------- */

/* One reading of the session clock per message: the core reads the clock at every operation, and a message is
 * several (the sweep, a state query, the operation). aegis_pq_service_sfn asks for a new reading. */
static int s_clock(void *user, uint64_t *now)
{
	(void)user;
	if (!msg_clock_read) {
		msg_clock = 0;
		msg_clock_rc = sclk_now(&msg_clock);
		msg_clock_read = 1;
	}
	*now = msg_clock;
	return msg_clock_rc;
}

/* The chip's true random number generator, through TF-M's crypto service. The status is kept: a refusal for want
 * of randomness answers with it. */
static int s_random(void *user, uint8_t *out, size_t n)
{
	(void)user;
	rng_status = psa_generate_random(out, n);
	return rng_status == PSA_SUCCESS ? 0 : -1;
}

/* The evidence: TF-M's initial attestation token for the challenge, written where the core signs it. */
static int s_evidence(void *user, const uint8_t challenge[AEGIS_CHALLENGE_LEN], uint8_t *out, size_t cap, size_t *len)
{
	psa_invec in[1];
	psa_outvec o[1];

	(void)user;
	in[0].base = challenge;
	in[0].len = AEGIS_CHALLENGE_LEN;
	o[0].base = out;
	o[0].len = cap < TOKEN_MAX ? cap : TOKEN_MAX;
	token_status = psa_call(TFM_ATTESTATION_SERVICE_HANDLE, TFM_ATTEST_GET_TOKEN, in, 1, o, 1);
	if (token_status != PSA_SUCCESS) {
		return -1;
	}
	*len = o[0].len;
	return 0;
}

static const struct aegis_platform platform = {
	.random = s_random,
	.clock = s_clock,
	.clock_hz = SCLK_HZ,
	.evidence = s_evidence,
	/* as the partition answered before it was built on the core (the head of this file) */
	.compat = AEGIS_COMPAT_HB_COUNTER_FROM_BOOT | AEGIS_COMPAT_CRED_WITHOUT_ENDPOINT,
};

psa_status_t aegis_pq_init(void)
{
	/* seed and exchange root are made in the work buffer, which the core does not write before its first
	 * operation (aegis_sdk.h says so of struct aegis_config.work): nothing of them on the stack, which the key
	 * generation below goes deep into */
	uint8_t *seed = work, *root = work + 32;
	const struct aegis_config cfg = {
		.platform = &platform,
		.verifier_pk = gateway_pk,
		.identity_seed = seed,
		.exchange_root = root,
		.work = work,
		.work_len = sizeof(work),
	};

	stack_fill(); /* first, so the key generation below counts towards the high-water mark */
	sclk_start();
	if (derive_from_dhuk(seed_label, seed) == 0 && derive_from_dhuk(prov_label, root) == 0) {
		key_ready = AEGIS_PROVER_INIT(&core, &cfg) == AEGIS_OK;
	}
	aegis_wipe(work, 64);
	return PSA_SUCCESS; /* without a key the service stays up and answers PSA_ERROR_BAD_STATE */
}

/* ---- the transport: PSA messages ------------------------------------------------------------------------------- */

/* The core's results as the PSA statuses this service has always answered with. */
static psa_status_t status_of(int rc)
{
	switch (rc) {
	case AEGIS_OK:
		return PSA_SUCCESS;
	case AEGIS_ERR_EVIDENCE: /* the attestation service's own status */
		return token_status != PSA_SUCCESS ? token_status : PSA_ERROR_GENERIC_ERROR;
	case AEGIS_ERR_RNG:      /* the crypto service's status, or success with zero bytes */
		return rng_status != PSA_SUCCESS ? rng_status : PSA_ERROR_INSUFFICIENT_ENTROPY;
	case AEGIS_ERR_SIGN_RNG:
		return rng_status != PSA_SUCCESS ? rng_status : PSA_ERROR_GENERIC_ERROR;
	case AEGIS_ERR_NO_EXCHANGE:
	case AEGIS_ERR_NO_SESSION:
		return PSA_ERROR_BAD_STATE;
	case AEGIS_ERR_EXPIRED:
		return PSA_ERROR_DOES_NOT_EXIST;
	case AEGIS_ERR_CLOCK:
		return PSA_ERROR_HARDWARE_FAILURE;
	case AEGIS_ERR_BAD_REQUEST:
		return PSA_ERROR_INVALID_ARGUMENT;
	case AEGIS_ERR_CRED_SIGNATURE:
	case AEGIS_ERR_CRED_OTHER_EXCHANGE:
	case AEGIS_ERR_CRED_OTHER_ENDPOINT:
	case AEGIS_ERR_CRED_OTHER_KEY:
	case AEGIS_ERR_CRED_OTHER_TRANSCRIPT:
		return PSA_ERROR_INVALID_SIGNATURE;
	case AEGIS_ERR_CRED_VALIDITY:
		return PSA_ERROR_NOT_PERMITTED;
	case AEGIS_ERR_BUFFER:
		return PSA_ERROR_BUFFER_TOO_SMALL;
	default: /* a signature or an ML-KEM operation that failed */
		return PSA_ERROR_GENERIC_ERROR;
	}
}

/* QUOTE and KEM_INIT end in an ML-DSA signature, the deepest use of this partition's stack: the other messages'
 * buffers are kept out of the frames above it (their functions are not inlined into the service function). */
static psa_status_t do_quote(const psa_msg_t *msg)
{
	const uint8_t *token, *sig;
	size_t token_len;
	int rc;

	if (msg->in_size[0] != AEGIS_CHALLENGE_LEN || msg->out_size[0] < TOKEN_MAX || msg->out_size[1] < AEGIS_SIG_LEN) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, msg_nonce, AEGIS_CHALLENGE_LEN) != AEGIS_CHALLENGE_LEN) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	rc = aegis_prover_quote(&core, msg_nonce, &token, &token_len, &sig);
	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	psa_write(msg->handle, 0, token, token_len);
	psa_write(msg->handle, 1, sig, AEGIS_SIG_LEN);
	return PSA_SUCCESS;
}

static psa_status_t do_kem_init(const psa_msg_t *msg)
{
	const uint8_t *ek, *sig;
	int rc;

	if (msg->in_size[0] != AEGIS_CHALLENGE_LEN || msg->out_size[0] < AEGIS_KEM_EK_LEN ||
	    msg->out_size[1] < AEGIS_SIG_LEN) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, msg_nonce, AEGIS_CHALLENGE_LEN) != AEGIS_CHALLENGE_LEN) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	/* a KEM_INIT with valid arguments cancels the pending exchange, whether or not it is answered */
	rc = aegis_prover_kem_init(&core, msg_nonce, &ek, &sig);
	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	psa_write(msg->handle, 0, ek, AEGIS_KEM_EK_LEN);
	psa_write(msg->handle, 1, sig, AEGIS_SIG_LEN);
	return PSA_SUCCESS;
}

static __attribute__((noinline)) psa_status_t do_kem_finish(const psa_msg_t *msg)
{
	uint8_t tag[AEGIS_TAG_LEN];
	size_t cred_len = msg->in_size[1];
	int rc;

	/* first what the exchange's state answers (no exchange, no clock), then the sizes: the order the partition has
	 * always answered in. Neither ends a pending exchange. */
	rc = aegis_prover_kem_pending(&core);
	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	if (msg->in_size[0] != AEGIS_KEM_CT_LEN || cred_len == 0 || cred_len > AEGIS_CRED_MAX ||
	    msg->out_size[0] < sizeof(tag)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, kem_ct, AEGIS_KEM_CT_LEN) != AEGIS_KEM_CT_LEN ||
	    psa_read(msg->handle, 1, cred, cred_len) != cred_len) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	rc = aegis_prover_kem_finish(&core, kem_ct, cred, cred_len, tag);
	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	psa_write(msg->handle, 0, tag, sizeof(tag));
	return PSA_SUCCESS;
}

static int has_key(const uint8_t *d, size_t n, const char *key)
{
	size_t k = strlen(key);

	for (size_t i = 0; i + k <= n; i++) {
		if (memcmp(d + i, key, k) == 0) {
			return 1;
		}
	}
	return 0;
}


static __attribute__((noinline)) psa_status_t do_heartbeat(const psa_msg_t *msg)
{
	uint8_t out[AEGIS_HB_LEN];
	char status[HB_STATUS_MAX];
	size_t dlen = msg->in_size[1], slen, cap = sizeof(status);
	int give_status = msg->out_size[1] != 0, rc;

	rc = aegis_prover_session_state(&core, NULL); /* without a session, whatever the arguments */
	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	if (msg->in_size[0] != AEGIS_CHALLENGE_LEN || dlen > HB_DATA_MAX || msg->out_size[0] < sizeof(out)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, msg_nonce, AEGIS_CHALLENGE_LEN) != AEGIS_CHALLENGE_LEN ||
	    (dlen && psa_read(msg->handle, 1, status, dlen) != dlen)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	/* the non-secure side must not be able to put its own stack figure or lifetime under the MAC, with or without
	 * out[1] */
	if (has_key((const uint8_t *)status, dlen, "sstack=") || has_key((const uint8_t *)status, dlen, "ttl=")) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	slen = dlen;
	if (give_status) {
		slen += sstack_field(status + slen);
		if (msg->out_size[1] < cap) {
			cap = msg->out_size[1]; /* the status with the core's ";ttl=" must fit the caller's buffer */
		}
	}
	/* without out[1] the data alone is MACed: there is no way to return what would be appended */
	rc = aegis_prover_heartbeat(&core, msg_nonce, status, &slen, cap, give_status ? 0u : AEGIS_HB_RAW, out);
	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	psa_write(msg->handle, 0, out, sizeof(out));
	if (give_status) {
		psa_write(msg->handle, 1, status, slen);
	}
	return PSA_SUCCESS;
}

static __attribute__((noinline)) psa_status_t do_session(const psa_msg_t *msg)
{
	uint8_t out[AEGIS_SESSION_LEN];
	int rc = aegis_prover_session_state(&core, NULL);

	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	if (msg->out_size[0] < sizeof(out)) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}
	rc = aegis_prover_session(&core, out);
	if (rc != AEGIS_OK) {
		return status_of(rc);
	}
	psa_write(msg->handle, 0, out, sizeof(out));
	return PSA_SUCCESS;
}

psa_status_t aegis_pq_service_sfn(const psa_msg_t *msg)
{
	msg_clock_read = 0;
	rng_status = token_status = PSA_SUCCESS;
	aegis_prover_poll(&core); /* the clock and the session's end before anything else, whatever the message */
	if (!key_ready) {
		return PSA_ERROR_BAD_STATE;
	}
	switch (msg->type) {
	case AEGIS_PQ_GET_PUBKEY:
		if (msg->out_size[0] < AEGIS_PK_LEN) {
			return PSA_ERROR_BUFFER_TOO_SMALL;
		}
		psa_write(msg->handle, 0, aegis_prover_public_key(&core), AEGIS_PK_LEN);
		return PSA_SUCCESS;
	case AEGIS_PQ_QUOTE:
		return do_quote(msg);
	case AEGIS_PQ_KEM_INIT:
		return do_kem_init(msg);
	case AEGIS_PQ_KEM_FINISH:
		return do_kem_finish(msg);
	case AEGIS_PQ_SESSION:
		return do_session(msg);
	case AEGIS_PQ_HEARTBEAT:
		return do_heartbeat(msg);
	default:
		return PSA_ERROR_NOT_SUPPORTED;
	}
}
