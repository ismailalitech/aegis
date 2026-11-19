/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Aegis post-quantum attestation partition for TF-M on the STM32H573.
 *
 * At initialisation:
 *   seed = AES-256-ECB(DHUK, LABEL)          the STM32H5's derived hardware unique key, used
 *                                            inside SAES; the DHUK itself never leaves SAES
 *   (pk, sk) = ML-DSA-65.KeyGen_internal(seed)   (FIPS 204, mldsa-native, reduced RAM)
 * The seed is wiped right after key generation. The same chip and boot flow give the same
 * key pair on every boot; another chip gives another key.
 *
 * Service AEGIS_PQ_SERVICE (stateless):
 *   type 1 GET_PUBKEY: out[0] <- pk (1952 bytes)
 *   type 2 QUOTE:      in[0] = 32-byte challenge
 *                      out[0] <- PSA initial attestation token for that challenge (from TF-M's
 *                                attestation service: boot measurements of S and NS images)
 *                      out[1] <- ML-DSA-65 signature over "aegis-endpoint-quote-v1\0" || token
 *                                (hedged ML-DSA: 32 fresh random bytes from TF-M's crypto service in
 *                                every signature; empty context. AEGIS_DETERMINISTIC_SIGNING=1 builds
 *                                the deterministic variant, rnd = 0)
 *   type 3 KEM_INIT:   in[0] = 32-byte gateway nonce
 *                      a fresh ML-KEM-768 key pair is derived from prov_root (a second
 *                      DHUK-derived secret), the nonce and a counter;
 *                      out[0] <- encapsulation key ek (1184 bytes)
 *                      out[1] <- ML-DSA-65 signature over "aegis-kem-init-v1\0" || nonce || ek
 *   type 4 KEM_FINISH: in[0] = ML-KEM ciphertext (1088), in[1] = credential issued by the gateway
 *                      K = ML-KEM.Decaps(dk, ct); the decapsulation key is wiped;
 *                      session = SHA3-256("aegis-session-v1" || K || nonce || SHA3-256(ct))
 *                      out[0] <- tag = SHA3-256("aegis-confirm-v1" || K || nonce || SHA3-256(ct)
 *                                                || SHA3-256(credential))
 *                      Mutual authentication: the credential must be "<canonical JSON body>\n<ML-DSA-65
 *                      signature>" signed by the gateway key pinned in this image (gateway_pk.h,
 *                      label "aegis-credential-v1"), and its body must name SHA3-256(ct) in
 *                      "kem_ct_sha3_256" and SHA3-256(ek) of the pending exchange in "kem_ek_sha3_256";
 *                      otherwise PSA_ERROR_INVALID_SIGNATURE and no session (a refused exchange leaves an
 *                      established session alone). A KEM_INIT with valid arguments cancels the pending
 *                      exchange first, so a refused one leaves nothing pending.
 *                      The body must also carry "issued" and "expires" (seconds, each once, 1 to 10 digits): their
 *                      difference, from 1 to 86400, is the credential's lifetime; otherwise
 *                      PSA_ERROR_NOT_PERMITTED. Without a session clock (below): PSA_ERROR_HARDWARE_FAILURE, the
 *                      exchange stays pending.
 *   type 5 SESSION:    out[0] <- SHA3-256("aegis-session-id-v1" || session) || SHA3-256(credential)
 *   type 6 HEARTBEAT:  in[0] = 32-byte gateway nonce, in[1] = up to 128 bytes of NS status data, which must not
 *                      contain "sstack=" or "ttl=" (those keys are the partition's)
 *                      status = data || ";sstack=<used>/<size>" (the high-water mark of this partition's stack, in
 *                               bytes; ";sstack=na" if the stack could not be filled at initialisation)
 *                               || ";ttl=<seconds the session has left on this side's clock>"
 *                      out[0] <- counter (8 bytes LE, increases every call)
 *                                || KMAC256(K = session, X = nonce || counter || status, L = 256,
 *                                           S = "aegis-hb-v2")   (NIST SP 800-185, aegis_kmac.c)
 *                      out[1] <- status (at most HB_STATUS_MAX = 162 bytes; a nonzero out[1] smaller than the
 *                                status is refused with PSA_ERROR_BUFFER_TOO_SMALL). The non-secure side shows this
 *                                text, as MACed.
 *                      Without out[1] (out_size[1] == 0: provers up to 0.5.0) status = data, as before.
 *                      AEGIS_HB_KMAC=0 builds the first version instead:
 *                                SHA3-256("aegis-hb-v1" || session || nonce || counter || status)
 *                      A light, symmetric proof of the session between full attestations.
 *
 * The session ends on this side's clock (docs/endpoint-expiry.md). Every message first reads the session clock; a
 * session older than its credential's lifetime plus a sixteenth is wiped, as is one whose age the clock can no
 * longer give. SESSION and HEARTBEAT answer PSA_ERROR_BAD_STATE before the first session and after a reset, and
 * PSA_ERROR_DOES_NOT_EXIST once a session has ended that way, until the next one starts.
 * The session clock is the RTC, clocked by the LSI (the internal 32 kHz oscillator) and run as a 32-bit binary
 * counter at 250 Hz ("the session clock" below): it keeps counting whatever the non-secure image does to the
 * system clock or to the power mode, and the partition makes it and its oscillator secure.
 * The Non-Secure world can ask for quotes and run provisioning but never sees the seed, the
 * secret keys, K or the session key.
 */
#include <stdint.h>
#include <string.h>

#include "mldsa_native.h"
#define MLK_CONFIG_FILE "aegis_mlkem_config.h"
#include "mlkem_native.h"
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
#include "aegis_kmac.h"

#if !defined(AEGIS_HB_KMAC)
#define AEGIS_HB_KMAC 1
#endif

#define AEGIS_PQ_GET_PUBKEY 1
#define AEGIS_PQ_QUOTE      2
#define AEGIS_PQ_KEM_INIT   3
#define AEGIS_PQ_KEM_FINISH 4
#define AEGIS_PQ_SESSION    5
#define AEGIS_PQ_HEARTBEAT  6
#define KEM_EK_LEN          MLKEM_PUBLICKEYBYTES(768)
#define KEM_DK_LEN          MLKEM_SECRETKEYBYTES(768)
#define KEM_CT_LEN          MLKEM_CIPHERTEXTBYTES(768)
#define CRED_MAX            6144u
#define CHALLENGE_LEN       32u
#define TOKEN_MAX           0x250u
#define QUOTE_LABEL         "aegis-endpoint-quote-v1"

static const uint8_t seed_label[32] = "aegis-stm32h5-mldsa65-seed-v1...";
static const uint8_t prov_label[32] = "aegis-stm32h5-provision-root-v1.";

static uint8_t pk[MLDSA_PUBLICKEYBYTES(65)];
static uint8_t sk[MLDSA_SECRETKEYBYTES(65)];
static uint8_t token[TOKEN_MAX];
static uint8_t signed_msg[sizeof("aegis-kem-init-v1") + 32 + MLKEM_PUBLICKEYBYTES(768) > sizeof(QUOTE_LABEL) + TOKEN_MAX ?
			  sizeof("aegis-kem-init-v1") + 32 + MLKEM_PUBLICKEYBYTES(768) : sizeof(QUOTE_LABEL) + TOKEN_MAX];
static uint8_t sig[MLDSA_BYTES(65)];
static int key_ready;

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
#define HB_TTL_MAX          (sizeof(";ttl=4294967295") - 1u)
#define HB_STATUS_MAX       (HB_DATA_MAX + HB_SSTACK_MAX + HB_TTL_MAX)
static int stack_filled;

/* The session's end (docs/endpoint-expiry.md): the credential's lifetime, "expires" - "issued", at most a day, plus a
 * sixteenth: the LSI is an RC oscillator, good to a few per cent, and the session must not end here before the
 * gateway's own expiry. */
#define CRED_LIFETIME_MAX   86400u
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
static uint64_t now_ticks;   /* this message's clock reading: epoch << 32 | counts in the epoch */
static int clock_ok;

static uint8_t prov_root[32];
static uint8_t kem_ek[KEM_EK_LEN];
static uint8_t kem_dk[KEM_DK_LEN];
static uint8_t kem_nonce[32];
static int kem_pending;
static uint32_t kem_counter;
static uint8_t kem_ct[KEM_CT_LEN];
static uint8_t cred[CRED_MAX];
static uint8_t session_key[32];
static uint8_t cred_hash[32];
static int session_ready;
static int session_expired;  /* the last session ended by the clock */
static uint64_t session_start, session_limit; /* the clock at KEM_FINISH; the counts the session may live */
static const uint8_t gateway_pk[MLDSA_PUBLICKEYBYTES(65)] = AEGIS_GATEWAY_PK;

/* ---- SHA3-256 (FIPS 202), small and simple -------------------------------------------- */

static const uint64_t KRC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const uint8_t KRHO[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

static uint64_t krol(uint64_t x, unsigned n)
{
	return n ? (x << n) | (x >> (64u - n)) : x;
}

static void keccak_f(uint64_t a[25])
{
	for (int r = 0; r < 24; r++) {
		uint64_t c[5], b[25];

		for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		for (int x = 0; x < 5; x++) {
			uint64_t d = c[(x + 4) % 5] ^ krol(c[(x + 1) % 5], 1);

			for (int y = 0; y < 5; y++) a[x + 5 * y] ^= d;
		}
		for (int x = 0; x < 5; x++)
			for (int y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = krol(a[x + 5 * y], KRHO[x + 5 * y]);
		for (int x = 0; x < 5; x++)
			for (int y = 0; y < 5; y++)
				a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
		a[0] ^= KRC[r];
	}
}

struct sha3 {
	uint64_t a[25];
	unsigned pos;
};

static void sha3_init(struct sha3 *h)
{
	memset(h, 0, sizeof(*h));
}

static void sha3_update(struct sha3 *h, const uint8_t *p, size_t n)
{
	while (n--) {
		h->a[h->pos / 8] ^= (uint64_t)*p++ << (8 * (h->pos % 8));
		if (++h->pos == 136) {
			keccak_f(h->a);
			h->pos = 0;
		}
	}
}

static void sha3_final(struct sha3 *h, uint8_t out[32])
{
	h->a[h->pos / 8] ^= (uint64_t)0x06 << (8 * (h->pos % 8));
	h->a[135 / 8] ^= (uint64_t)0x80 << (8 * (135 % 8));
	keccak_f(h->a);
	for (int i = 0; i < 32; i++) out[i] = (uint8_t)(h->a[i / 8] >> (8 * (i % 8)));
}

static void sha3_256(const uint8_t *p, size_t n, uint8_t out[32])
{
	struct sha3 h;

	sha3_init(&h);
	sha3_update(&h, p, n);
	sha3_final(&h, out);
}

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n--) {
		*v++ = 0;
	}
}

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

static size_t put_text(char *out, const char *t)
{
	size_t n = strlen(t);

	memcpy(out, t, n);
	return n;
}

static size_t put_uint(char *out, unsigned v)
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
	size_t k = put_text(out, ";sstack=");

	if (!stack_filled) {
		return k + put_text(out + k, "na");
	}
	k += put_uint(out + k, stack_used());
	out[k++] = '/';
	return k + put_uint(out + k, AEGIS_PQ_STACK_SIZE);
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

/* The clock now, in counts: the wraps seen in the upper word. Nonzero if there is no clock (any more). */
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
			*ticks = (uint64_t)sclk_epoch << 32 | count;
			return 0;
		}
	}
	sclk_ok = 0; /* a flag that stays, or a second wrap within one reading: not a clock */
	return -1;
}

static void session_end(void)
{
	wipe(session_key, sizeof(session_key));
	wipe(cred_hash, sizeof(cred_hash));
	session_ready = 0;
	session_expired = 1;
}

/* Read the clock once per message, and end a session that has outlived its credential, or whose age the clock cannot
 * give: no clock, a reading below the session's start, or a wrap of the counter in between (the flag says that it
 * wrapped, not how often, so a session does not survive one). */
static void session_sweep(void)
{
	now_ticks = 0;
	clock_ok = sclk_now(&now_ticks) == 0;
	if (session_ready && (!clock_ok || now_ticks < session_start || (now_ticks >> 32) != (session_start >> 32) ||
			      now_ticks - session_start >= session_limit)) {
		session_end();
	}
}

psa_status_t aegis_pq_init(void)
{
	uint8_t seed[32];

	stack_fill(); /* first, so the key generation below counts towards the high-water mark */
	sclk_start();
	if (derive_from_dhuk(seed_label, seed) != 0 || derive_from_dhuk(prov_label, prov_root) != 0) {
		wipe(seed, sizeof(seed));
		return PSA_SUCCESS; /* service stays up and answers PSA_ERROR_BAD_STATE */
	}
	key_ready = (aegis_mldsa_keypair_internal(pk, sk, seed) == 0);
	wipe(seed, sizeof(seed));
	return PSA_SUCCESS;
}

/* FIPS 204 hedged signing: fresh randomness from TF-M's crypto service (backed by the STM32H5 RNG)
 * goes into every signature, so two signatures never share their internal randomness even for the
 * same message. If the service fails, the signature is refused rather than made deterministically. */
static psa_status_t signing_rnd(uint8_t rnd[32])
{
#if defined(AEGIS_DETERMINISTIC_SIGNING) && AEGIS_DETERMINISTIC_SIGNING
	memset(rnd, 0, 32);
	return PSA_SUCCESS;
#else
	return psa_generate_random(rnd, 32);
#endif
}

static psa_status_t do_quote(const psa_msg_t *msg)
{
	uint8_t challenge[CHALLENGE_LEN];
	uint8_t rnd[32] = {0};
	const uint8_t pre[2] = {0, 0}; /* pure ML-DSA, empty context: M' = 0 || 0 || M */
	psa_invec in[1];
	psa_outvec out[1];
	psa_status_t st;
	size_t token_len;

	if (msg->in_size[0] != CHALLENGE_LEN || msg->out_size[0] < TOKEN_MAX || msg->out_size[1] < sizeof(sig)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, challenge, CHALLENGE_LEN) != CHALLENGE_LEN) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	in[0].base = challenge;
	in[0].len = CHALLENGE_LEN;
	out[0].base = token;
	out[0].len = sizeof(token);
	st = psa_call(TFM_ATTESTATION_SERVICE_HANDLE, TFM_ATTEST_GET_TOKEN, in, 1, out, 1);
	if (st != PSA_SUCCESS) {
		return st;
	}
	token_len = out[0].len;
	memcpy(signed_msg, QUOTE_LABEL, sizeof(QUOTE_LABEL)); /* label and its NUL separator */
	memcpy(signed_msg + sizeof(QUOTE_LABEL), token, token_len);
	st = signing_rnd(rnd);
	if (st != PSA_SUCCESS) {
		return st;
	}
	if (aegis_mldsa_signature_internal(sig, signed_msg, sizeof(QUOTE_LABEL) + token_len, pre, sizeof(pre),
					   rnd, sk, 0) != 0) {
		wipe(rnd, sizeof(rnd));
		return PSA_ERROR_GENERIC_ERROR;
	}
	wipe(rnd, sizeof(rnd));
	psa_write(msg->handle, 0, token, token_len);
	psa_write(msg->handle, 1, sig, sizeof(sig));
	return PSA_SUCCESS;
}

static psa_status_t do_kem_init(const psa_msg_t *msg)
{
	static const char lbl[] = "aegis-kem-init-v1";
	uint8_t coins[64], rnd[32] = {0};
	const uint8_t pre[2] = {0, 0};
	psa_status_t st;
	struct sha3 h;
	uint8_t c[4];

	if (msg->in_size[0] != 32 || msg->out_size[0] < KEM_EK_LEN || msg->out_size[1] < sizeof(sig)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	/* A new exchange replaces a pending one whether or not it completes. Without this, a KEM_INIT refused after
	 * the key was made (no signing randomness, a signing error) left the older exchange pending with this nonce
	 * and key in it: unusable, its decapsulation key kept in memory (found by fuzzing the RW612 prover's copy of
	 * this construction, tests/fuzz, 2026-11-18). */
	kem_pending = 0;
	wipe(kem_dk, sizeof(kem_dk));
	if (psa_read(msg->handle, 0, kem_nonce, 32) != 32) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	kem_counter++;
	c[0] = (uint8_t)kem_counter; c[1] = (uint8_t)(kem_counter >> 8);
	c[2] = (uint8_t)(kem_counter >> 16); c[3] = (uint8_t)(kem_counter >> 24);
	for (uint8_t half = 0; half < 2; half++) {
		sha3_init(&h);
		sha3_update(&h, prov_root, 32);
		sha3_update(&h, kem_nonce, 32);
		sha3_update(&h, c, 4);
		sha3_update(&h, &half, 1);
		sha3_final(&h, coins + 32 * half);
	}
	if (aegis_mlkem_keypair_derand(kem_ek, kem_dk, coins) != 0) {
		wipe(coins, sizeof(coins));
		return PSA_ERROR_GENERIC_ERROR;
	}
	wipe(coins, sizeof(coins));
	/* sign "aegis-kem-init-v1\0" || nonce || ek with the device's ML-DSA key */
	memcpy(signed_msg, lbl, sizeof(lbl));
	memcpy(signed_msg + sizeof(lbl), kem_nonce, 32);
	if (sizeof(signed_msg) < sizeof(lbl) + 32 + KEM_EK_LEN) {
		return PSA_ERROR_GENERIC_ERROR;
	}
	memcpy(signed_msg + sizeof(lbl) + 32, kem_ek, KEM_EK_LEN);
	st = signing_rnd(rnd);
	if (st != PSA_SUCCESS) {
		wipe(kem_dk, sizeof(kem_dk));
		return st;
	}
	if (aegis_mldsa_signature_internal(sig, signed_msg, sizeof(lbl) + 32 + KEM_EK_LEN, pre, sizeof(pre), rnd, sk,
					   0) != 0) {
		wipe(rnd, sizeof(rnd));
		wipe(kem_dk, sizeof(kem_dk));
		return PSA_ERROR_GENERIC_ERROR;
	}
	wipe(rnd, sizeof(rnd));
	kem_pending = 1;
	/* The established session stays valid until a new exchange completes (a stray or hostile
	 * KEM_INIT must not tear it down; found by review 2026-11-16). */
	psa_write(msg->handle, 0, kem_ek, KEM_EK_LEN);
	psa_write(msg->handle, 1, sig, sizeof(sig));
	return PSA_SUCCESS;
}

/* the body contains "<key>":"<hex of v>" (canonical JSON: no spaces) */
static int names(const uint8_t *body, size_t n, const char *key, const uint8_t v[32])
{
	static const char hx[] = "0123456789abcdef";
	char want[96];
	size_t k = strlen(key), w = k + 69, i;

	if (w > sizeof(want)) {
		return 0;
	}
	want[0] = '"';
	memcpy(want + 1, key, k);
	memcpy(want + 1 + k, "\":\"", 3);
	for (i = 0; i < 32; i++) {
		want[4 + k + 2 * i] = hx[v[i] >> 4];
		want[4 + k + 2 * i + 1] = hx[v[i] & 15];
	}
	want[w - 1] = '"';
	for (i = 0; i + w <= n; i++) {
		if (memcmp(body + i, want, w) == 0) {
			return 1;
		}
	}
	return 0;
}

/* The value of "<key>":<1 to 10 decimal digits> in the body, which must hold that key exactly once, the digits
 * followed by ',' or '}' (canonical JSON). Returns 0 if not so. */
static int number_of(const uint8_t *body, size_t n, const char *key, uint64_t *v)
{
	char want[24];
	size_t k = strlen(key), w = k + 3, at = 0, d, i;
	int found = 0;

	if (w > sizeof(want)) {
		return 0;
	}
	want[0] = '"';
	memcpy(want + 1, key, k);
	want[k + 1] = '"';
	want[k + 2] = ':';
	for (i = 0; i + w <= n; i++) {
		if (memcmp(body + i, want, w) == 0) {
			if (found) {
				return 0;
			}
			found = 1;
			at = i + w;
		}
	}
	if (!found) {
		return 0;
	}
	*v = 0;
	for (d = 0; at + d < n && body[at + d] >= '0' && body[at + d] <= '9'; d++) {
		if (d == 10) {
			return 0;
		}
		*v = *v * 10u + (uint64_t)(body[at + d] - '0');
	}
	return d >= 1 && at + d < n && (body[at + d] == ',' || body[at + d] == '}');
}

/* The credential's lifetime in seconds, "expires" - "issued", from 1 to CRED_LIFETIME_MAX; 0 if the body carries
 * none. The two times are the gateway's: they are subtracted, never compared with a clock of this side. */
static uint32_t cred_lifetime(const uint8_t *body, size_t n)
{
	uint64_t issued, expires;

	if (!number_of(body, n, "issued", &issued) || !number_of(body, n, "expires", &expires)) {
		return 0;
	}
	if (expires <= issued || expires - issued > CRED_LIFETIME_MAX) {
		return 0;
	}
	return (uint32_t)(expires - issued);
}

/* Credential = body || '\n' || ML-DSA-65 signature by the pinned gateway key over
 * "aegis-credential-v1\0" || body (pure ML-DSA, empty context). The body must name SHA3-256(ct) in
 * "kem_ct_sha3_256" and SHA3-256(ek) of the pending exchange in "kem_ek_sha3_256": without the second, an old
 * KEM_FINISH replayed after a new KEM_INIT passed the check, decapsulated to an unrelated key and replaced a
 * working session (found on the RW612 by review, 2026-11-18; the gateway names both).
 * Returns PSA_SUCCESS and the lifetime the body carries, PSA_ERROR_INVALID_SIGNATURE, or PSA_ERROR_NOT_PERMITTED for
 * a signed and bound credential without a lifetime. */
static psa_status_t check_credential(const uint8_t *c, size_t len, const uint8_t h_ct[32], uint32_t *lifetime)
{
	static const char lbl[] = "aegis-credential-v1";
	const uint8_t pre[2] = {0, 0};
	uint8_t h_ek[32];
	size_t body_len = 0;

	while (body_len < len && c[body_len] != '\n') body_len++;
	if (body_len == len || len - body_len - 1 != MLDSA_BYTES(65) ||
	    sizeof(lbl) + body_len > sizeof(signed_msg)) {
		return PSA_ERROR_INVALID_SIGNATURE;
	}
	memcpy(signed_msg, lbl, sizeof(lbl));
	memcpy(signed_msg + sizeof(lbl), c, body_len);
	if (aegis_mldsa_verify_internal(c + body_len + 1, signed_msg, sizeof(lbl) + body_len, pre, sizeof(pre),
					gateway_pk, 0) != 0) {
		return PSA_ERROR_INVALID_SIGNATURE;
	}
	sha3_256(kem_ek, KEM_EK_LEN, h_ek);
	if (!names(c, body_len, "kem_ct_sha3_256", h_ct) || !names(c, body_len, "kem_ek_sha3_256", h_ek)) {
		return PSA_ERROR_INVALID_SIGNATURE;
	}
	*lifetime = cred_lifetime(c, body_len);
	return *lifetime ? PSA_SUCCESS : PSA_ERROR_NOT_PERMITTED;
}

static psa_status_t do_kem_finish(const psa_msg_t *msg)
{
	static const char l_sess[] = "aegis-session-v1", l_conf[] = "aegis-confirm-v1";
	uint8_t k[32], h_ct[32], tag[32];
	size_t cred_len = msg->in_size[1];
	uint32_t lifetime = 0;
	psa_status_t st;
	struct sha3 h;

	if (!kem_pending) {
		return PSA_ERROR_BAD_STATE;
	}
	if (!clock_ok) {
		return PSA_ERROR_HARDWARE_FAILURE; /* a session's end could not be measured: none starts */
	}
	if (msg->in_size[0] != KEM_CT_LEN || cred_len == 0 || cred_len > CRED_MAX || msg->out_size[0] < 32) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, kem_ct, KEM_CT_LEN) != KEM_CT_LEN ||
	    psa_read(msg->handle, 1, cred, cred_len) != cred_len) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	kem_pending = 0;
	sha3_256(kem_ct, KEM_CT_LEN, h_ct);
	st = check_credential(cred, cred_len, h_ct, &lifetime);
	if (st != PSA_SUCCESS) {
		wipe(kem_dk, sizeof(kem_dk));
		return st;
	}
	if (aegis_mlkem_dec(k, kem_ct, kem_dk) != 0) {
		wipe(kem_dk, sizeof(kem_dk));
		return PSA_ERROR_GENERIC_ERROR;
	}
	wipe(kem_dk, sizeof(kem_dk));
	sha3_256(cred, cred_len, cred_hash);
	sha3_init(&h);
	sha3_update(&h, (const uint8_t *)l_sess, sizeof(l_sess) - 1);
	sha3_update(&h, k, 32);
	sha3_update(&h, kem_nonce, 32);
	sha3_update(&h, h_ct, 32);
	sha3_final(&h, session_key);
	sha3_init(&h);
	sha3_update(&h, (const uint8_t *)l_conf, sizeof(l_conf) - 1);
	sha3_update(&h, k, 32);
	sha3_update(&h, kem_nonce, 32);
	sha3_update(&h, h_ct, 32);
	sha3_update(&h, cred_hash, 32);
	sha3_final(&h, tag);
	wipe(k, sizeof(k));
	session_ready = 1;
	session_expired = 0;
	session_start = now_ticks;
	session_limit = ((uint64_t)lifetime + lifetime / 16u) * SCLK_HZ;
	psa_write(msg->handle, 0, tag, 32);
	return PSA_SUCCESS;
}

static uint64_t hb_counter;

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

/* SESSION and HEARTBEAT without a session: was there never one (since reset), or did the clock end it? */
static psa_status_t no_session(void)
{
	return session_expired ? PSA_ERROR_DOES_NOT_EXIST : PSA_ERROR_BAD_STATE;
}

/* ";ttl=<seconds left>", rounded up; at most HB_TTL_MAX bytes */
static size_t ttl_field(char out[HB_TTL_MAX])
{
	uint64_t left = session_limit - (now_ticks - session_start);
	size_t k = put_text(out, ";ttl=");

	return k + put_uint(out + k, (unsigned)((left + SCLK_HZ - 1u) / SCLK_HZ));
}

static psa_status_t do_heartbeat(const psa_msg_t *msg)
{
#if AEGIS_HB_KMAC
	static const char lbl[] = "aegis-hb-v2"; /* the KMAC customization string */
	struct aegis_kmac k;
#else
	static const char lbl[] = "aegis-hb-v1";
	struct sha3 h;
#endif
	uint8_t nonce[32], status[HB_STATUS_MAX], out[40], ctr[8];
	size_t dlen = msg->in_size[1], slen;
	int give_status = msg->out_size[1] != 0;

	if (!session_ready) {
		return no_session();
	}
	if (msg->in_size[0] != 32 || dlen > HB_DATA_MAX || msg->out_size[0] < sizeof(out)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, nonce, 32) != 32 || (dlen && psa_read(msg->handle, 1, status, dlen) != dlen)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	/* the non-secure side must not be able to put its own stack figure or lifetime under the MAC, with or without
	 * out[1] */
	if (has_key(status, dlen, "sstack=") || has_key(status, dlen, "ttl=")) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	slen = dlen;
	if (give_status) {
		slen += sstack_field((char *)status + slen);
		slen += ttl_field((char *)status + slen);
		if (msg->out_size[1] < slen) {
			return PSA_ERROR_BUFFER_TOO_SMALL;
		}
	}
	hb_counter++;
	for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(hb_counter >> (8 * i));
	memcpy(out, ctr, 8);
#if AEGIS_HB_KMAC
	aegis_kmac256_init(&k, session_key, 32, (const uint8_t *)lbl, sizeof(lbl) - 1);
	aegis_kmac256_update(&k, nonce, 32);
	aegis_kmac256_update(&k, ctr, 8);
	aegis_kmac256_update(&k, status, slen);
	aegis_kmac256_final(&k, out + 8, 32); /* also wipes the KMAC state */
#else
	sha3_init(&h);
	sha3_update(&h, (const uint8_t *)lbl, sizeof(lbl) - 1);
	sha3_update(&h, session_key, 32);
	sha3_update(&h, nonce, 32);
	sha3_update(&h, ctr, 8);
	sha3_update(&h, status, slen);
	sha3_final(&h, out + 8);
#endif
	psa_write(msg->handle, 0, out, sizeof(out));
	if (give_status) {
		psa_write(msg->handle, 1, status, slen);
	}
	return PSA_SUCCESS;
}

static psa_status_t do_session(const psa_msg_t *msg)
{
	static const char l_id[] = "aegis-session-id-v1";
	uint8_t out[64];
	struct sha3 h;

	if (!session_ready) {
		return no_session();
	}
	if (msg->out_size[0] < sizeof(out)) {
		return PSA_ERROR_BUFFER_TOO_SMALL;
	}
	sha3_init(&h);
	sha3_update(&h, (const uint8_t *)l_id, sizeof(l_id) - 1);
	sha3_update(&h, session_key, 32);
	sha3_final(&h, out);
	memcpy(out + 32, cred_hash, 32);
	psa_write(msg->handle, 0, out, sizeof(out));
	return PSA_SUCCESS;
}

psa_status_t aegis_pq_service_sfn(const psa_msg_t *msg)
{
	session_sweep(); /* before anything else, whatever the message */
	if (!key_ready) {
		return PSA_ERROR_BAD_STATE;
	}
	switch (msg->type) {
	case AEGIS_PQ_GET_PUBKEY:
		if (msg->out_size[0] < sizeof(pk)) {
			return PSA_ERROR_BUFFER_TOO_SMALL;
		}
		psa_write(msg->handle, 0, pk, sizeof(pk));
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
