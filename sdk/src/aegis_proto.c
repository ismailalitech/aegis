/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Prover SDK: the protocol core. One source for every device family: the STM32H573 and RW612 TF-M partitions,
 * the RW612 single-image prover, the ZynqMP OP-TEE trusted application and the PC (sdk/ports/host, the tests and
 * tests/fuzz) build this same file. It includes nothing of TF-M, Zephyr, OP-TEE or a vendor's HAL: the device is
 * reached through struct aegis_platform (sdk/include/aegis_sdk.h), and nothing here allocates or prints.
 *
 * Two ways in, the same state machine behind both:
 *   binary operations   aegis_prover_quote / _kem_init / _kem_finish / _session / _heartbeat   (the STM32 partition's
 *                       PSA messages are these, one to one)
 *   text lines          aegis_prover_handle_line: "kind aegis-device" as the gateway speaks it over TCP
 *     PQKEY                    -> PQKEY <len> <hex> END                       the device's ML-DSA-65 public key
 *     PQCHAL <32-byte hex>     -> PQTOKEN <len> <evidence> <len> <sig> END   evidence, ML-DSA-65 signature
 *     PQKEMINIT <nonce>        -> PQKEMEK <len> <ek> <len> <sig> END          ML-KEM-768 key for this exchange, signed
 *     PQKEMFIN <ct> <cred>     -> PQKEMOK <tag> END | ERR cred <reason>       credential checked, then the session
 *     PQHB <nonce>             -> PQHB <status> <counter> <tag> END           KMAC256 over the session; the status is
 *                                                                             the platform's text plus ";ttl=<seconds left>"
 *     PQSESSION                -> PQSESSION <session id> <credential hash> END
 *   PQHB and PQSESSION answer "ERR pq no-session" before the first session and after a restart, and "ERR pq expired"
 *   once a session has ended on this side's clock, until the next one starts.
 *
 * The constructions:
 *   evidence         the platform's token (TF-M's PSA initial attestation token on the STM32), or CBOR claims made
 *                    here from the platform's measurements (PSA claim numbers, so the gateway's measurement check
 *                    applies unchanged). make_claims() is the one place that knows the claims' encoding: an EAT /
 *                    COSE encoding replaces it, or comes in through the platform's evidence function.
 *   quote signature  ML-DSA-65 (pure, empty context, hedged) over "aegis-endpoint-quote-v1\0" || evidence
 *   KEM key          ML-KEM-768.KeyGen(SHA3(root || fresh || nonce || counter || 0) || SHA3(... || 1)),
 *                    fresh = 32 bytes from the platform's generator, root = the device's exchange root
 *   credential       "<canonical JSON>\n<ML-DSA-65 signature by the pinned verifier key over
 *                    "aegis-credential-v1\0" || JSON>"; the JSON must name SHA3-256(ct), SHA3-256(ek) of the pending
 *                    exchange and SHA-256(this pk), and carry "issued" and "expires" (seconds), whose difference
 *                    is the credential's lifetime. check_credential() is the one place that decides which verifier
 *                    a device accepts: endorsed enrolment (a credential chain instead of one pinned key) goes there.
 *   session end      every request first reads the platform's clock; a session older than its lifetime plus a
 *                    sixteenth, or a clock that fails or runs backwards, wipes the session key
 *                    (docs/endpoint-expiry.md). The start is this side's clock at the accepted credential: the
 *                    credential's times are only subtracted, never compared with a clock.
 *   session          SHA3-256("aegis-session-v1" || K || nonce || SHA3-256(ct))
 *   confirm tag      SHA3-256("aegis-confirm-v1" || K || nonce || SHA3-256(ct) || SHA3-256(credential))
 *   heartbeat        KMAC256(session, nonce || counter || status, 256, "aegis-hb-v2")
 *                    (AEGIS_HB_KMAC=0 builds the first version: SHA3-256("aegis-hb-v1" || session || nonce ||
 *                    counter || status))
 * A refused exchange leaves an established session alone.
 *
 * One transcript (docs/architecture.md, common/transcript.py): the quote and the exchange that follows it are one
 * hash chain, so a verifier can refuse to finish a session with other code than the code whose quote it appraised.
 *   T1 = SHA3-256("aegis-transcript-v2/quote"    || challenge || SHA3-256(evidence))   kept for the last quote signed
 *   T2 = SHA3-256("aegis-transcript-v2/kem-init" || T1 || ek)
 *   T3 = SHA3-256("aegis-transcript-v2/kem-fin"  || T2 || SHA3-256(ct) || SHA3-256(credential))
 * An exchange whose nonce is the challenge of the last quote signed since the start continues that quote, once:
 *   KEM key signature  over "aegis-kem-init-v2\0" || T2 instead of "aegis-kem-init-v1\0" || nonce || ek
 *   credential         must also name T2 in "transcript_sha3_256"
 *   confirm tag        SHA3-256("aegis-confirm-v2" || K || T3)
 *   session            SHA3-256("aegis-session-v2" || K || T3)
 * Any other nonce gets the exchange above, unchanged, which a verifier that requires the transcript refuses (the
 * labels differ). The quote is kept in RAM only: after a restart there is none to continue. The measurements in a
 * quote are what the platform gives when the quote is asked for. Nothing is measured again for the exchange: the
 * transcript says that this boot signed exactly that quote and then made this key for it.
 *
 * Stack: the deepest paths are the ML-DSA calls. What must not lie under them (hash states, the key's coins, the
 * claims' encoder) is in functions of its own that have returned by then, marked AEGIS_NOINLINE, and the two
 * operations that sign are part of their callers' frames (AEGIS_INLINE) rather than a frame more; the STM32
 * partition's stack is sized by this (tools/stack_estimate.py).
 */
#include <string.h>

#if !defined(MLD_CONFIG_FILE)
#define MLD_CONFIG_FILE "aegis_mldsa_config.h"
#endif
#include "mldsa_native.h"
#define MLK_CONFIG_FILE "aegis_mlkem_config.h"
#include "mlkem_native.h"

#include "aegis_kmac.h"
#include "aegis_sdk.h"
#include "aegis_sha256.h"

#if !defined(AEGIS_HB_KMAC)
#define AEGIS_HB_KMAC 1
#endif
#if defined(__GNUC__)
#define AEGIS_NOINLINE __attribute__((noinline))
#define AEGIS_INLINE static inline __attribute__((always_inline))
#else
#define AEGIS_NOINLINE
#define AEGIS_INLINE static inline
#endif

/* Tests (sdk/tests/core_contract_check.c) define this to overwrite the caller's buffers at the points where an
 * operation has taken its inputs: from there on it must not read them again. */
#if !defined(AEGIS_TEST_INPUTS_TAKEN)
#define AEGIS_TEST_INPUTS_TAKEN() ((void)0)
#endif

#define KEM_EK_LEN  MLKEM_PUBLICKEYBYTES(768)
#define KEM_DK_LEN  MLKEM_SECRETKEYBYTES(768)
#define KEM_CT_LEN  MLKEM_CIPHERTEXTBYTES(768)
#define PK_LEN      MLDSA_PUBLICKEYBYTES(65)
#define SIG_LEN     MLDSA_BYTES(65)

_Static_assert(PK_LEN == AEGIS_PK_LEN && MLDSA_SECRETKEYBYTES(65) == AEGIS_SK_LEN && SIG_LEN == AEGIS_SIG_LEN,
	       "ML-DSA-65 sizes");
_Static_assert(KEM_EK_LEN == AEGIS_KEM_EK_LEN && KEM_DK_LEN == AEGIS_KEM_DK_LEN && KEM_CT_LEN == AEGIS_KEM_CT_LEN,
	       "ML-KEM-768 sizes");

/* PSA claim numbers (common/psa_token.py) */
#define C_PROFILE   (-75000)
#define C_SWC       (-75006)
#define C_CHALLENGE (-75008)
#define C_INSTANCE  (-75009)

static const char QUOTE_LABEL[] = "aegis-endpoint-quote-v1";
static const char KEM_LABEL[] = "aegis-kem-init-v1";
static const char KEM2_LABEL[] = "aegis-kem-init-v2"; /* over T2: the exchange continues a quote */
static const char T_QUOTE[] = "aegis-transcript-v2/quote";
static const char T_KEM_INIT[] = "aegis-transcript-v2/kem-init";
static const char T_KEM_FIN[] = "aegis-transcript-v2/kem-fin";
static const char CRED_LABEL[] = "aegis-credential-v1";
static const char RNG_LABEL[] = "aegis-rng-last-draw"; /* never on the wire: the hash a draw is remembered by */

_Static_assert(sizeof(QUOTE_LABEL) == AEGIS_WORK_QUOTE_HEAD && sizeof(CRED_LABEL) == AEGIS_WORK_CRED_HEAD &&
	       sizeof(KEM_LABEL) + 32 + KEM_EK_LEN == AEGIS_WORK_MIN, "work buffer heads");

/* ---- SHA3-256 (FIPS 202) -------------------------------------------------------------------- */

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

/* Overwrite n bytes with zeros in a way the compiler does not remove. */
void aegis_wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n--) *v++ = 0;
}
#define wipe aegis_wipe

static void keccak_f(uint64_t a[25])
{
	uint64_t c[5], b[25], d;

	for (int r = 0; r < 24; r++) {
		for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		for (int x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ krol(c[(x + 1) % 5], 1);

			for (int y = 0; y < 5; y++) a[x + 5 * y] ^= d;
		}
		for (int x = 0; x < 5; x++)
			for (int y = 0; y < 5; y++) b[y + 5 * ((2 * x + 3 * y) % 5)] = krol(a[x + 5 * y], KRHO[x + 5 * y]);
		for (int x = 0; x < 5; x++)
			for (int y = 0; y < 5; y++)
				a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
		a[0] ^= KRC[r];
	}
	/* copies of the state, which several of the protocol's hashes make from a secret: not left on the stack */
	wipe(b, sizeof(b));
	wipe(c, sizeof(c));
	wipe(&d, sizeof(d));
}

struct sha3 {
	uint64_t a[25];
	unsigned pos;
};

static void sha3_init(struct sha3 *h)
{
	memset(h, 0, sizeof(*h));
}

static void sha3_update(struct sha3 *h, const void *data, size_t n)
{
	const uint8_t *p = data;

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

/* SHA3-256(label || a || b || c || d): every hash of the protocol. Every caller passes fields of fixed lengths (but
 * for one last field), and no label is the beginning of another, so the results cannot be taken for one another.
 * A function of its own, so that the hash state is off the stack again before the callers' deep parts. Several of
 * these hashes take a secret: the state is wiped here, and the permutation wipes its own copies of it (keccak_f). */
static AEGIS_NOINLINE void hash_parts(uint8_t out[32], const char *label, const uint8_t *a, size_t an, const uint8_t *b,
				      size_t bn, const uint8_t *c, size_t cn, const uint8_t *d, size_t dn)
{
	struct sha3 h;

	sha3_init(&h);
	sha3_update(&h, label, strlen(label));
	sha3_update(&h, a, an);
	sha3_update(&h, b, bn);
	sha3_update(&h, c, cn);
	sha3_update(&h, d, dn);
	sha3_final(&h, out);
	wipe(&h, sizeof(h));
}

static void sha3_256(const uint8_t *p, size_t n, uint8_t out[32])
{
	hash_parts(out, "", p, n, NULL, 0, NULL, 0, NULL, 0);
}

/* ---- text and CBOR ---------------------------------------------------------------------------- */

static const char HX[] = "0123456789abcdef";

static char *put_hex(char *o, const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		*o++ = HX[p[i] >> 4];
		*o++ = HX[p[i] & 15];
	}
	return o;
}

/* without the terminator */
static char *put_str(char *o, const char *s)
{
	size_t n = strlen(s);

	memcpy(o, s, n);
	return o + n;
}

static char *put_uint(char *o, uint32_t v)
{
	char d[10];
	int n = 0;

	do {
		d[n++] = (char)('0' + v % 10u);
		v /= 10u;
	} while (v);
	while (n) *o++ = d[--n];
	return o;
}

static int unhex(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decode hex text; out may be the text itself (byte i is written after characters 2i and 2i + 1 are read). Returns
 * the byte count, or -1 if the text is not hex of even length or longer than cap bytes. */
static long get_hex(const char *s, uint8_t *out, size_t cap)
{
	size_t n = strlen(s);

	if (n % 2 || n / 2 > cap) return -1;
	for (size_t i = 0; i < n / 2; i++) {
		int a = unhex(s[2 * i]), b = unhex(s[2 * i + 1]);

		if (a < 0 || b < 0) return -1;
		out[i] = (uint8_t)(a << 4 | b);
	}
	return (long)(n / 2);
}

/* A CBOR writer that stops at the end of its buffer: p is NULL from the first item that did not fit. */
struct cbor {
	uint8_t *p, *end;
};

static void cbor_raw(struct cbor *c, const void *b, size_t n)
{
	if (c->p == NULL || (size_t)(c->end - c->p) < n) {
		c->p = NULL;
		return;
	}
	memcpy(c->p, b, n);
	c->p += n;
}

static void cbor_head(struct cbor *c, unsigned major, uint64_t v)
{
	uint8_t h[5];
	size_t n = 1;

	major <<= 5;
	if (v < 24) {
		h[0] = (uint8_t)(major | v);
	} else if (v < 0x100) {
		h[0] = (uint8_t)(major | 24); h[1] = (uint8_t)v;
		n = 2;
	} else if (v < 0x10000) {
		h[0] = (uint8_t)(major | 25); h[1] = (uint8_t)(v >> 8); h[2] = (uint8_t)v;
		n = 3;
	} else if (v <= 0xFFFFFFFFu) {
		h[0] = (uint8_t)(major | 26);
		for (int i = 3; i >= 0; i--) h[4 - i] = (uint8_t)(v >> (8 * i));
		n = 5;
	} else {
		c->p = NULL; /* nothing here is that long: refused rather than written with its upper half cut off */
		return;
	}
	cbor_raw(c, h, n);
}

static void cbor_int(struct cbor *c, long v)
{
	if (v >= 0) cbor_head(c, 0, (uint64_t)v);
	else cbor_head(c, 1, (uint64_t)(-1 - v));
}

static void cbor_bytes(struct cbor *c, const uint8_t *b, size_t n)
{
	cbor_head(c, 2, n);
	cbor_raw(c, b, n);
}

static void cbor_text_n(struct cbor *c, const char *s, size_t n)
{
	cbor_head(c, 3, n);
	cbor_raw(c, s, n);
}

static void cbor_text(struct cbor *c, const char *s)
{
	cbor_text_n(c, s, strlen(s));
}

/* ---- start ------------------------------------------------------------------------------------ */

static int all_equal(const uint8_t *b, size_t n)
{
	uint8_t diff = 0;

	for (size_t i = 1; i < n; i++) diff |= (uint8_t)(b[i] ^ b[0]);
	return diff == 0;
}

static int all_zero(const uint8_t *b, size_t n)
{
	return b[0] == 0 && all_equal(b, n);
}

int aegis_prover_init(struct aegis_prover *p, size_t prover_size, uint32_t api_version, const struct aegis_config *cfg)
{
	const struct aegis_platform *pl;
	int rc;

	if (p == NULL || cfg == NULL) return AEGIS_ERR_ARGUMENT;
	if (prover_size != sizeof(*p) || api_version != AEGIS_SDK_API_VERSION) return AEGIS_ERR_VERSION;
	wipe(p, sizeof(*p)); /* whatever a start before this one left: no session, no quote, no exchange */
	pl = cfg->platform;
	if (pl == NULL || pl->random == NULL || pl->clock == NULL || pl->clock_hz == 0u ||
	    (pl->measurements == NULL) == (pl->evidence == NULL) ||
	    (pl->measurements != NULL && (pl->profile == NULL || pl->version == NULL)) ||
	    (pl->identity_sign == NULL) != (pl->identity_public_key == NULL) ||
	    (pl->identity_sign == NULL) == (cfg->identity_seed == NULL) || cfg->verifier_pk == NULL ||
	    cfg->exchange_root == NULL || cfg->work == NULL || cfg->work_len < AEGIS_WORK_MIN) {
		return AEGIS_ERR_ARGUMENT;
	}
	/* Seed and root may lie in the work buffer (the STM32 port derives them there): both are read here, and the
	 * work buffer is not written before the first operation. All zeros is what a derivation that failed without
	 * saying so leaves behind: no key is made from it. */
	if (all_zero(cfg->exchange_root, AEGIS_SEED_LEN) ||
	    (cfg->identity_seed != NULL && all_zero(cfg->identity_seed, AEGIS_SEED_LEN))) {
		return AEGIS_ERR_IDENTITY;
	}
	p->plat = pl;
	p->verifier_pk = cfg->verifier_pk;
	p->work = cfg->work;
	p->work_len = cfg->work_len;
	memcpy(p->prov_root, cfg->exchange_root, sizeof(p->prov_root));
	if (pl->identity_sign != NULL) {
		rc = pl->identity_public_key(pl->user, p->pk);
	} else {
		rc = aegis_mldsa_keypair_internal(p->pk, p->sk, cfg->identity_seed);
	}
	if (rc != 0) {
		wipe(p, sizeof(*p));
		return AEGIS_ERR_IDENTITY;
	}
	aegis_sha256(p->pk, PK_LEN, p->pk_sha256);
	p->ready = 1;
	return AEGIS_OK;
}

const uint8_t *aegis_prover_public_key(const struct aegis_prover *p)
{
	return p != NULL && p->ready ? p->pk : NULL;
}

/* ---- the session's end ------------------------------------------------------------------------ */

static void session_end(struct aegis_prover *p)
{
	wipe(p->session_key, sizeof(p->session_key));
	wipe(p->cred_hash, sizeof(p->cred_hash));
	p->session_ready = 0;
	p->session_expired = 1;
}

/* Read the clock once per request, and end a session that has outlived its credential. A clock that fails or shows
 * less than at the session's start cannot measure the lifetime: the session ends too. */
static void sweep(struct aegis_prover *p)
{
	p->now = 0;
	p->clock_ok = p->plat->clock(p->plat->user, &p->now) == 0;
	if (p->session_ready &&
	    (!p->clock_ok || p->now < p->session_start || p->now - p->session_start >= p->session_limit)) {
		session_end(p);
	}
}

static int no_session(const struct aegis_prover *p)
{
	return p->session_expired ? AEGIS_ERR_EXPIRED : AEGIS_ERR_NO_SESSION;
}

/* the seconds the session has left on this side's clock, rounded up */
static uint32_t session_ttl(const struct aegis_prover *p)
{
	uint64_t left = p->session_limit - (p->now - p->session_start);

	return (uint32_t)((left + p->plat->clock_hz - 1u) / p->plat->clock_hz);
}

/* ---- the quote -------------------------------------------------------------------------------- */

/* Sign the n bytes in the work buffer (a label, its terminator, the message) with the identity key: pure ML-DSA-65,
 * empty context (M' = 0 || 0 || M), hedged. Fresh randomness goes into every signature, so two signatures never
 * share their internal randomness even for the same message; without it the signature is refused rather than made
 * deterministically (AEGIS_DETERMINISTIC_SIGNING=1 builds the deterministic variant, to compare signatures in a
 * test). */
static int sign_work(struct aegis_prover *p, size_t n)
{
	const struct aegis_platform *pl = p->plat;
	const uint8_t pre[2] = {0, 0};

	if (pl->identity_sign != NULL) {
		return pl->identity_sign(pl->user, p->work, n, p->sig) == 0 ? AEGIS_OK : AEGIS_ERR_SIGN;
	}
#if defined(AEGIS_DETERMINISTIC_SIGNING) && AEGIS_DETERMINISTIC_SIGNING
	{
		static const uint8_t rnd[32];

		return aegis_mldsa_signature_internal(p->sig, p->work, n, pre, sizeof(pre), rnd, p->sk, 0) == 0
			       ? AEGIS_OK : AEGIS_ERR_SIGN;
	}
#else
	{
		/* The draw goes into the context, not onto the stack under the signature; afterwards its hash stays there
		 * as the generator's last output, which the next exchange key's draw is compared with (kem_coins). */
		int rc;

		p->rng_have = 0;
		if (pl->random(pl->user, p->rng_last, sizeof(p->rng_last)) != 0) {
			wipe(p->rng_last, sizeof(p->rng_last));
			return AEGIS_ERR_SIGN_RNG;
		}
		rc = aegis_mldsa_signature_internal(p->sig, p->work, n, pre, sizeof(pre), p->rng_last, p->sk, 0);
		hash_parts(p->rng_last, RNG_LABEL, p->rng_last, sizeof(p->rng_last), NULL, 0, NULL, 0, NULL, 0);
		p->rng_have = 1;
		return rc == 0 ? AEGIS_OK : AEGIS_ERR_SIGN;
	}
#endif
}

/* The Aegis claims for a challenge, from the platform's measurements: a CBOR map of profile, challenge, instance
 * (0x02 || SHA-256 of the identity key: not a PSA IAK-based instance ID) and the software components. */
static AEGIS_NOINLINE int make_claims(struct aegis_prover *p, const uint8_t challenge[32], uint8_t *out, size_t cap,
				      size_t *len)
{
	static const uint8_t zero[32];
	const struct aegis_platform *pl = p->plat;
	const struct aegis_measurement *m = NULL;
	struct cbor c = {out, out + cap};
	uint8_t inst[33];
	size_t n = 0;

	if (pl->measurements(pl->user, &m, &n) != 0 || (n != 0 && m == NULL)) return AEGIS_ERR_EVIDENCE;
	inst[0] = 0x02;
	memcpy(inst + 1, p->pk_sha256, 32);
	cbor_head(&c, 5, 4);
	cbor_int(&c, C_PROFILE);
	cbor_text(&c, pl->profile);
	cbor_int(&c, C_CHALLENGE);
	cbor_bytes(&c, challenge, 32);
	cbor_int(&c, C_INSTANCE);
	cbor_bytes(&c, inst, sizeof(inst));
	cbor_int(&c, C_SWC);
	cbor_head(&c, 4, n);
	for (size_t i = 0; i < n && c.p != NULL; i++) {
		size_t dl = 0;

		if (m[i].label == NULL) return AEGIS_ERR_EVIDENCE;
		while (dl < sizeof(m[i].desc) && m[i].desc[dl] != '\0') dl++; /* never read beyond the description */
		cbor_head(&c, 5, 5);
		cbor_int(&c, 1); cbor_text(&c, m[i].label);
		cbor_int(&c, 2); cbor_bytes(&c, m[i].value, 32);
		cbor_int(&c, 4); cbor_text(&c, pl->version);
		cbor_int(&c, 5); cbor_bytes(&c, zero, 32);
		cbor_int(&c, 6); cbor_text_n(&c, m[i].desc, dl);
	}
	if (c.p == NULL) return AEGIS_ERR_EVIDENCE; /* more than fits the work buffer or the caller's reply */
	*len = (size_t)(c.p - out);
	return AEGIS_OK;
}

/* The quote just signed becomes the one an exchange can continue. */
static AEGIS_NOINLINE void quote_keep(struct aegis_prover *p, const uint8_t *evidence, size_t n)
{
	uint8_t h[32];

	sha3_256(evidence, n, h);
	hash_parts(p->quote_t1, T_QUOTE, p->quote_ch, 32, h, 32, NULL, 0, NULL, 0);
	p->quote_ready = 1;
}

/* max: the most evidence the caller can take; the work buffer may hold less */
AEGIS_INLINE int quote(struct aegis_prover *p, const uint8_t challenge[32], size_t max, const uint8_t **evidence,
		       size_t *len)
{
	const struct aegis_platform *pl = p->plat;
	uint8_t *e = p->work + sizeof(QUOTE_LABEL);
	size_t cap = p->work_len - sizeof(QUOTE_LABEL), n = 0;
	int rc;

	p->quote_ready = 0; /* only a quote that was signed can be continued, and only the last one */
	/* The challenge is read once, into the context: the evidence, the transcript and the comparison at the next
	 * exchange all use that copy, whatever happens to the caller's afterwards. */
	memcpy(p->quote_ch, challenge, 32);
	AEGIS_TEST_INPUTS_TAKEN();
	if (cap > max) cap = max;
	if (pl->evidence != NULL) {
		/* what the platform says it wrote must be what fits: a length beyond cap is refused, never signed */
		rc = pl->evidence(pl->user, p->quote_ch, e, cap, &n) == 0 && n != 0 && n <= cap ? AEGIS_OK : AEGIS_ERR_EVIDENCE;
	} else {
		rc = make_claims(p, p->quote_ch, e, cap, &n);
	}
	if (rc != AEGIS_OK) return rc;
	memcpy(p->work, QUOTE_LABEL, sizeof(QUOTE_LABEL)); /* the label and its terminator, then the evidence */
	rc = sign_work(p, sizeof(QUOTE_LABEL) + n);
	if (rc != AEGIS_OK) return rc;
	quote_keep(p, e, n);
	*evidence = e;
	*len = n;
	return AEGIS_OK;
}

/* ---- the exchange ----------------------------------------------------------------------------- */

/* The coins of an exchange's ML-KEM key pair.
 *
 * The 32 random bytes are what makes the key new. The root is the same at every start, the counter starts again at
 * every reset and the nonce is the caller's: without the random bytes, whoever recorded an exchange could reset the
 * device, send the recorded request as the same exchange since reset and get the same key pair, and the recorded
 * credential (it names that key) then gave the device the old session back, for a whole new lifetime (found by
 * review, 2026-11-20). Any failure of the generator refuses the exchange, as do 32 zero bytes: a generator that
 * reports success and writes nothing must not bring that back.
 *
 * The inputs have fixed lengths, so their boundaries cannot move; the root is used for nothing else, and the last
 * byte separates the two halves.
 *
 * What a broken generator typically gives is refused too: 32 equal bytes (all zeros among them), and the very bytes
 * of its last draw (a generator that stands still; the last draw is a signature's or the exchange before this
 * one's, remembered in the context by its hash). A generator that starts again with the same output after a reset cannot be seen from
 * here: that is the platform's to exclude (aegis_sdk.h). */
static AEGIS_NOINLINE int kem_coins(struct aegis_prover *p, uint8_t coins[64])
{
	const struct aegis_platform *pl = p->plat;
	uint8_t fresh[32] = {0}, c[5], h[32];
	int bad;

	if (pl->random(pl->user, fresh, sizeof(fresh)) != 0) {
		wipe(fresh, sizeof(fresh));
		return AEGIS_ERR_RNG;
	}
	/* remembered as a hash: the bytes themselves are part of this exchange's key and are not kept */
	hash_parts(h, RNG_LABEL, fresh, sizeof(fresh), NULL, 0, NULL, 0, NULL, 0);
	bad = all_equal(fresh, sizeof(fresh)) || (p->rng_have && memcmp(h, p->rng_last, sizeof(h)) == 0);
	memcpy(p->rng_last, h, sizeof(h));
	p->rng_have = 1;
	if (bad) {
		wipe(fresh, sizeof(fresh));
		return AEGIS_ERR_RNG;
	}
	p->kem_counter++; /* counts the key pairs made since the start */
	c[0] = (uint8_t)p->kem_counter; c[1] = (uint8_t)(p->kem_counter >> 8);
	c[2] = (uint8_t)(p->kem_counter >> 16); c[3] = (uint8_t)(p->kem_counter >> 24);
	for (uint8_t half = 0; half < 2; half++) {
		c[4] = half;
		hash_parts(coins + 32 * half, "", p->prov_root, 32, fresh, 32, p->kem_nonce, 32, c, 5);
	}
	wipe(fresh, sizeof(fresh));
	return AEGIS_OK;
}

/* The exchange's key pair. A function of its own: the coins are off the stack again before the signature. */
static AEGIS_NOINLINE int kem_make_key(struct aegis_prover *p)
{
	uint8_t coins[64];
	int rc = kem_coins(p, coins);

	if (rc == AEGIS_OK && aegis_mlkem_keypair_derand(p->kem_ek, p->kem_dk, coins) != 0) {
		wipe(p->kem_dk, sizeof(p->kem_dk));
		rc = AEGIS_ERR_KEM;
	}
	wipe(coins, sizeof(coins));
	return rc;
}

/* What the identity key signs for the exchange's ML-KEM key, into the work buffer; returns its length. */
static AEGIS_NOINLINE size_t kem_init_message(struct aegis_prover *p)
{
	if (p->kem_bound) {
		/* "aegis-kem-init-v2\0" || T2: the quote this exchange continues, and the key made for it */
		hash_parts(p->kem_t2, T_KEM_INIT, p->quote_t1, 32, p->kem_ek, KEM_EK_LEN, NULL, 0, NULL, 0);
		memcpy(p->work, KEM2_LABEL, sizeof(KEM2_LABEL));
		memcpy(p->work + sizeof(KEM2_LABEL), p->kem_t2, 32);
		return sizeof(KEM2_LABEL) + 32;
	}
	/* "aegis-kem-init-v1\0" || nonce || ek */
	memcpy(p->work, KEM_LABEL, sizeof(KEM_LABEL));
	memcpy(p->work + sizeof(KEM_LABEL), p->kem_nonce, 32);
	memcpy(p->work + sizeof(KEM_LABEL) + 32, p->kem_ek, KEM_EK_LEN);
	return sizeof(KEM_LABEL) + 32 + KEM_EK_LEN;
}

AEGIS_INLINE int kem_init(struct aegis_prover *p, const uint8_t nonce[32])
{
	int rc;

	/* A new exchange replaces a pending one whether or not it completes. Without this, an exchange refused after
	 * the key was made (no signing randomness, a signing error) left the older exchange pending with this key and
	 * nonce in it: unusable, and its decapsulation key kept in memory (found by tests/fuzz, 2026-11-18). */
	p->kem_pending = 0;
	wipe(p->kem_dk, sizeof(p->kem_dk));
	/* The nonce names the quote this exchange continues: the challenge of the last one signed. That quote is used
	 * up here, whether or not the exchange completes. Any other nonce: the unbound exchange. (Both values are
	 * public, so the comparison need not take constant time.) */
	memcpy(p->kem_nonce, nonce, 32); /* read once: the comparison, the key and the signature use this copy */
	AEGIS_TEST_INPUTS_TAKEN();
	p->kem_bound = p->quote_ready && memcmp(p->kem_nonce, p->quote_ch, 32) == 0;
	if (p->kem_bound) p->quote_ready = 0;
	rc = kem_make_key(p); /* no fresh randomness: no key, rather than one that can be made again */
	if (rc != AEGIS_OK) return rc;
	rc = sign_work(p, kem_init_message(p));
	if (rc != AEGIS_OK) {
		wipe(p->kem_dk, sizeof(p->kem_dk));
		return rc;
	}
	/* The established session stays valid until a new exchange completes (a stray or hostile request must not tear
	 * it down; found by review 2026-11-16). */
	p->kem_pending = 1;
	return AEGIS_OK;
}

/* the JSON body contains "<key>":"<hex of v>" (canonical JSON: no spaces) */
static int names(const uint8_t *body, size_t n, const char *key, const uint8_t v[32])
{
	char want[96];
	size_t k = strlen(key), w = k + 69;

	if (w > sizeof(want)) return 0;
	want[0] = '"';
	memcpy(want + 1, key, k);
	memcpy(want + 1 + k, "\":\"", 3);
	put_hex(want + 4 + k, v, 32);
	want[w - 1] = '"';
	for (size_t i = 0; i + w <= n; i++) {
		if (memcmp(body + i, want, w) == 0) return 1;
	}
	return 0;
}

/* The value of "<key>":<1 to 10 decimal digits> in the body, which must hold that key exactly once, the digits
 * followed by ',' or '}' (canonical JSON). Returns 0 if not so. */
static int number_of(const uint8_t *body, size_t n, const char *key, uint64_t *v)
{
	char want[24];
	size_t k = strlen(key), w = k + 3, at = 0, d;
	int found = 0;

	if (w > sizeof(want)) return 0;
	want[0] = '"';
	memcpy(want + 1, key, k);
	memcpy(want + 1 + k, "\":", 2);
	for (size_t i = 0; i + w <= n; i++) {
		if (memcmp(body + i, want, w) == 0) {
			if (found) return 0;
			found = 1;
			at = i + w;
		}
	}
	if (!found) return 0;
	*v = 0;
	for (d = 0; at + d < n && body[at + d] >= '0' && body[at + d] <= '9'; d++) {
		if (d == 10) return 0;
		*v = *v * 10u + (uint64_t)(body[at + d] - '0');
	}
	return d >= 1 && at + d < n && (body[at + d] == ',' || body[at + d] == '}');
}

/* The credential's lifetime in seconds: "expires" - "issued", from 1 to AEGIS_CRED_LIFETIME_MAX. Returns 0 if the
 * body does not carry one. The two times are the verifier's; this side has no wall clock to compare them with. */
static uint32_t cred_lifetime(const uint8_t *body, size_t n)
{
	uint64_t issued, expires;

	if (!number_of(body, n, "issued", &issued) || !number_of(body, n, "expires", &expires)) return 0;
	if (expires <= issued || expires - issued > AEGIS_CRED_LIFETIME_MAX) return 0;
	return (uint32_t)(expires - issued);
}

/* Take the credential in: body || '\n' || ML-DSA-65 signature. The caller's bytes are read here, once, and never
 * again: the body goes into the work buffer behind the label it is verified under, the signature into the context
 * (in the place of the last signature made, which has been given out). Everything after this (the verification, the
 * names, the lifetime, the credential's hash) is done on these copies, so that what is accepted is what was
 * verified even if the caller's memory changes meanwhile. The first newline must be the one before the signature.
 * Gives the body's length. */
static int cred_take(struct aegis_prover *p, const uint8_t *cred, size_t cred_len, size_t *body_len)
{
	uint8_t *body = p->work + sizeof(CRED_LABEL);
	uint8_t newlines = 0, separator;
	size_t n;

	if (cred_len < SIG_LEN + 1) return AEGIS_ERR_CRED_SIGNATURE;
	n = cred_len - SIG_LEN - 1;
	/* the body must fit the work buffer behind the label: a longer one than this port takes is refused */
	if (n > p->work_len - sizeof(CRED_LABEL)) return AEGIS_ERR_CRED_SIGNATURE;
	memcpy(p->work, CRED_LABEL, sizeof(CRED_LABEL));
	memcpy(body, cred, n);
	separator = cred[n];
	memcpy(p->sig, cred + n + 1, SIG_LEN);
	for (size_t i = 0; i < n; i++) newlines |= (uint8_t)(body[i] == '\n');
	*body_len = n;
	return !newlines && separator == '\n' ? AEGIS_OK : AEGIS_ERR_CRED_SIGNATURE;
}

/* The credential taken in by cred_take: signed by the pinned verifier key over "aegis-credential-v1\0" || body (pure
 * ML-DSA, empty context). The body must name SHA3-256(ct), this device's key and SHA3-256(ek) of the pending
 * exchange: without the last, an old credential replayed after a new exchange passed the check, decapsulated to an
 * unrelated key and replaced a working session (review 2026-11-18). For an exchange that continues a quote it must
 * name T2 as well: the verifier signed for that quote and this key. Gives the lifetime the body carries. */
static int check_credential(struct aegis_prover *p, size_t body_len, const uint8_t h_ct[32], const uint8_t h_ek[32],
			    uint32_t *lifetime)
{
	const uint8_t pre[2] = {0, 0};
	const uint8_t *body = p->work + sizeof(CRED_LABEL);

	if (aegis_mldsa_verify_internal(p->sig, p->work, sizeof(CRED_LABEL) + body_len, pre, sizeof(pre), p->verifier_pk,
					0) != 0) {
		return AEGIS_ERR_CRED_SIGNATURE;
	}
	if (!names(body, body_len, "kem_ct_sha3_256", h_ct)) return AEGIS_ERR_CRED_OTHER_EXCHANGE;
	if (!(p->plat->compat & AEGIS_COMPAT_CRED_WITHOUT_ENDPOINT) &&
	    !names(body, body_len, "endpoint_pq_pk_sha256", p->pk_sha256)) {
		return AEGIS_ERR_CRED_OTHER_ENDPOINT;
	}
	if (!names(body, body_len, "kem_ek_sha3_256", h_ek)) return AEGIS_ERR_CRED_OTHER_KEY;
	if (p->kem_bound && !names(body, body_len, "transcript_sha3_256", p->kem_t2)) return AEGIS_ERR_CRED_OTHER_TRANSCRIPT;
	*lifetime = cred_lifetime(body, body_len);
	return *lifetime ? AEGIS_OK : AEGIS_ERR_CRED_VALIDITY;
}

static int kem_state(const struct aegis_prover *p)
{
	if (!p->kem_pending) return AEGIS_ERR_NO_EXCHANGE;
	if (!p->clock_ok) return AEGIS_ERR_CLOCK; /* a session's end could not be measured: none starts */
	return AEGIS_OK;
}

static int kem_finish(struct aegis_prover *p, const uint8_t *ct, const uint8_t *cred, size_t cred_len, uint8_t tag[32])
{
	static const uint8_t newline[1] = {'\n'};
	uint8_t k[32], h_ct[32], h_ek[32];
	uint8_t *own_ct = p->kem_ek; /* see below */
	size_t body_len = 0;
	uint32_t lifetime = 0;
	int rc = kem_state(p);

	if (rc != AEGIS_OK) return rc;
	if (cred_len == 0 || cred_len > AEGIS_CRED_MAX) return AEGIS_ERR_BAD_REQUEST;
	p->kem_pending = 0;
	/* The caller's ciphertext and credential are read once, here. The ciphertext is hashed and then decapsulated:
	 * both must see the same bytes, so it is copied into the context first, into the place of the exchange's
	 * encapsulation key, of which only the hash is needed from here on (the exchange is over either way). */
	sha3_256(p->kem_ek, KEM_EK_LEN, h_ek);
	memcpy(own_ct, ct, KEM_CT_LEN);
	rc = cred_take(p, cred, cred_len, &body_len);
	AEGIS_TEST_INPUTS_TAKEN();
	sha3_256(own_ct, KEM_CT_LEN, h_ct);
	if (rc == AEGIS_OK) rc = check_credential(p, body_len, h_ct, h_ek, &lifetime);
	if (rc == AEGIS_OK && aegis_mlkem_dec(k, own_ct, p->kem_dk) != 0) rc = AEGIS_ERR_KEM;
	wipe(p->kem_dk, sizeof(p->kem_dk));
	if (rc != AEGIS_OK) {
		wipe(k, sizeof(k));
		return rc;
	}
	/* SHA3-256 of the credential as it was verified: body, newline, signature */
	hash_parts(p->cred_hash, "", p->work + sizeof(CRED_LABEL), body_len, newline, 1, p->sig, SIG_LEN, NULL, 0);
	if (p->kem_bound) {
		/* T3 takes h_ct's place: the ciphertext's hash is in it, and is not used again */
		hash_parts(h_ct, T_KEM_FIN, p->kem_t2, 32, h_ct, 32, p->cred_hash, 32, NULL, 0);
		hash_parts(p->session_key, "aegis-session-v2", k, 32, h_ct, 32, NULL, 0, NULL, 0);
		hash_parts(tag, "aegis-confirm-v2", k, 32, h_ct, 32, NULL, 0, NULL, 0);
	} else {
		hash_parts(p->session_key, "aegis-session-v1", k, 32, p->kem_nonce, 32, h_ct, 32, NULL, 0);
		hash_parts(tag, "aegis-confirm-v1", k, 32, p->kem_nonce, 32, h_ct, 32, p->cred_hash, 32);
	}
	wipe(k, sizeof(k));
	p->session_ready = 1;
	p->session_expired = 0;
	p->session_start = p->now;
	p->session_limit = AEGIS_SESSION_LIMIT(lifetime) * p->plat->clock_hz;
	if (!(p->plat->compat & AEGIS_COMPAT_HB_COUNTER_FROM_BOOT)) p->hb_counter = 0;
	return AEGIS_OK;
}

/* ---- the session ------------------------------------------------------------------------------ */

static int session_info(struct aegis_prover *p, uint8_t out[AEGIS_SESSION_LEN])
{
	if (!p->session_ready) return no_session(p);
	hash_parts(out, "aegis-session-id-v1", p->session_key, 32, NULL, 0, NULL, 0, NULL, 0);
	memcpy(out + 32, p->cred_hash, 32);
	return AEGIS_OK;
}

static int heartbeat(struct aegis_prover *p, const uint8_t nonce[32], char *status, size_t *status_len, size_t cap,
		     uint32_t flags, uint8_t out[AEGIS_HB_LEN])
{
	size_t n = *status_len;
	uint8_t ctr[8];

	if (!p->session_ready) return no_session(p);
	if (n > cap) return AEGIS_ERR_BUFFER;
	if (!(flags & AEGIS_HB_RAW)) {
		/* the seconds this session has left on this side's clock, under the MAC like the rest */
		char ttl[AEGIS_HB_TTL_MAX];
		size_t t = (size_t)(put_uint(put_str(ttl, ";ttl="), session_ttl(p)) - ttl);

		if (cap - n < t) return AEGIS_ERR_BUFFER;
		memcpy(status + n, ttl, t);
		n += t;
	}
	p->hb_counter++; /* only for a heartbeat that is answered */
	for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(p->hb_counter >> (8 * i));
#if AEGIS_HB_KMAC
	{
		struct aegis_kmac km;

		aegis_kmac256_init(&km, p->session_key, 32, (const uint8_t *)"aegis-hb-v2", 11);
		aegis_kmac256_update(&km, nonce, 32);
		aegis_kmac256_update(&km, ctr, 8);
		aegis_kmac256_update(&km, (const uint8_t *)status, n);
		aegis_kmac256_final(&km, out + 8, 32); /* also wipes the KMAC state */
	}
#else
	hash_parts(out + 8, "aegis-hb-v1", p->session_key, 32, nonce, 32, ctr, 8, (const uint8_t *)status, n);
#endif
	memcpy(out, ctr, 8);
	*status_len = n;
	return AEGIS_OK;
}

/* ---- the binary operations -------------------------------------------------------------------- */

#define READY(p) ((p) != NULL && (p)->ready)

void aegis_prover_poll(struct aegis_prover *p)
{
	if (READY(p)) sweep(p);
}

int aegis_prover_quote(struct aegis_prover *p, const uint8_t challenge[AEGIS_CHALLENGE_LEN], const uint8_t **evidence,
		       size_t *evidence_len, const uint8_t **sig)
{
	int rc;

	if (!READY(p)) return AEGIS_ERR_IDENTITY;
	if (challenge == NULL || evidence == NULL || evidence_len == NULL || sig == NULL) return AEGIS_ERR_ARGUMENT;
	sweep(p);
	rc = quote(p, challenge, (size_t)-1, evidence, evidence_len);
	if (rc == AEGIS_OK) *sig = p->sig;
	return rc;
}

int aegis_prover_kem_init(struct aegis_prover *p, const uint8_t nonce[AEGIS_CHALLENGE_LEN], const uint8_t **ek,
			  const uint8_t **sig)
{
	int rc;

	if (!READY(p)) return AEGIS_ERR_IDENTITY;
	if (nonce == NULL || ek == NULL || sig == NULL) return AEGIS_ERR_ARGUMENT;
	sweep(p);
	rc = kem_init(p, nonce);
	if (rc == AEGIS_OK) {
		*ek = p->kem_ek;
		*sig = p->sig;
	}
	return rc;
}

int aegis_prover_kem_pending(struct aegis_prover *p)
{
	if (!READY(p)) return AEGIS_ERR_IDENTITY;
	sweep(p);
	return kem_state(p);
}

int aegis_prover_kem_finish(struct aegis_prover *p, const uint8_t ct[AEGIS_KEM_CT_LEN], const uint8_t *cred,
			    size_t cred_len, uint8_t tag[AEGIS_TAG_LEN])
{
	if (!READY(p)) return AEGIS_ERR_IDENTITY;
	if (ct == NULL || cred == NULL || tag == NULL) return AEGIS_ERR_ARGUMENT;
	sweep(p);
	return kem_finish(p, ct, cred, cred_len, tag);
}

int aegis_prover_session_state(struct aegis_prover *p, uint32_t *ttl_s)
{
	if (!READY(p)) return AEGIS_ERR_IDENTITY;
	sweep(p);
	if (!p->session_ready) return no_session(p);
	if (ttl_s != NULL) *ttl_s = session_ttl(p);
	return AEGIS_OK;
}

int aegis_prover_session(struct aegis_prover *p, uint8_t out[AEGIS_SESSION_LEN])
{
	if (!READY(p)) return AEGIS_ERR_IDENTITY;
	if (out == NULL) return AEGIS_ERR_ARGUMENT;
	sweep(p);
	return session_info(p, out);
}

int aegis_prover_heartbeat(struct aegis_prover *p, const uint8_t nonce[AEGIS_CHALLENGE_LEN], char *status,
			   size_t *status_len, size_t status_cap, uint32_t flags, uint8_t out[AEGIS_HB_LEN])
{
	if (!READY(p)) return AEGIS_ERR_IDENTITY;
	if (nonce == NULL || status == NULL || status_len == NULL || out == NULL) return AEGIS_ERR_ARGUMENT;
	sweep(p);
	return heartbeat(p, nonce, status, status_len, status_cap, flags, out);
}

/* ---- the line transport ----------------------------------------------------------------------- */

#define LINE_ERR_MAX 32u /* the longest "ERR ..." reply, with its terminator */

static int reply(char *out, const char *text)
{
	size_t n = strlen(text);

	memcpy(out, text, n + 1);
	return (int)n;
}

static int reply_error(char *out, int rc)
{
	switch (rc) {
	case AEGIS_ERR_BAD_REQUEST:           return reply(out, "ERR bad-request");
	case AEGIS_ERR_EVIDENCE:              return reply(out, "ERR evidence");
	case AEGIS_ERR_RNG:                   return reply(out, "ERR rng");
	case AEGIS_ERR_SIGN_RNG:
	case AEGIS_ERR_SIGN:                  return reply(out, "ERR sign");
	case AEGIS_ERR_KEM:                   return reply(out, "ERR kem");
	case AEGIS_ERR_NO_EXCHANGE:           return reply(out, "ERR cred no-exchange");
	case AEGIS_ERR_CLOCK:                 return reply(out, "ERR clock");
	case AEGIS_ERR_CRED_SIGNATURE:        return reply(out, "ERR cred signature");
	case AEGIS_ERR_CRED_OTHER_EXCHANGE:   return reply(out, "ERR cred other-exchange");
	case AEGIS_ERR_CRED_OTHER_ENDPOINT:   return reply(out, "ERR cred other-endpoint");
	case AEGIS_ERR_CRED_OTHER_KEY:        return reply(out, "ERR cred other-key");
	case AEGIS_ERR_CRED_OTHER_TRANSCRIPT: return reply(out, "ERR cred other-transcript");
	case AEGIS_ERR_CRED_VALIDITY:         return reply(out, "ERR cred validity");
	case AEGIS_ERR_NO_SESSION:            return reply(out, "ERR pq no-session");
	case AEGIS_ERR_EXPIRED:               return reply(out, "ERR pq expired");
	case AEGIS_ERR_STATUS:                return reply(out, "ERR status");
	default:                              return reply(out, "ERR internal");
	}
}

/* "<name> <len> <a in hex> <len> <sig in hex> END" */
static int reply_signed(char *out, const char *name, const uint8_t *a, size_t an, const uint8_t *sig)
{
	char *o = put_str(out, name);

	o = put_uint(o, (uint32_t)an);
	*o++ = ' ';
	o = put_hex(o, a, an);
	*o++ = ' ';
	o = put_uint(o, (uint32_t)SIG_LEN);
	*o++ = ' ';
	o = put_hex(o, sig, SIG_LEN);
	return (int)(o - out) + reply(o, " END");
}

static int is_space(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}

int aegis_prover_handle_line(struct aegis_prover *p, char *line, char *out, size_t cap)
{
	char *tok[4], *o;
	int n = 0, rc;

	if (p == NULL || line == NULL || out == NULL || cap < LINE_ERR_MAX) return -1;
	if (!p->ready) return reply(out, "ERR internal");
	sweep(p); /* before anything else, whatever the request */
	for (char *s = line;;) {
		while (is_space(*s)) s++;
		if (*s == '\0') break;
		if (n == 4) return reply(out, "ERR bad-request");
		tok[n++] = s;
		while (*s != '\0' && !is_space(*s)) s++;
		if (*s != '\0') *s++ = '\0';
	}
	if (n == 0) {
		return reply(out, "ERR empty");
	}
	if (cap < AEGIS_REPLY_LEN(KEM_EK_LEN)) {
		return reply(out, "ERR internal");
	}
	if (!strcmp(tok[0], "PQKEY") && n == 1) {
		o = put_uint(put_str(out, "PQKEY "), (uint32_t)PK_LEN);
		*o++ = ' ';
		o = put_hex(o, p->pk, PK_LEN);
		return (int)(o - out) + reply(o, " END");
	}
	if (!strcmp(tok[0], "PQCHAL") && n == 2) {
		const uint8_t *evidence;
		uint8_t ch[32];
		size_t len;

		if (get_hex(tok[1], ch, sizeof(ch)) != 32) return reply(out, "ERR bad-request");
		rc = quote(p, ch, (cap - 64u) / 2u - SIG_LEN, &evidence, &len); /* no more than the reply can carry */
		if (rc != AEGIS_OK) return reply_error(out, rc);
		return reply_signed(out, "PQTOKEN ", evidence, len, p->sig);
	}
	if (!strcmp(tok[0], "PQKEMINIT") && n == 2) {
		uint8_t nonce[32];

		if (get_hex(tok[1], nonce, 32) != 32) return reply(out, "ERR bad-request");
		rc = kem_init(p, nonce);
		if (rc != AEGIS_OK) return reply_error(out, rc);
		return reply_signed(out, "PQKEMEK ", p->kem_ek, KEM_EK_LEN, p->sig);
	}
	if (!strcmp(tok[0], "PQKEMFIN") && n == 3) {
		uint8_t tag[32];
		long ct_len, cred_len;

		rc = kem_state(p);
		if (rc != AEGIS_OK) return reply_error(out, rc);
		/* both decoded where they stand, in the line */
		ct_len = get_hex(tok[1], (uint8_t *)tok[1], KEM_CT_LEN);
		cred_len = get_hex(tok[2], (uint8_t *)tok[2], AEGIS_CRED_MAX);
		if (ct_len != (long)KEM_CT_LEN || cred_len <= 0) return reply(out, "ERR bad-request");
		rc = kem_finish(p, (const uint8_t *)tok[1], (const uint8_t *)tok[2], (size_t)cred_len, tag);
		if (rc != AEGIS_OK) return reply_error(out, rc);
		o = put_hex(put_str(out, "PQKEMOK "), tag, 32);
		return (int)(o - out) + reply(o, " END");
	}
	if (!strcmp(tok[0], "PQHB") && n == 2) {
		char status[AEGIS_STATUS_MAX + AEGIS_HB_TTL_MAX];
		uint8_t nonce[32], hb[AEGIS_HB_LEN];
		size_t len;
		int sl = 0;

		if (!p->session_ready) return reply_error(out, no_session(p));
		if (get_hex(tok[1], nonce, 32) != 32) return reply(out, "ERR bad-request");
		if (p->plat->status != NULL) sl = p->plat->status(p->plat->user, status, AEGIS_STATUS_MAX);
		if (sl < 0 || (size_t)sl >= AEGIS_STATUS_MAX) return reply(out, "ERR status");
		len = (size_t)sl;
		rc = heartbeat(p, nonce, status, &len, sizeof(status), 0, hb);
		if (rc != AEGIS_OK) return reply_error(out, rc);
		o = put_hex(put_str(out, "PQHB "), (const uint8_t *)status, len);
		*o++ = ' ';
		o = put_hex(o, hb, 8);
		*o++ = ' ';
		o = put_hex(o, hb + 8, 32);
		return (int)(o - out) + reply(o, " END");
	}
	if (!strcmp(tok[0], "PQSESSION") && n == 1) {
		uint8_t info[AEGIS_SESSION_LEN];

		rc = session_info(p, info);
		if (rc != AEGIS_OK) return reply_error(out, rc);
		o = put_hex(put_str(out, "PQSESSION "), info, 32);
		*o++ = ' ';
		o = put_hex(o, info + 32, 32);
		return (int)(o - out) + reply(o, " END");
	}
	return reply(out, "ERR unknown");
}
