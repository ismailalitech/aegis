/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis line protocol for a device prover (kind "aegis-device"), with no RTOS in it: the RW612 firmware (main.c) and
 * the PC test (tests/host/test_rw612_proto.py, through host_main.c) build this same file.
 *
 *   PQKEY                    -> PQKEY <len> <hex> END                       the device's ML-DSA-65 public key
 *   PQCHAL <32-byte hex>     -> PQTOKEN <len> <claims> <len> <sig> END     CBOR claims, ML-DSA-65 signature
 *   PQKEMINIT <nonce>        -> PQKEMEK <len> <ek> <len> <sig> END          ML-KEM-768 key for this exchange, signed
 *   PQKEMFIN <ct> <cred>     -> PQKEMOK <tag> END | ERR cred <reason>       credential checked, then the session
 *   PQHB <nonce>             -> PQHB <status> <counter> <tag> END           KMAC256 over the session; the status is the
 *                                                                           platform's text plus ";ttl=<seconds left>"
 *   PQSESSION                -> PQSESSION <session id> <credential hash> END
 * PQHB and PQSESSION answer "ERR pq no-session" before the first session and after a restart, and "ERR pq expired"
 * once a session has ended on this side's clock, until the next one starts.
 *
 * The constructions are the STM32 partition's (endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c):
 *   quote signature  ML-DSA-65 (pure, empty context, hedged) over "aegis-endpoint-quote-v1\0" || claims
 *   KEM key          ML-KEM-768.KeyGen(SHA3(prov_root || fresh || nonce || counter || 0) || SHA3(... || 1)),
 *                    fresh = 32 bytes from the platform RNG
 *   credential       "<canonical JSON>\n<ML-DSA-65 signature by the pinned gateway key over
 *                    "aegis-credential-v1\0" || JSON>"; the JSON must name SHA3-256(ct), SHA3-256(ek) of the pending
 *                    exchange and SHA-256(this pk), and carry "issued" and "expires" (seconds), whose difference
 *                    is the credential's lifetime
 *   session end      every request first reads the platform's monotonic clock (aegis_proto.h); a session older than
 *                    its lifetime plus a sixteenth, or a clock that fails or runs backwards, wipes the session key
 *                    (docs/endpoint-expiry.md). The start is this side's clock at the accepted PQKEMFIN: the
 *                    credential's times are only subtracted, never compared with a clock.
 *   session          SHA3-256("aegis-session-v1" || K || nonce || SHA3-256(ct))
 *   confirm tag      SHA3-256("aegis-confirm-v1" || K || nonce || SHA3-256(ct) || SHA3-256(credential))
 *   heartbeat        KMAC256(session, nonce || counter || status, 256, "aegis-hb-v2")
 * A refused exchange leaves an established session alone.
 *
 * One transcript (docs/architecture.md, common/transcript.py): the quote and the exchange that follows it are one
 * hash chain, so a verifier can refuse to finish a session with other code than the code whose quote it appraised.
 *   T1 = SHA3-256("aegis-transcript-v2/quote"    || challenge || SHA3-256(claims))   kept for the last quote signed
 *   T2 = SHA3-256("aegis-transcript-v2/kem-init" || T1 || ek)
 *   T3 = SHA3-256("aegis-transcript-v2/kem-fin"  || T2 || SHA3-256(ct) || SHA3-256(credential))
 * A PQKEMINIT whose nonce is the challenge of the last quote signed since the start continues that quote, once:
 *   KEM key signature  over "aegis-kem-init-v2\0" || T2 instead of "aegis-kem-init-v1\0" || nonce || ek
 *   credential         must also name T2 in "transcript_sha3_256" (else "ERR cred other-transcript")
 *   confirm tag        SHA3-256("aegis-confirm-v2" || K || T3)
 *   session            SHA3-256("aegis-session-v2" || K || T3)
 * Any other nonce gets the exchange above, unchanged, which a verifier that requires the transcript refuses (the
 * labels differ). The request and reply lines are the same in both. The quote is kept in RAM only: after a restart
 * there is none to continue. The measurements in a quote are what the platform gives when the quote is asked for:
 * taken once at start by the TF-M partition and by the ZynqMP's boot chain (the TA reports the FSBL's hand-off),
 * hashed from flash at every quote by the single-image prover. Nothing is measured again at PQKEMINIT: the transcript
 * says that this boot signed exactly that quote and then made this key for it.
 */
#include <stdio.h>
#include <string.h>

#include "mldsa_native.h"
#define MLK_CONFIG_FILE "aegis_mlkem_config.h"
#include "mlkem_native.h"

#include "aegis_kmac.h"
#include "aegis_proto.h"
#include "aegis_sha256.h"

#define KEM_EK_LEN  MLKEM_PUBLICKEYBYTES(768)
#define KEM_DK_LEN  MLKEM_SECRETKEYBYTES(768)
#define KEM_CT_LEN  MLKEM_CIPHERTEXTBYTES(768)
#define PK_LEN      MLDSA_PUBLICKEYBYTES(65)
#define SIG_LEN     MLDSA_BYTES(65)
#define CRED_MAX    6144u
#define CLAIMS_MAX  AEGIS_CLAIMS_MAX
#define AEGIS_STATUS_MAX 96u /* the platform's status text, with its terminator */

/* PSA claim numbers (common/psa_token.py), so the gateway's measurement check applies unchanged */
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

static uint8_t pk[PK_LEN];
static uint8_t sk[MLDSA_SECRETKEYBYTES(65)];
static uint8_t pk_sha256[32];
static uint8_t gw_pk[PK_LEN];
static uint8_t prov_root[32];
static uint8_t sig[SIG_LEN];
static uint8_t msgbuf[sizeof(KEM_LABEL) + 32 + KEM_EK_LEN + CRED_MAX];
static uint8_t claims[CLAIMS_MAX];
static uint8_t kem_ek[KEM_EK_LEN], kem_dk[KEM_DK_LEN], kem_nonce[32], kem_ct[KEM_CT_LEN];
static int kem_pending;
static uint32_t kem_counter;
static uint8_t quote_ch[32], quote_t1[32];  /* the last quote signed since the start: its challenge and T1 ... */
static int quote_ready;                     /* ... until a PQKEMINIT continues it, or another PQCHAL replaces it */
static uint8_t kem_t2[32];                  /* T2 of the pending exchange, when it continues a quote */
static int kem_bound;
static uint8_t cred[CRED_MAX];
static uint8_t session_key[32], cred_hash[32];
static int session_ready;
static int session_expired;                 /* the last session ended by the clock: "ERR pq expired" until the next */
static uint64_t session_start, session_limit; /* the clock at PQKEMFIN, and how many seconds the session may live */
static uint64_t now_s;                      /* this request's clock reading */
static int clock_ok;
static uint64_t hb_counter;
static const struct aegis_proto_platform *plat;

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

	while (n--) *v++ = 0;
}

/* One step of the transcript: SHA3-256(label || a || b || c). Every caller passes fields of fixed lengths, and no
 * label is the beginning of another, so the steps cannot be taken for one another. */
static void transcript_step(uint8_t out[32], const char *label, const uint8_t *a, size_t an, const uint8_t *b,
			    size_t bn, const uint8_t *c, size_t cn)
{
	struct sha3 h;

	sha3_init(&h);
	sha3_update(&h, label, strlen(label));
	sha3_update(&h, a, an);
	sha3_update(&h, b, bn);
	sha3_update(&h, c, cn);
	sha3_final(&h, out);
}

/* ---- hex and CBOR ---------------------------------------------------------------------------- */

static const char HX[] = "0123456789abcdef";

static char *put_hex(char *o, const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		*o++ = HX[p[i] >> 4];
		*o++ = HX[p[i] & 15];
	}
	return o;
}

static char *put_str(char *o, const char *s)
{
	size_t n = strlen(s);

	memcpy(o, s, n + 1);
	return o + n;
}

static int unhex(int c)
{
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return -1;
}

/* Decode in place: returns the byte count, or -1 if the text is not hex of even length or longer than cap. */
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

static uint8_t *cbor_head(uint8_t *p, unsigned major, uint64_t v)
{
	major <<= 5;
	if (v < 24) {
		*p++ = (uint8_t)(major | v);
	} else if (v < 0x100) {
		*p++ = (uint8_t)(major | 24); *p++ = (uint8_t)v;
	} else if (v < 0x10000) {
		*p++ = (uint8_t)(major | 25); *p++ = (uint8_t)(v >> 8); *p++ = (uint8_t)v;
	} else {
		*p++ = (uint8_t)(major | 26);
		for (int i = 3; i >= 0; i--) *p++ = (uint8_t)(v >> (8 * i));
	}
	return p;
}

static uint8_t *cbor_int(uint8_t *p, long v)
{
	return v >= 0 ? cbor_head(p, 0, (uint64_t)v) : cbor_head(p, 1, (uint64_t)(-1 - v));
}

static uint8_t *cbor_bytes(uint8_t *p, const uint8_t *b, size_t n)
{
	p = cbor_head(p, 2, n);
	memcpy(p, b, n);
	return p + n;
}

static uint8_t *cbor_text(uint8_t *p, const char *s)
{
	size_t n = strlen(s);

	p = cbor_head(p, 3, n);
	memcpy(p, s, n);
	return p + n;
}

/* ---- the protocol ---------------------------------------------------------------------------- */

int aegis_proto_init(const struct aegis_proto_platform *pl, const uint8_t seed[32], const uint8_t root[32],
		     const uint8_t gateway_pk[PK_LEN])
{
	plat = pl;
	memcpy(prov_root, root, 32);
	memcpy(gw_pk, gateway_pk, PK_LEN);
	if (aegis_mldsa_keypair_internal(pk, sk, seed) != 0) {
		return -1;
	}
	sha256(pk, PK_LEN, pk_sha256);
	return 0;
}

const uint8_t *aegis_proto_pk(void)
{
	return pk;
}

/* pure ML-DSA-65, empty context, hedged: M' = 0 || 0 || label || 0 || msg */
static int sign_framed(const char *label, size_t label_len, size_t msg_len)
{
	const uint8_t pre[2] = {0, 0};
	uint8_t rnd[32];
	int rc;

	if (plat->random(rnd, sizeof(rnd)) != 0) {
		return -1; /* no fresh randomness: refuse rather than sign deterministically */
	}
	memmove(msgbuf + label_len + 1, msgbuf, msg_len);
	memcpy(msgbuf, label, label_len + 1);
	rc = aegis_mldsa_signature_internal(sig, msgbuf, label_len + 1 + msg_len, pre, sizeof(pre), rnd, sk, 0);
	wipe(rnd, sizeof(rnd));
	return rc;
}

static int verify_framed(const uint8_t *s, const char *label, const uint8_t *m, size_t n)
{
	const uint8_t pre[2] = {0, 0};
	size_t l = strlen(label) + 1;

	if (l + n > sizeof(msgbuf)) return -1;
	memcpy(msgbuf, label, l);
	memcpy(msgbuf + l, m, n);
	return aegis_mldsa_verify_internal(s, msgbuf, l + n, pre, sizeof(pre), gw_pk, 0);
}

static uint8_t *put_component(uint8_t *p, const char *label, const uint8_t value[32], const char *desc)
{
	static const uint8_t zero[32];

	p = cbor_head(p, 5, 5);
	p = cbor_int(p, 1); p = cbor_text(p, label);
	p = cbor_int(p, 2); p = cbor_bytes(p, value, 32);
	p = cbor_int(p, 4); p = cbor_text(p, AEGIS_DEVICE_VERSION);
	p = cbor_int(p, 5); p = cbor_bytes(p, zero, 32);
	p = cbor_int(p, 6); p = cbor_text(p, desc);
	return p;
}

static size_t make_claims(const uint8_t challenge[32])
{
	static struct aegis_measurement m[AEGIS_MAX_MEASUREMENTS];
	uint8_t inst[33];
	size_t n = 0;
	uint8_t *p = claims;

	if (plat->measure_all) {
		n = plat->measure_all(m, AEGIS_MAX_MEASUREMENTS);
		if (n > AEGIS_MAX_MEASUREMENTS) n = AEGIS_MAX_MEASUREMENTS;
	} else {
		size_t img_len;

		plat->measure(m[0].value, &img_len);
		m[0].label = "APP";
		snprintf(m[0].desc, sizeof(m[0].desc), "SHA256 of the firmware image (%u bytes)", (unsigned)img_len);
		n = 1;
	}
	inst[0] = 0x02; /* not a PSA IAK-based instance ID: SHA-256 of the ML-DSA key */
	memcpy(inst + 1, pk_sha256, 32);
	p = cbor_head(p, 5, 4);
	p = cbor_int(p, C_PROFILE);
	p = cbor_text(p, plat->profile ? plat->profile : AEGIS_DEVICE_PROFILE);
	p = cbor_int(p, C_CHALLENGE);
	p = cbor_bytes(p, challenge, 32);
	p = cbor_int(p, C_INSTANCE);
	p = cbor_bytes(p, inst, sizeof(inst));
	p = cbor_int(p, C_SWC);
	p = cbor_head(p, 4, n);
	for (size_t i = 0; i < n; i++) {
		p = put_component(p, m[i].label, m[i].value, m[i].desc);
	}
	return (size_t)(p - claims);
}

/* the JSON body must contain "<key>":"<hex of v>" (canonical JSON: no spaces) */
static int names(const uint8_t *body, size_t n, const char *key, const uint8_t v[32])
{
	char want[128];
	size_t k = strlen(key), w;

	if (k + 69 > sizeof(want)) return 0;
	want[0] = '"';
	memcpy(want + 1, key, k);
	memcpy(want + 1 + k, "\":\"", 3);
	put_hex(want + 4 + k, v, 32);
	want[68 + k] = '"';
	w = 69 + k;
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
 * body does not carry one. The two times are the gateway's; this side has no wall clock to compare them with. */
static uint32_t cred_lifetime(const uint8_t *body, size_t n)
{
	uint64_t issued, expires;

	if (!number_of(body, n, "issued", &issued) || !number_of(body, n, "expires", &expires)) return 0;
	if (expires <= issued || expires - issued > AEGIS_CRED_LIFETIME_MAX) return 0;
	return (uint32_t)(expires - issued);
}

static void session_end(void)
{
	wipe(session_key, sizeof(session_key));
	wipe(cred_hash, sizeof(cred_hash));
	session_ready = 0;
	session_expired = 1;
}

/* Read the clock once per request, and end a session that has outlived its credential. A clock that fails or shows
 * less than at the session's start cannot measure the lifetime: the session ends too. */
static void session_sweep(void)
{
	now_s = 0;
	clock_ok = plat->monotonic_s != NULL && plat->monotonic_s(&now_s) == 0;
	if (session_ready && (!clock_ok || now_s < session_start || now_s - session_start >= session_limit)) {
		session_end();
	}
}

static int no_session(char *out, size_t cap)
{
	return snprintf(out, cap, "%s", session_expired ? "ERR pq expired" : "ERR pq no-session");
}

static int kem_finish(const char *ct_hex, const char *cred_hex, char *out, size_t cap)
{
	uint8_t k[32], h_ct[32], tag[32];
	long ct_len, cred_len;
	size_t body_len = 0;
	uint32_t lifetime;
	struct sha3 h;

	if (!kem_pending) {
		return snprintf(out, cap, "ERR cred no-exchange");
	}
	if (!clock_ok) {
		return snprintf(out, cap, "ERR clock"); /* a session's end could not be measured: none starts */
	}
	ct_len = get_hex(ct_hex, kem_ct, sizeof(kem_ct));
	cred_len = get_hex(cred_hex, cred, sizeof(cred));
	if (ct_len != KEM_CT_LEN || cred_len <= 0) {
		return snprintf(out, cap, "ERR bad-request");
	}
	kem_pending = 0;
	while (body_len < (size_t)cred_len && cred[body_len] != '\n') body_len++;
	if (body_len == (size_t)cred_len || (size_t)cred_len - body_len - 1 != SIG_LEN ||
	    verify_framed(cred + body_len + 1, CRED_LABEL, cred, body_len) != 0) {
		wipe(kem_dk, sizeof(kem_dk));
		return snprintf(out, cap, "ERR cred signature");
	}
	sha3_256(kem_ct, KEM_CT_LEN, h_ct);
	if (!names(cred, body_len, "kem_ct_sha3_256", h_ct)) {
		wipe(kem_dk, sizeof(kem_dk));
		return snprintf(out, cap, "ERR cred other-exchange");
	}
	if (!names(cred, body_len, "endpoint_pq_pk_sha256", pk_sha256)) {
		wipe(kem_dk, sizeof(kem_dk));
		return snprintf(out, cap, "ERR cred other-endpoint");
	}
	/* the credential must also name this exchange's encapsulation key: an old PQKEMFIN replayed after a new
	 * PQKEMINIT would otherwise pass and replace a working session (review 2026-11-18) */
	{
		uint8_t h_ek[32];

		sha3_256(kem_ek, sizeof(kem_ek), h_ek);
		if (!names(cred, body_len, "kem_ek_sha3_256", h_ek)) {
			wipe(kem_dk, sizeof(kem_dk));
			return snprintf(out, cap, "ERR cred other-key");
		}
	}
	/* an exchange that continues a quote: the gateway must have signed for that quote and this key (T2) */
	if (kem_bound && !names(cred, body_len, "transcript_sha3_256", kem_t2)) {
		wipe(kem_dk, sizeof(kem_dk));
		return snprintf(out, cap, "ERR cred other-transcript");
	}
	lifetime = cred_lifetime(cred, body_len);
	if (lifetime == 0) {
		wipe(kem_dk, sizeof(kem_dk));
		return snprintf(out, cap, "ERR cred validity");
	}
	if (aegis_mlkem_dec(k, kem_ct, kem_dk) != 0) {
		wipe(kem_dk, sizeof(kem_dk));
		return snprintf(out, cap, "ERR kem");
	}
	wipe(kem_dk, sizeof(kem_dk));
	sha3_256(cred, (size_t)cred_len, cred_hash);
	if (kem_bound) {
		uint8_t t3[32];

		transcript_step(t3, T_KEM_FIN, kem_t2, 32, h_ct, 32, cred_hash, 32);
		sha3_init(&h);
		sha3_update(&h, "aegis-session-v2", 16);
		sha3_update(&h, k, 32);
		sha3_update(&h, t3, 32);
		sha3_final(&h, session_key);
		sha3_init(&h);
		sha3_update(&h, "aegis-confirm-v2", 16);
		sha3_update(&h, k, 32);
		sha3_update(&h, t3, 32);
		sha3_final(&h, tag);
	} else {
		sha3_init(&h);
		sha3_update(&h, "aegis-session-v1", 16);
		sha3_update(&h, k, 32);
		sha3_update(&h, kem_nonce, 32);
		sha3_update(&h, h_ct, 32);
		sha3_final(&h, session_key);
		sha3_init(&h);
		sha3_update(&h, "aegis-confirm-v1", 16);
		sha3_update(&h, k, 32);
		sha3_update(&h, kem_nonce, 32);
		sha3_update(&h, h_ct, 32);
		sha3_update(&h, cred_hash, 32);
		sha3_final(&h, tag);
	}
	wipe(k, sizeof(k));
	session_ready = 1;
	session_expired = 0;
	session_start = now_s;
	session_limit = AEGIS_SESSION_LIMIT(lifetime);
	hb_counter = 0;
	memcpy(out, "PQKEMOK ", 8);
	memcpy(put_hex(out + 8, tag, 32), " END", 5);
	return 8 + 64 + 4;
}

int aegis_proto_handle(char *line, char *out, size_t cap)
{
	char *tok[4], *save = NULL;
	int n = 0;
	char *o;

	session_sweep(); /* before anything else, whatever the request */
	for (char *t = strtok_r(line, " \t\r\n", &save); t; t = strtok_r(NULL, " \t\r\n", &save)) {
		if (n == 4) return snprintf(out, cap, "ERR bad-request");
		tok[n++] = t;
	}
	if (n == 0) {
		return snprintf(out, cap, "ERR empty");
	}
	if (cap < 2 * (KEM_EK_LEN + SIG_LEN) + 64 || cap < 2 * (CLAIMS_MAX + SIG_LEN) + 64) {
		return snprintf(out, cap, "ERR internal");
	}
	if (!strcmp(tok[0], "PQKEY") && n == 1) {
		o = out + sprintf(out, "PQKEY %u ", (unsigned)PK_LEN);
		o = put_hex(o, pk, PK_LEN);
		return (int)(put_str(o, " END") - out);
	}
	if (!strcmp(tok[0], "PQCHAL") && n == 2) {
		uint8_t ch[32];
		size_t cl;

		if (get_hex(tok[1], ch, sizeof(ch)) != 32) return snprintf(out, cap, "ERR bad-request");
		quote_ready = 0; /* only a quote that was signed can be continued, and only the last one */
		cl = make_claims(ch);
		memcpy(msgbuf, claims, cl);
		if (sign_framed(QUOTE_LABEL, sizeof(QUOTE_LABEL) - 1, cl) != 0) return snprintf(out, cap, "ERR sign");
		{
			uint8_t h_claims[32];

			sha3_256(claims, cl, h_claims);
			transcript_step(quote_t1, T_QUOTE, ch, 32, h_claims, 32, NULL, 0);
			memcpy(quote_ch, ch, 32);
			quote_ready = 1;
		}
		o = out + sprintf(out, "PQTOKEN %u ", (unsigned)cl);
		o = put_hex(o, claims, cl);
		o += sprintf(o, " %u ", (unsigned)SIG_LEN);
		o = put_hex(o, sig, SIG_LEN);
		return (int)(put_str(o, " END") - out);
	}
	if (!strcmp(tok[0], "PQKEMINIT") && n == 2) {
		uint8_t coins[64], c[4], nonce[32], fresh[32];
		struct sha3 h;

		if (get_hex(tok[1], nonce, 32) != 32) return snprintf(out, cap, "ERR bad-request");
		/* A new exchange replaces a pending one whether or not it completes. Without this, a PQKEMINIT refused
		 * after the key was made (ERR sign, ERR kem) left the older exchange pending with this key and nonce in
		 * it: unusable, and its decapsulation key kept in memory (found by tests/fuzz, 2026-11-18). */
		kem_pending = 0;
		wipe(kem_dk, sizeof(kem_dk));
		/* The nonce names the quote this exchange continues: the challenge of the last one signed. That quote is
		 * used up here, whether or not the exchange completes. Any other nonce: the unbound exchange. (Both
		 * values are public, so the comparison need not take constant time.) */
		kem_bound = quote_ready && memcmp(nonce, quote_ch, 32) == 0;
		if (kem_bound) quote_ready = 0;
		/* fresh randomness too, so an exchange's key cannot be regenerated after a reboot */
		if (plat->random(fresh, sizeof(fresh)) != 0) return snprintf(out, cap, "ERR rng");
		memcpy(kem_nonce, nonce, 32);
		kem_counter++;
		c[0] = (uint8_t)kem_counter; c[1] = (uint8_t)(kem_counter >> 8);
		c[2] = (uint8_t)(kem_counter >> 16); c[3] = (uint8_t)(kem_counter >> 24);
		for (uint8_t half = 0; half < 2; half++) {
			sha3_init(&h);
			sha3_update(&h, prov_root, 32);
			sha3_update(&h, fresh, 32);
			sha3_update(&h, kem_nonce, 32);
			sha3_update(&h, c, 4);
			sha3_update(&h, &half, 1);
			sha3_final(&h, coins + 32 * half);
		}
		if (aegis_mlkem_keypair_derand(kem_ek, kem_dk, coins) != 0) {
			wipe(coins, sizeof(coins));
			return snprintf(out, cap, "ERR kem");
		}
		wipe(coins, sizeof(coins));
		wipe(fresh, sizeof(fresh));
		if (kem_bound) {
			transcript_step(kem_t2, T_KEM_INIT, quote_t1, 32, kem_ek, KEM_EK_LEN, NULL, 0);
			memcpy(msgbuf, kem_t2, 32);
		} else {
			memcpy(msgbuf, kem_nonce, 32);
			memcpy(msgbuf + 32, kem_ek, KEM_EK_LEN);
		}
		if ((kem_bound ? sign_framed(KEM2_LABEL, sizeof(KEM2_LABEL) - 1, 32)
			       : sign_framed(KEM_LABEL, sizeof(KEM_LABEL) - 1, 32 + KEM_EK_LEN)) != 0) {
			wipe(kem_dk, sizeof(kem_dk));
			return snprintf(out, cap, "ERR sign");
		}
		kem_pending = 1; /* the established session stays until a new exchange completes */
		o = out + sprintf(out, "PQKEMEK %u ", (unsigned)KEM_EK_LEN);
		o = put_hex(o, kem_ek, KEM_EK_LEN);
		o += sprintf(o, " %u ", (unsigned)SIG_LEN);
		o = put_hex(o, sig, SIG_LEN);
		return (int)(put_str(o, " END") - out);
	}
	if (!strcmp(tok[0], "PQKEMFIN") && n == 3) {
		return kem_finish(tok[1], tok[2], out, cap);
	}
	if (!strcmp(tok[0], "PQHB") && n == 2) {
		uint8_t nonce[32], ctr[8], tag[32];
		char status[AEGIS_STATUS_MAX + sizeof(";ttl=4294967295")];
		struct aegis_kmac km;
		int sl;

		if (!session_ready) return no_session(out, cap);
		if (get_hex(tok[1], nonce, 32) != 32) return snprintf(out, cap, "ERR bad-request");
		if (plat->status) {
			sl = plat->status(status, AEGIS_STATUS_MAX);
		} else {
			sl = snprintf(status, AEGIS_STATUS_MAX, "uptime_s=%u;link=1;fw=%s-%s", (unsigned)plat->uptime_s(),
				      AEGIS_DEVICE_FW, AEGIS_DEVICE_VERSION);
		}
		if (sl < 0 || (size_t)sl >= AEGIS_STATUS_MAX) return snprintf(out, cap, "ERR status");
		/* the seconds this session has left on this side's clock, under the MAC like the rest */
		sl += sprintf(status + sl, ";ttl=%u", (unsigned)(session_limit - (now_s - session_start)));
		hb_counter++; /* only for a heartbeat that is answered */
		for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(hb_counter >> (8 * i));
		aegis_kmac256_init(&km, session_key, 32, (const uint8_t *)"aegis-hb-v2", 11);
		aegis_kmac256_update(&km, nonce, 32);
		aegis_kmac256_update(&km, ctr, 8);
		aegis_kmac256_update(&km, (const uint8_t *)status, (size_t)sl);
		aegis_kmac256_final(&km, tag, 32);
		o = put_str(out, "PQHB ");
		o = put_hex(o, (const uint8_t *)status, (size_t)sl);
		*o++ = ' ';
		o = put_hex(o, ctr, 8);
		*o++ = ' ';
		o = put_hex(o, tag, 32);
		return (int)(put_str(o, " END") - out);
	}
	if (!strcmp(tok[0], "PQSESSION") && n == 1) {
		uint8_t id[32];
		struct sha3 h;

		if (!session_ready) return no_session(out, cap);
		sha3_init(&h);
		sha3_update(&h, "aegis-session-id-v1", 19);
		sha3_update(&h, session_key, 32);
		sha3_final(&h, id);
		o = put_str(out, "PQSESSION ");
		o = put_hex(o, id, 32);
		*o++ = ' ';
		o = put_hex(o, cred_hash, 32);
		return (int)(put_str(o, " END") - out);
	}
	return snprintf(out, cap, "ERR unknown");
}
