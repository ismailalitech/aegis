/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis line protocol for a device prover (kind "aegis-device"), with no RTOS in it: the RW612 firmware (main.c) and
 * the PC test (tests/host/test_rw612_proto.py, through host_main.c) build this same file.
 *
 *   PQKEY                    -> PQKEY <len> <hex> END                       the device's ML-DSA-65 public key
 *   PQCHAL <32-byte hex>     -> PQTOKEN <len> <claims> <len> <sig> END     CBOR claims, ML-DSA-65 signature
 *   PQKEMINIT <nonce>        -> PQKEMEK <len> <ek> <len> <sig> END          ML-KEM-768 key for this exchange, signed
 *   PQKEMFIN <ct> <cred>     -> PQKEMOK <tag> END | ERR cred <reason>       credential checked, then the session
 *   PQHB <nonce>             -> PQHB <status> <counter> <tag> END           KMAC256 over the session
 *   PQSESSION                -> PQSESSION <session id> <credential hash> END
 *
 * The constructions are the STM32 partition's (endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c):
 *   quote signature  ML-DSA-65 (pure, empty context, hedged) over "aegis-endpoint-quote-v1\0" || claims
 *   KEM key          ML-KEM-768.KeyGen(SHA3(prov_root || nonce || counter || 0) || SHA3(... || 1))
 *   credential       "<canonical JSON>\n<ML-DSA-65 signature by the pinned gateway key over
 *                    "aegis-credential-v1\0" || JSON>"; the JSON must name SHA3-256(ct) and SHA-256(this pk)
 *   session          SHA3-256("aegis-session-v1" || K || nonce || SHA3-256(ct))
 *   confirm tag      SHA3-256("aegis-confirm-v1" || K || nonce || SHA3-256(ct) || SHA3-256(credential))
 *   heartbeat        KMAC256(session, nonce || counter || status, 256, "aegis-hb-v2")
 * A refused exchange leaves an established session alone.
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
#define CLAIMS_MAX  1024u

/* PSA claim numbers (common/psa_token.py), so the gateway's measurement check applies unchanged */
#define C_PROFILE   (-75000)
#define C_SWC       (-75006)
#define C_CHALLENGE (-75008)
#define C_INSTANCE  (-75009)

static const char QUOTE_LABEL[] = "aegis-endpoint-quote-v1";
static const char KEM_LABEL[] = "aegis-kem-init-v1";
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
static uint8_t cred[CRED_MAX];
static uint8_t session_key[32], cred_hash[32];
static int session_ready;
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

static int kem_finish(const char *ct_hex, const char *cred_hex, char *out, size_t cap)
{
	uint8_t k[32], h_ct[32], tag[32];
	long ct_len, cred_len;
	size_t body_len = 0;
	struct sha3 h;

	if (!kem_pending) {
		return snprintf(out, cap, "ERR cred no-exchange");
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
	if (aegis_mlkem_dec(k, kem_ct, kem_dk) != 0) {
		wipe(kem_dk, sizeof(kem_dk));
		return snprintf(out, cap, "ERR kem");
	}
	wipe(kem_dk, sizeof(kem_dk));
	sha3_256(cred, (size_t)cred_len, cred_hash);
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
	wipe(k, sizeof(k));
	session_ready = 1;
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
		cl = make_claims(ch);
		memcpy(msgbuf, claims, cl);
		if (sign_framed(QUOTE_LABEL, sizeof(QUOTE_LABEL) - 1, cl) != 0) return snprintf(out, cap, "ERR sign");
		o = out + sprintf(out, "PQTOKEN %u ", (unsigned)cl);
		o = put_hex(o, claims, cl);
		o += sprintf(o, " %u ", (unsigned)SIG_LEN);
		o = put_hex(o, sig, SIG_LEN);
		return (int)(put_str(o, " END") - out);
	}
	if (!strcmp(tok[0], "PQKEMINIT") && n == 2) {
		uint8_t coins[64], c[4], nonce[32];
		struct sha3 h;

		if (get_hex(tok[1], nonce, 32) != 32) return snprintf(out, cap, "ERR bad-request");
		memcpy(kem_nonce, nonce, 32);
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
			return snprintf(out, cap, "ERR kem");
		}
		wipe(coins, sizeof(coins));
		memcpy(msgbuf, kem_nonce, 32);
		memcpy(msgbuf + 32, kem_ek, KEM_EK_LEN);
		if (sign_framed(KEM_LABEL, sizeof(KEM_LABEL) - 1, 32 + KEM_EK_LEN) != 0) {
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
		char status[96];
		struct aegis_kmac km;
		int sl;

		if (!session_ready) return snprintf(out, cap, "ERR pq no-session");
		if (get_hex(tok[1], nonce, 32) != 32) return snprintf(out, cap, "ERR bad-request");
		hb_counter++;
		for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(hb_counter >> (8 * i));
		if (plat->status) {
			sl = plat->status(status, sizeof(status));
		} else {
			sl = snprintf(status, sizeof(status), "uptime_s=%u;link=1;fw=%s-%s", (unsigned)plat->uptime_s(),
				      AEGIS_DEVICE_FW, AEGIS_DEVICE_VERSION);
		}
		if (sl < 0 || (size_t)sl >= sizeof(status)) return snprintf(out, cap, "ERR status");
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

		if (!session_ready) return snprintf(out, cap, "ERR pq no-session");
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
