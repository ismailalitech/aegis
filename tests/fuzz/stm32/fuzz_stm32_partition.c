/* SPDX-License-Identifier: Apache-2.0
 *
 * libFuzzer harness for the STM32H573 TF-M partition (endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c),
 * built on the PC with ASan and UBSan against stand-ins for TF-M's PSA service API, the attestation service and the
 * SAES unit (stub/). Build and run: STM32=1 tests/fuzz/run.sh.
 *
 * The harness sends PSA messages as the non-secure prover would, and as a hostile non-secure image could (any
 * message type, any input and output sizes). It also plays the gateway, so the fuzzer gets past the credential
 * signature. An input is a list of operations "op, length (2 bytes, little-endian), payload":
 *   0  a raw message: type, two input sizes, two output sizes (from the payload), input bytes from the payload
 *   1  KEM_INIT with a nonce from the payload
 *   2  KEM_FINISH built as the gateway would, then changed (fields left out or wrong, text added, a newline, the
 *      signature or ciphertext damaged, or the payload signed as the whole body)
 *   3  HEARTBEAT with a nonce and status data from the payload
 *   4  QUOTE with a challenge from the payload
 *   5  SESSION
 *   6  after K good random draws, the next N fail
 *   7  GET_PUBKEY
 * Checks, besides the sanitizers:
 *   - no psa_write beyond the caller's output size (TF-M panics on it), no read of an input that is not there;
 *   - a credential is accepted if and only if an exchange is pending, the sizes are valid, its body has no newline and
 *     fits, the gateway's signature over it is valid, and it names SHA3-256(ct) and SHA3-256(ek) of the pending
 *     exchange (checked here independently); a raw message is never accepted as a credential;
 *   - a KEM_INIT with valid arguments that is refused leaves no exchange pending;
 *   - confirmation tag, session id, credential hash and every heartbeat tag are what the gateway computes; the
 *     heartbeat counter counts up by one (from boot, across sessions); a refused exchange leaves the session as it
 *     was;
 *   - every KEM key and quote is signed by the device key.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aegis_pq_attest.c"

#define DIE(...) do { fprintf(stderr, "ORACLE: " __VA_ARGS__); fputc('\n', stderr); abort(); } while (0)
#define SIG_LEN MLDSA_BYTES(65)
#define PK_LEN MLDSA_PUBLICKEYBYTES(65)

/* ---- stand-ins for TF-M and the HAL ---- */
static struct {
	const uint8_t *in[4];
	size_t in_len[4], in_pos[4];
	uint8_t *out[4];
	size_t out_cap[4], out_len[4];
} cur;
static uint64_t rng_state;
static unsigned rng_skip, rng_fail;

size_t psa_read(psa_handle_t h, uint32_t i, void *buf, size_t n)
{
	size_t left;

	(void)h;
	if (i >= 4) DIE("psa_read of invec %u", i);
	left = cur.in_len[i] - cur.in_pos[i];
	if (n > left) n = left;
	memcpy(buf, cur.in[i] + cur.in_pos[i], n);
	cur.in_pos[i] += n;
	return n;
}

void psa_write(psa_handle_t h, uint32_t i, const void *buf, size_t n)
{
	(void)h;
	if (i >= 4) DIE("psa_write to outvec %u", i);
	if (cur.out_len[i] + n > cur.out_cap[i])
		DIE("psa_write beyond the output size (outvec %u: %zu + %zu > %zu): TF-M would panic", i, cur.out_len[i], n,
		    cur.out_cap[i]);
	memcpy(cur.out[i] + cur.out_len[i], buf, n);
	cur.out_len[i] += n;
}

psa_status_t psa_generate_random(uint8_t *out, size_t n)
{
	if (rng_skip) {
		rng_skip--;
	} else if (rng_fail) {
		rng_fail--;
		return PSA_ERROR_INSUFFICIENT_ENTROPY;
	}
	for (size_t i = 0; i < n; i++) {
		rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
		out[i] = (uint8_t)(rng_state >> 24);
	}
	return PSA_SUCCESS;
}

/* the attestation service: a stand-in token that carries the challenge */
#define FZ_TOKEN_LEN 120u
psa_status_t psa_call(psa_handle_t handle, int32_t type, const psa_invec *in, size_t in_len, psa_outvec *out,
		      size_t out_len)
{
	uint8_t *t = out[0].base;

	if (handle != TFM_ATTESTATION_SERVICE_HANDLE || type != TFM_ATTEST_GET_TOKEN || in_len != 1 || out_len != 1 ||
	    in[0].len != 32 || out[0].len < FZ_TOKEN_LEN)
		DIE("unexpected psa_call");
	memset(t, 0xa7, FZ_TOKEN_LEN);
	memcpy(t, "FZTOKEN", 7);
	memcpy(t + 8, in[0].base, 32);
	out[0].len = FZ_TOKEN_LEN;
	return PSA_SUCCESS;
}

HAL_StatusTypeDef HAL_CRYP_Init(CRYP_HandleTypeDef *h) { (void)h; return HAL_OK; }
HAL_StatusTypeDef HAL_CRYP_DeInit(CRYP_HandleTypeDef *h) { (void)h; return HAL_OK; }
HAL_StatusTypeDef HAL_CRYP_Encrypt(CRYP_HandleTypeDef *h, uint32_t *in, uint16_t size, uint32_t *out, uint32_t t)
{
	(void)h; (void)t;
	for (unsigned i = 0; i < size; i++) ((uint8_t *)out)[i] = (uint8_t)(((const uint8_t *)in)[i] ^ 0x5c);
	return HAL_OK;
}

/* ---- the gateway's side ---- */
static uint8_t gw_sec[MLDSA_SECRETKEYBYTES(65)], gw_pub[PK_LEN];
static struct {
	int pending;
	uint8_t ek[KEM_EK_LEN], nonce[32];
	int session;
	uint8_t session_key[32], cred_hash[32];
	uint64_t hb;
} M;

/* one message; buffers are exactly the sizes the caller declares, so ASan sees any overrun */
static psa_status_t send(int32_t type, const uint8_t *in0, size_t l0, const uint8_t *in1, size_t l1, size_t o0,
			 size_t o1, uint8_t **out0, uint8_t **out1, size_t *w0, size_t *w1)
{
	psa_msg_t msg;
	psa_status_t st;
	uint8_t *a = malloc(l0 ? l0 : 1), *b = malloc(l1 ? l1 : 1);

	memset(&msg, 0, sizeof(msg));
	memset(&cur, 0, sizeof(cur));
	if (l0) memcpy(a, in0, l0);
	if (l1) memcpy(b, in1, l1);
	msg.type = type;
	msg.handle = 0x1234;
	msg.in_size[0] = l0; msg.in_size[1] = l1;
	msg.out_size[0] = o0; msg.out_size[1] = o1;
	cur.in[0] = a; cur.in_len[0] = l0;
	cur.in[1] = b; cur.in_len[1] = l1;
	cur.out[0] = malloc(o0 ? o0 : 1); cur.out_cap[0] = o0;
	cur.out[1] = malloc(o1 ? o1 : 1); cur.out_cap[1] = o1;
	st = aegis_pq_service_sfn(&msg);
	free(a);
	free(b);
	if (st != PSA_SUCCESS && (cur.out_len[0] || cur.out_len[1])) DIE("an error after writing output");
	*out0 = cur.out[0]; *out1 = cur.out[1];
	*w0 = cur.out_len[0]; *w1 = cur.out_len[1];
	return st;
}

static void sha3v(uint8_t out[32], int n, ...)
{
	struct sha3 h;
	va_list ap;

	sha3_init(&h);
	va_start(ap, n);
	for (int i = 0; i < n; i++) {
		const void *p = va_arg(ap, const void *);
		size_t l = va_arg(ap, size_t);

		sha3_update(&h, p, l);
	}
	va_end(ap);
	sha3_final(&h, out);
}

static int dev_verify(const char *label, const uint8_t *m, size_t n, const uint8_t *s)
{
	static uint8_t buf[64 + KEM_EK_LEN + TOKEN_MAX];
	const uint8_t pre[2] = {0, 0};
	size_t l = strlen(label) + 1;

	memcpy(buf, label, l);
	memcpy(buf + l, m, n);
	return aegis_mldsa_verify_internal(s, buf, l + n, pre, 2, pk, 0);
}

static int contains(const uint8_t *b, size_t n, const char *key, const uint8_t v[32])
{
	static const char hx[] = "0123456789abcdef";
	char want[160];
	int k = snprintf(want, sizeof(want), "\"%s\":\"", key);

	for (int i = 0; i < 32; i++) { want[k++] = hx[v[i] >> 4]; want[k++] = hx[v[i] & 15]; }
	want[k++] = '"';
	return memmem(b, n, want, (size_t)k) != NULL;
}

static size_t u16(const uint8_t *p, size_t n, size_t i) { return i + 1 < n ? (size_t)p[i] | (size_t)p[i + 1] << 8 : 0; }

/* ---- operations ---- */
static void op_raw(const uint8_t *p, size_t n)
{
	int32_t type = n ? (int32_t)(p[0] % 8) : 0;
	size_t l0 = u16(p, n, 1) % 8192, l1 = u16(p, n, 3) % 8192, o0 = u16(p, n, 5) % 8192, o1 = u16(p, n, 7) % 8192;
	const uint8_t *d = n > 9 ? p + 9 : p;
	size_t dn = n > 9 ? n - 9 : 0, w0, w1;
	uint8_t *r0, *r1;
	psa_status_t st;
	int valid_init;

	if (l0 > dn) l0 = dn;
	if (l1 > dn - l0) l1 = dn - l0;
	valid_init = type == AEGIS_PQ_KEM_INIT && l0 == 32 && o0 >= KEM_EK_LEN && o1 >= SIG_LEN;
	st = send(type, d, l0, d + l0, l1, o0, o1, &r0, &r1, &w0, &w1);
	if (valid_init) {
		M.pending = 0;
		if (st == PSA_SUCCESS) {
			if (w0 != KEM_EK_LEN) DIE("KEM_INIT output");
			memcpy(M.ek, r0, KEM_EK_LEN);
			memcpy(M.nonce, d, 32);
			M.pending = 1;
		}
	} else if (type == AEGIS_PQ_KEM_INIT && st == PSA_SUCCESS) {
		DIE("KEM_INIT with invalid arguments succeeded");
	} else if (type == AEGIS_PQ_KEM_FINISH) {
		if (st == PSA_SUCCESS) DIE("a raw message was accepted as a credential");
		if (!M.pending) {
			if (st != PSA_ERROR_BAD_STATE) DIE("KEM_FINISH without an exchange: %d", (int)st);
		} else if (st != PSA_ERROR_INVALID_ARGUMENT) {
			M.pending = 0;
		}
	} else if (type == AEGIS_PQ_HEARTBEAT && st == PSA_SUCCESS) {
		M.hb++;
	}
	free(r0);
	free(r1);
}

static void op_kem_init(const uint8_t *p, size_t n)
{
	uint8_t nonce[32] = {0}, msg[32 + KEM_EK_LEN], *r0, *r1;
	size_t w0, w1;
	psa_status_t st;

	memcpy(nonce, p, n < 32 ? n : 32);
	st = send(AEGIS_PQ_KEM_INIT, nonce, 32, NULL, 0, KEM_EK_LEN, SIG_LEN, &r0, &r1, &w0, &w1);
	M.pending = 0;
	if (st == PSA_SUCCESS) {
		if (w0 != KEM_EK_LEN || w1 != SIG_LEN) DIE("KEM_INIT output sizes");
		memcpy(msg, nonce, 32);
		memcpy(msg + 32, r0, KEM_EK_LEN);
		if (dev_verify("aegis-kem-init-v1", msg, sizeof(msg), r1) != 0) DIE("KEM key not signed by the device key");
		memcpy(M.ek, r0, KEM_EK_LEN);
		memcpy(M.nonce, nonce, 32);
		M.pending = 1;
	} else if (st != PSA_ERROR_INSUFFICIENT_ENTROPY && st != PSA_ERROR_GENERIC_ERROR) {
		DIE("KEM_INIT: %d", (int)st);
	}
	free(r0);
	free(r1);
}

#define F_DROP_CT   0x01
#define F_DROP_EK   0x02
#define F_BAD_SIG   0x08
#define F_BAD_CT    0x10
#define F_NEWLINE   0x20
#define F_STALE_EK  0x40
#define F_SIGN_RAW  0x80

static void op_kem_fin(const uint8_t *p, size_t n)
{
	static uint8_t body[CRED_MAX + 512], cred[CRED_MAX + 512 + SIG_LEN + 1], msg[32 + CRED_MAX + 512];
	static const char hx[] = "0123456789abcdef";
	const uint8_t pre[2] = {0, 0};
	uint8_t flags = n ? p[0] : 0, coins[32] = {0}, ct[KEM_CT_LEN], k[32], h_ct[32], h_ek[32], stale[32], rnd[32] = {0};
	const uint8_t *extra = n > 33 ? p + 33 : p;
	size_t extra_n = n > 33 ? n - 33 : 0, bl = 0, cl, ctl = KEM_CT_LEN, w0, w1;
	int pending = M.pending, expect, sizes_ok;
	uint8_t *r0, *r1;
	psa_status_t st;

	if (n > 1) memcpy(coins, p + 1, n - 1 < 32 ? n - 1 : 32);
	if (aegis_mlkem_enc_derand(ct, k, M.ek, coins) != 0) DIE("encaps");
	sha3_256(ct, KEM_CT_LEN, h_ct);
	sha3_256(M.ek, KEM_EK_LEN, h_ek);
	memset(stale, 0xa5, 32);
	if (!(flags & F_SIGN_RAW)) {
		const uint8_t *e = (flags & F_STALE_EK) ? stale : h_ek;

		bl += (size_t)sprintf((char *)body, "{\"endpoint\":\"stm32h573-dk-2\"");
		if (!(flags & F_DROP_CT)) {
			bl += (size_t)sprintf((char *)body + bl, ",\"kem_ct_sha3_256\":\"");
			for (int i = 0; i < 32; i++) { body[bl++] = hx[h_ct[i] >> 4]; body[bl++] = hx[h_ct[i] & 15]; }
			body[bl++] = '"';
		}
		if (!(flags & F_DROP_EK)) {
			bl += (size_t)sprintf((char *)body + bl, ",\"kem_ek_sha3_256\":\"");
			for (int i = 0; i < 32; i++) { body[bl++] = hx[e[i] >> 4]; body[bl++] = hx[e[i] & 15]; }
			body[bl++] = '"';
		}
		bl += (size_t)sprintf((char *)body + bl, ",\"x\":\"");
	}
	for (size_t i = 0; i < extra_n && bl < CRED_MAX; i++) {
		if (extra[i] == '\n' && !(flags & F_NEWLINE)) continue;
		body[bl++] = extra[i];
	}
	if (!(flags & F_SIGN_RAW)) { body[bl++] = '"'; body[bl++] = '}'; }
	memcpy(msg, "aegis-credential-v1", 20);
	memcpy(msg + 20, body, bl);
	memcpy(cred, body, bl);
	cred[bl] = '\n';
	if (aegis_mldsa_signature_internal(cred + bl + 1, msg, 20 + bl, pre, 2, rnd, gw_sec, 0) != 0) DIE("gateway sign");
	cl = bl + 1 + SIG_LEN;
	if (flags & F_BAD_SIG) cred[bl + 1 + (n ? p[n - 1] : 0u) * 13u % SIG_LEN] ^= 0x01;
	if (flags & F_BAD_CT) ctl--;
	st = send(AEGIS_PQ_KEM_FINISH, ct, ctl, cred, cl, 32, 0, &r0, &r1, &w0, &w1);

	sizes_ok = ctl == KEM_CT_LEN && cl > 0 && cl <= CRED_MAX;
	expect = pending && sizes_ok && !memchr(body, '\n', bl) && 20 + bl <= sizeof(signed_msg) &&
		 !(flags & F_BAD_SIG) && contains(body, bl, "kem_ct_sha3_256", h_ct) &&
		 contains(body, bl, "kem_ek_sha3_256", h_ek);
	if (!pending) {
		if (st != PSA_ERROR_BAD_STATE) DIE("KEM_FINISH without an exchange: %d", (int)st);
	} else if (!sizes_ok) {
		if (st != PSA_ERROR_INVALID_ARGUMENT) DIE("bad sizes: %d", (int)st);
	} else {
		M.pending = 0;
		if (expect != (st == PSA_SUCCESS))
			DIE("credential %s, but the model says %s (%d)", st == PSA_SUCCESS ? "accepted" : "refused",
			    expect ? "valid" : "invalid", (int)st);
		if (!expect && st != PSA_ERROR_INVALID_SIGNATURE) DIE("refusal code %d", (int)st);
	}
	if (expect) {
		uint8_t tag[32], h_cred[32];

		if (w0 != 32) DIE("KEM_FINISH output");
		sha3_256(cred, cl, h_cred);
		sha3v(tag, 5, "aegis-confirm-v1", (size_t)16, k, (size_t)32, M.nonce, (size_t)32, h_ct, (size_t)32,
		      h_cred, (size_t)32);
		if (memcmp(tag, r0, 32)) DIE("confirmation tag");
		sha3v(M.session_key, 4, "aegis-session-v1", (size_t)16, k, (size_t)32, M.nonce, (size_t)32, h_ct,
		      (size_t)32);
		memcpy(M.cred_hash, h_cred, 32);
		M.session = 1;
		/* M.hb is not reset: this partition's heartbeat counter runs from boot across sessions (the RW612's restarts
		 * at 1 with each session); the gateway only needs it to rise within a session, and the nonce makes each
		 * heartbeat fresh */
	}
	free(r0);
	free(r1);
}

static void op_hb(const uint8_t *p, size_t n)
{
	uint8_t nonce[32] = {0}, tag[32], ctr[8], *r0, *r1;
	const uint8_t *data = n > 32 ? p + 32 : p;
	size_t dl = n > 32 ? n - 32 : 0, w0, w1;
	struct aegis_kmac km;
	psa_status_t st;

	memcpy(nonce, p, n < 32 ? n : 32);
	st = send(AEGIS_PQ_HEARTBEAT, nonce, 32, data, dl, 40, 0, &r0, &r1, &w0, &w1);
	if (!M.session) {
		if (st != PSA_ERROR_BAD_STATE) DIE("HEARTBEAT without a session: %d", (int)st);
	} else if (dl > 128) {
		if (st != PSA_ERROR_INVALID_ARGUMENT) DIE("long heartbeat data: %d", (int)st);
	} else {
		if (st != PSA_SUCCESS || w0 != 40) DIE("HEARTBEAT: %d", (int)st);
		M.hb++;
		for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(M.hb >> (8 * i));
		if (memcmp(r0, ctr, 8)) DIE("heartbeat counter");
		aegis_kmac256_init(&km, M.session_key, 32, (const uint8_t *)"aegis-hb-v2", 11);
		aegis_kmac256_update(&km, nonce, 32);
		aegis_kmac256_update(&km, ctr, 8);
		aegis_kmac256_update(&km, data, dl);
		aegis_kmac256_final(&km, tag, 32);
		if (memcmp(tag, r0 + 8, 32)) DIE("heartbeat tag");
	}
	free(r0);
	free(r1);
}

static void op_quote(const uint8_t *p, size_t n)
{
	uint8_t ch[32] = {0}, *r0, *r1;
	size_t w0, w1;
	psa_status_t st;

	memcpy(ch, p, n < 32 ? n : 32);
	st = send(AEGIS_PQ_QUOTE, ch, 32, NULL, 0, TOKEN_MAX, SIG_LEN, &r0, &r1, &w0, &w1);
	if (st == PSA_SUCCESS) {
		if (w0 != FZ_TOKEN_LEN || w1 != SIG_LEN || memcmp(r0 + 8, ch, 32)) DIE("QUOTE output");
		if (dev_verify(QUOTE_LABEL, r0, w0, r1) != 0) DIE("quote not signed by the device key");
	} else if (st != PSA_ERROR_INSUFFICIENT_ENTROPY) {
		DIE("QUOTE: %d", (int)st);
	}
	free(r0);
	free(r1);
}

static void op_session(void)
{
	uint8_t id[32], *r0, *r1;
	size_t w0, w1;
	psa_status_t st = send(AEGIS_PQ_SESSION, NULL, 0, NULL, 0, 64, 0, &r0, &r1, &w0, &w1);

	if (!M.session) {
		if (st != PSA_ERROR_BAD_STATE) DIE("SESSION without a session");
	} else {
		sha3v(id, 2, "aegis-session-id-v1", (size_t)19, M.session_key, (size_t)32);
		if (st != PSA_SUCCESS || w0 != 64 || memcmp(r0, id, 32) || memcmp(r0 + 32, M.cred_hash, 32))
			DIE("session id or credential hash");
	}
	free(r0);
	free(r1);
}

static void op_pubkey(void)
{
	uint8_t *r0, *r1;
	size_t w0, w1;
	psa_status_t st = send(AEGIS_PQ_GET_PUBKEY, NULL, 0, NULL, 0, PK_LEN, 0, &r0, &r1, &w0, &w1);

	if (st != PSA_SUCCESS || w0 != PK_LEN || memcmp(r0, pk, PK_LEN)) DIE("GET_PUBKEY");
	free(r0);
	free(r1);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	uint8_t seed[32];

	(void)argc; (void)argv;
	memset(seed, 0x47, 32);
	if (aegis_mldsa_keypair_internal(gw_pub, gw_sec, seed) != 0) abort();
	if (memcmp(gw_pub, gateway_pk, PK_LEN)) abort(); /* the partition must pin the test gateway's key */
	if (aegis_pq_init() != PSA_SUCCESS || !key_ready) abort();
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t i = 0;
	int ops = 0;

	kem_pending = 0; session_ready = 0; hb_counter = 0; kem_counter = 0;
	memset(session_key, 0, sizeof(session_key));
	memset(&M, 0, sizeof(M));
	rng_state = 0x9e3779b97f4a7c15ull;
	rng_skip = rng_fail = 0;
	while (i + 3 <= size && ops++ < 24) {
		uint8_t op = data[i] & 7;
		size_t n = (size_t)data[i + 1] | (size_t)data[i + 2] << 8;
		const uint8_t *p = data + i + 3;

		if (n > size - i - 3) n = size - i - 3;
		i += 3 + n;
		switch (op) {
		case 0: op_raw(p, n); break;
		case 1: op_kem_init(p, n); break;
		case 2: op_kem_fin(p, n); break;
		case 3: op_hb(p, n); break;
		case 4: op_quote(p, n); break;
		case 5: op_session(); break;
		case 6: rng_skip = n ? p[0] & 3 : 0; rng_fail = n > 1 ? p[1] & 3 : 1; break;
		case 7: op_pubkey(); break;
		}
	}
	return 0;
}
