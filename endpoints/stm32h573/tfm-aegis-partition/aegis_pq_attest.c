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
 *                                (deterministic ML-DSA, empty context)
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
 *                      "kem_ct_sha3_256"; otherwise PSA_ERROR_INVALID_SIGNATURE and no session.
 *   type 5 SESSION:    out[0] <- SHA3-256("aegis-session-id-v1" || session) || SHA3-256(credential)
 *   type 6 HEARTBEAT:  in[0] = 32-byte gateway nonce, in[1] = up to 128 bytes of NS status data
 *                      out[0] <- counter (8 bytes LE, increases every call)
 *                                || SHA3-256("aegis-hb-v1" || session || nonce || counter || data)
 *                      A light, symmetric proof of the session between full attestations.
 * The Non-Secure world can ask for quotes and run provisioning but never sees the seed, the
 * secret keys, K or the session key.
 */
#include <stdint.h>
#include <string.h>

#include "mldsa_native.h"
#define MLK_CONFIG_FILE "aegis_mlkem_config.h"
#include "mlkem_native.h"
#include "psa/client.h"
#include "psa/service.h"
#include "psa_manifest/aegis_pq_attest.h"
#include "psa_manifest/sid.h"
#include "stm32h5xx_hal.h"
#include "tfm_attest_defs.h"
#include "gateway_pk.h"

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

psa_status_t aegis_pq_init(void)
{
	uint8_t seed[32];

	if (derive_from_dhuk(seed_label, seed) != 0 || derive_from_dhuk(prov_label, prov_root) != 0) {
		wipe(seed, sizeof(seed));
		return PSA_SUCCESS; /* service stays up and answers PSA_ERROR_BAD_STATE */
	}
	key_ready = (aegis_mldsa_keypair_internal(pk, sk, seed) == 0);
	wipe(seed, sizeof(seed));
	return PSA_SUCCESS;
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
	if (aegis_mldsa_signature_internal(sig, signed_msg, sizeof(QUOTE_LABEL) + token_len, pre, sizeof(pre),
					   rnd, sk, 0) != 0) {
		return PSA_ERROR_GENERIC_ERROR;
	}
	psa_write(msg->handle, 0, token, token_len);
	psa_write(msg->handle, 1, sig, sizeof(sig));
	return PSA_SUCCESS;
}

static psa_status_t do_kem_init(const psa_msg_t *msg)
{
	static const char lbl[] = "aegis-kem-init-v1";
	uint8_t coins[64], rnd[32] = {0};
	const uint8_t pre[2] = {0, 0};
	struct sha3 h;
	uint8_t c[4];

	if (msg->in_size[0] != 32 || msg->out_size[0] < KEM_EK_LEN || msg->out_size[1] < sizeof(sig)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
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
	if (aegis_mldsa_signature_internal(sig, signed_msg, sizeof(lbl) + 32 + KEM_EK_LEN, pre, sizeof(pre), rnd, sk,
					   0) != 0) {
		return PSA_ERROR_GENERIC_ERROR;
	}
	kem_pending = 1;
	/* The established session stays valid until a new exchange completes (a stray or hostile
	 * KEM_INIT must not tear it down; found by review 2026-11-16). */
	psa_write(msg->handle, 0, kem_ek, KEM_EK_LEN);
	psa_write(msg->handle, 1, sig, sizeof(sig));
	return PSA_SUCCESS;
}

/* Credential = body || '\n' || ML-DSA-65 signature by the pinned gateway key over
 * "aegis-credential-v1\0" || body (pure ML-DSA, empty context). The body must contain
 * "kem_ct_sha3_256":"<hex of SHA3-256(ct)>" (canonical JSON), binding it to this exchange. */
static int check_credential(const uint8_t *c, size_t len, const uint8_t h_ct[32])
{
	static const char lbl[] = "aegis-credential-v1";
	static const char key[] = "\"kem_ct_sha3_256\":\"";
	static const char hx[] = "0123456789abcdef";
	const uint8_t pre[2] = {0, 0};
	char want[sizeof(key) - 1 + 64 + 1];
	size_t body_len = 0, i;

	while (body_len < len && c[body_len] != '\n') body_len++;
	if (body_len == len || len - body_len - 1 != MLDSA_BYTES(65) ||
	    sizeof(lbl) + body_len > sizeof(signed_msg)) {
		return -1;
	}
	memcpy(signed_msg, lbl, sizeof(lbl));
	memcpy(signed_msg + sizeof(lbl), c, body_len);
	if (aegis_mldsa_verify_internal(c + body_len + 1, signed_msg, sizeof(lbl) + body_len, pre, sizeof(pre),
					gateway_pk, 0) != 0) {
		return -1;
	}
	memcpy(want, key, sizeof(key) - 1);
	for (i = 0; i < 32; i++) {
		want[sizeof(key) - 1 + 2 * i] = hx[h_ct[i] >> 4];
		want[sizeof(key) - 1 + 2 * i + 1] = hx[h_ct[i] & 15];
	}
	want[sizeof(want) - 1] = '"';
	for (i = 0; i + sizeof(want) <= body_len; i++) {
		if (memcmp(c + i, want, sizeof(want)) == 0) {
			return 0;
		}
	}
	return -1;
}

static psa_status_t do_kem_finish(const psa_msg_t *msg)
{
	static const char l_sess[] = "aegis-session-v1", l_conf[] = "aegis-confirm-v1";
	uint8_t k[32], h_ct[32], tag[32];
	size_t cred_len = msg->in_size[1];
	struct sha3 h;

	if (!kem_pending) {
		return PSA_ERROR_BAD_STATE;
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
	if (check_credential(cred, cred_len, h_ct) != 0) {
		wipe(kem_dk, sizeof(kem_dk));
		return PSA_ERROR_INVALID_SIGNATURE;
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
	psa_write(msg->handle, 0, tag, 32);
	return PSA_SUCCESS;
}

static uint64_t hb_counter;

static psa_status_t do_heartbeat(const psa_msg_t *msg)
{
	static const char lbl[] = "aegis-hb-v1";
	uint8_t nonce[32], data[128], out[40], ctr[8];
	size_t dlen = msg->in_size[1];
	struct sha3 h;

	if (!session_ready) {
		return PSA_ERROR_BAD_STATE;
	}
	if (msg->in_size[0] != 32 || dlen > sizeof(data) || msg->out_size[0] < sizeof(out)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	if (psa_read(msg->handle, 0, nonce, 32) != 32 || (dlen && psa_read(msg->handle, 1, data, dlen) != dlen)) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}
	hb_counter++;
	for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(hb_counter >> (8 * i));
	sha3_init(&h);
	sha3_update(&h, (const uint8_t *)lbl, sizeof(lbl) - 1);
	sha3_update(&h, session_key, 32);
	sha3_update(&h, nonce, 32);
	sha3_update(&h, ctr, 8);
	sha3_update(&h, data, dlen);
	memcpy(out, ctr, 8);
	sha3_final(&h, out + 8);
	psa_write(msg->handle, 0, out, sizeof(out));
	return PSA_SUCCESS;
}

static psa_status_t do_session(const psa_msg_t *msg)
{
	static const char l_id[] = "aegis-session-id-v1";
	uint8_t out[64];
	struct sha3 h;

	if (!session_ready) {
		return PSA_ERROR_BAD_STATE;
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
