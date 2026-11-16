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
 * The Non-Secure world can ask for quotes but never sees the seed or the secret key.
 */
#include <stdint.h>
#include <string.h>

#include "mldsa_native.h"
#include "psa/client.h"
#include "psa/service.h"
#include "psa_manifest/aegis_pq_attest.h"
#include "psa_manifest/sid.h"
#include "stm32h5xx_hal.h"
#include "tfm_attest_defs.h"

#define AEGIS_PQ_GET_PUBKEY 1
#define AEGIS_PQ_QUOTE      2
#define CHALLENGE_LEN       32u
#define TOKEN_MAX           0x250u
#define QUOTE_LABEL         "aegis-endpoint-quote-v1"

static const uint8_t seed_label[32] = "aegis-stm32h5-mldsa65-seed-v1...";

static uint8_t pk[MLDSA_PUBLICKEYBYTES(65)];
static uint8_t sk[MLDSA_SECRETKEYBYTES(65)];
static uint8_t token[TOKEN_MAX];
static uint8_t signed_msg[sizeof(QUOTE_LABEL) + TOKEN_MAX];
static uint8_t sig[MLDSA_BYTES(65)];
static int key_ready;

static void wipe(void *p, size_t n)
{
	volatile uint8_t *v = p;

	while (n--) {
		*v++ = 0;
	}
}

static int derive_seed_from_dhuk(uint8_t out[32])
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
	    HAL_CRYP_Encrypt(&h, (uint32_t *)(uintptr_t)seed_label, sizeof(seed_label), (uint32_t *)out, 100) == HAL_OK) {
		rc = 0;
	}
	(void)HAL_CRYP_DeInit(&h);
	return rc;
}

psa_status_t aegis_pq_init(void)
{
	uint8_t seed[32];

	if (derive_seed_from_dhuk(seed) != 0) {
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
	default:
		return PSA_ERROR_NOT_SUPPORTED;
	}
}
