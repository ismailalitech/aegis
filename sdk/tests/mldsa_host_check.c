/* SPDX-License-Identifier: Apache-2.0
 * Host check of the partition's ML-DSA-65 configuration (reduced RAM, deterministic):
 * derive a key pair from a fixed seed, sign "aegis-endpoint-quote-v1\0" || msg with an empty
 * context, print pk/sig as hex for verification by liboqs on the PC. */
#include <stdio.h>
#include <string.h>
#include "mldsa_native.h"

#define LABEL "aegis-endpoint-quote-v1"

int main(void)
{
	static uint8_t pk[MLDSA_PUBLICKEYBYTES(65)], sk[MLDSA_SECRETKEYBYTES(65)], sig[MLDSA_BYTES(65)];
	uint8_t seed[32], rnd[32] = {0}, pre[2] = {0, 0}, m[64];
	const char msg[] = "hello from the host check";
	size_t ml = sizeof(LABEL) + sizeof(msg) - 1;

	for (int i = 0; i < 32; i++) seed[i] = (uint8_t)i;
	memcpy(m, LABEL, sizeof(LABEL));          /* includes the NUL separator */
	memcpy(m + sizeof(LABEL), msg, sizeof(msg) - 1);
	if (aegis_mldsa_keypair_internal(pk, sk, seed)) return 1;
	if (aegis_mldsa_signature_internal(sig, m, ml, pre, 2, rnd, sk, 0)) return 2;
	printf("pk ");
	for (size_t i = 0; i < sizeof(pk); i++) printf("%02x", pk[i]);
	printf("\nsig ");
	for (size_t i = 0; i < sizeof(sig); i++) printf("%02x", sig[i]);
	printf("\nmsg %s\n", msg);
	return 0;
}
