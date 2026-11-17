/* SPDX-License-Identifier: Apache-2.0
 * Host check of hedged signing with the partition's ML-DSA-65 configuration: derive a key pair from a
 * fixed seed, sign "aegis-endpoint-quote-v1\0" || msg twice, each time with 32 fresh bytes from
 * /dev/urandom as rnd (as the partition now does with TF-M's crypto service), and print pk and both
 * signatures as hex for verification by liboqs (tests/host/test_hedged_signing.py). */
#include <stdio.h>
#include <string.h>
#include "mldsa_native.h"

#define LABEL "aegis-endpoint-quote-v1"

static void hex(const char *tag, const uint8_t *p, size_t n)
{
	printf("%s ", tag);
	for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
	printf("\n");
}

int main(void)
{
	static uint8_t pk[MLDSA_PUBLICKEYBYTES(65)], sk[MLDSA_SECRETKEYBYTES(65)], sig[MLDSA_BYTES(65)];
	uint8_t seed[32], rnd[32], pre[2] = {0, 0}, m[64];
	const char msg[] = "hello from the hedged check";
	size_t ml = sizeof(LABEL) + sizeof(msg) - 1;
	FILE *u = fopen("/dev/urandom", "rb");

	if (!u) return 3;
	for (int i = 0; i < 32; i++) seed[i] = (uint8_t)i;
	memcpy(m, LABEL, sizeof(LABEL));          /* includes the NUL separator */
	memcpy(m + sizeof(LABEL), msg, sizeof(msg) - 1);
	if (aegis_mldsa_keypair_internal(pk, sk, seed)) return 1;
	hex("pk", pk, sizeof(pk));
	for (int k = 0; k < 2; k++) {
		if (fread(rnd, 1, sizeof(rnd), u) != sizeof(rnd)) return 4;
		if (aegis_mldsa_signature_internal(sig, m, ml, pre, 2, rnd, sk, 0)) return 2;
		hex(k == 0 ? "sig1" : "sig2", sig, sizeof(sig));
	}
	fclose(u);
	printf("msg %s\n", msg);
	return 0;
}
