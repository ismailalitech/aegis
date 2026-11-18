/* SPDX-License-Identifier: Apache-2.0
 * Print a gateway_pk.h for the PC tests of the STM32 partition: the ML-DSA-65 public key of the test gateway
 * (seed 0x47 repeated, the same key fuzz_stm32_partition.c signs credentials with). */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "mldsa_native.h"

int main(void)
{
	static uint8_t pk[MLDSA_PUBLICKEYBYTES(65)], sk[MLDSA_SECRETKEYBYTES(65)];
	uint8_t seed[32];

	memset(seed, 0x47, sizeof(seed));
	if (aegis_mldsa_keypair_internal(pk, sk, seed) != 0) return 1;
	printf("/* test gateway key for tests/fuzz/stm32 (seed 0x47 x 32); not the bench gateway's */\n");
	printf("#define AEGIS_GATEWAY_PK { \\\n");
	for (size_t i = 0; i < sizeof(pk); i++) printf("0x%02x,%s", pk[i], i % 16 == 15 ? " \\\n" : " ");
	printf("}\n");
	return 0;
}
