/* SPDX-License-Identifier: Apache-2.0
 * Driver for tools/accel/profile_keccak.sh: runs each operation RUNS times and prints, per category, the mean number of
 * permutations and of calls that permuted ([perms, calls]). */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

extern unsigned long aegis_prof[3][4][2], aegis_calls[3][4][2];
static const char *ph[3] = {"none", "absorb", "squeeze"}, *rt[4] = {"168", "136", "72", "other"};

static void dump(const char *op, int runs, int last)
{
	printf("  \"%s\": {", op);
	int first = 1;
	for (int p = 0; p < 3; p++)
		for (int r = 0; r < 4; r++)
			for (int x = 0; x < 2; x++)
				if (aegis_prof[p][r][x]) {
					printf("%s\"%s/%s/%s\": [%.2f, %.2f]", first ? "" : ", ", ph[p], rt[r], x ? "x4" : "x1",
					       (double)aegis_prof[p][r][x] / runs, (double)aegis_calls[p][r][x] / runs);
					first = 0;
				}
	printf("}%s\n", last ? "" : ",");
	memset(aegis_prof, 0, sizeof(aegis_prof));
	memset(aegis_calls, 0, sizeof(aegis_calls));
}

int main(int argc, char **argv)
{
	int runs = argc > 1 ? atoi(argv[1]) : 200;
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	uint8_t pk[4096], sk[8192], ct[2048], ss[64], ss2[64], sg[8192], msg[64] = {1};
	size_t sl;
	printf("{\n");
	memset(aegis_prof, 0, sizeof(aegis_prof));
	for (int i = 0; i < runs; i++) OQS_KEM_keypair(kem, pk, sk);
	dump("ML-KEM-768 keygen", runs, 0);
	for (int i = 0; i < runs; i++) OQS_KEM_encaps(kem, ct, ss, pk);
	dump("ML-KEM-768 encaps", runs, 0);
	for (int i = 0; i < runs; i++) OQS_KEM_decaps(kem, ss2, ct, sk);
	dump("ML-KEM-768 decaps", runs, 0);
	for (int i = 0; i < runs; i++) OQS_SIG_keypair(sig, pk, sk);
	dump("ML-DSA-65 keygen", runs, 0);
	for (int i = 0; i < runs; i++) { msg[0] = (uint8_t)i; OQS_SIG_sign(sig, sg, &sl, msg, sizeof(msg), sk); }
	dump("ML-DSA-65 sign", runs, 0);
	for (int i = 0; i < runs; i++) { msg[0] = (uint8_t)i; if (OQS_SIG_verify(sig, msg, sizeof(msg), sg, sl, pk) != OQS_SUCCESS && i == runs - 1) return 1; }
	dump("ML-DSA-65 verify", runs, 1);
	printf("}\n");
	return memcmp(ss, ss2, 32) != 0;
}
