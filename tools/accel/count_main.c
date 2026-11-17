/* SPDX-License-Identifier: Apache-2.0
 * Bus traffic of the aegis_pqc2 SHA-3 provider per ML-KEM-768 / ML-DSA-65 operation, on the PC model.
 * Run with AEGIS_PQC_SPONGE=model; prints JSON for tools/accel/cost_model.py --counts. */
#include <oqs/oqs.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void aegis_sponge_counts(unsigned long c[8]);
static const char *names[8] = {"reads", "writes", "polls", "dma_cmds", "dma_bytes", "selects", "spills", "perms"};
static unsigned long before[8];

static void mark(void) { aegis_sponge_counts(before); }
static void dump(const char *op, int runs, int last)
{
	unsigned long now[8];
	aegis_sponge_counts(now);
	printf("  \"%s\": {", op);
	for (int i = 0; i < 8; i++) printf("%s\"%s\": %.2f", i ? ", " : "", names[i], (double)(now[i] - before[i]) / runs);
	printf("}%s\n", last ? "" : ",");
}

int main(int argc, char **argv)
{
	int runs = argc > 1 ? atoi(argv[1]) : 100;
	OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
	OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
	uint8_t pk[4096], sk[8192], ct[2048], ss[64], ss2[64], sg[8192], msg[64] = {1};
	size_t sl;
	if (!getenv("AEGIS_PQC_SPONGE")) {
		fprintf(stderr, "set AEGIS_PQC_SPONGE=model\n");
		return 2;
	}
	printf("{\n");
	mark(); for (int i = 0; i < runs; i++) OQS_KEM_keypair(kem, pk, sk); dump("ML-KEM-768 keygen", runs, 0);
	mark(); for (int i = 0; i < runs; i++) OQS_KEM_encaps(kem, ct, ss, pk); dump("ML-KEM-768 encaps", runs, 0);
	mark(); for (int i = 0; i < runs; i++) OQS_KEM_decaps(kem, ss2, ct, sk); dump("ML-KEM-768 decaps", runs, 0);
	mark(); for (int i = 0; i < runs; i++) OQS_SIG_keypair(sig, pk, sk); dump("ML-DSA-65 keygen", runs, 0);
	mark();
	for (int i = 0; i < runs; i++) { msg[0] = (uint8_t)i; OQS_SIG_sign(sig, sg, &sl, msg, sizeof(msg), sk); }
	dump("ML-DSA-65 sign", runs, 0);
	mark();
	for (int i = 0; i < runs; i++) if (OQS_SIG_verify(sig, msg, sizeof(msg), sg, sl, pk) != OQS_SUCCESS) return 1;
	dump("ML-DSA-65 verify", runs, 1);
	printf("}\n");
	return memcmp(ss, ss2, 32) != 0;
}
