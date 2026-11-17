/* SPDX-License-Identifier: Apache-2.0
 * Replay the RTL test script (hw/tb/vectors/sponge_ops.txt) against the C model (gateway/pqc/aegis_sponge_model.c),
 * so the model the driver is tested with behaves as the RTL does. Same memory error window as the testbench. */
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include "aegis_sponge_hw.h"

#define ERR_BASE 0x80F000ULL
static uint64_t mem_a[65536], mem_v[65536];
static unsigned n_mem, beats;

static int mem_write(void *ctx, uint64_t pa, uint64_t v)
{
	(void)ctx;
	beats++;
	if (pa >= ERR_BASE && pa < ERR_BASE + 0x1000) return 1;
	for (unsigned i = 0; i < n_mem; i++)
		if (mem_a[i] == pa) { mem_v[i] = v; return 0; }
	mem_a[n_mem] = pa;
	mem_v[n_mem++] = v;
	return 0;
}

int main(int argc, char **argv)
{
	FILE *f = fopen(argc > 1 ? argv[1] : "hw/tb/vectors/sponge_ops.txt", "r");
	struct aegis_sponge_model *m = aegis_sponge_model_new(mem_write, NULL);
	char op[4];
	uint64_t a, b, c;
	unsigned ops = 0, checks = 0, errors = 0;
	if (!f || !m) return 2;
	while (fscanf(f, "%3s", op) == 1 && op[0] != 'E') {
		ops++;
		if (op[0] == 'W' && fscanf(f, "%" SCNx64 " %" SCNx64, &a, &b) == 2) {
			aegis_sponge_model_wr(m, (uint32_t)a, (uint32_t)b);
		} else if (op[0] == 'R' && fscanf(f, "%" SCNx64 " %" SCNx64 " %" SCNx64, &a, &b, &c) == 3) {
			checks++;
			if ((aegis_sponge_model_rd(m, (uint32_t)a) & c) != b) errors++;
		} else if (op[0] == 'D' && fscanf(f, "%" SCNx64 " %" SCNx64, &a, &b) == 2) {
			checks++;
			if ((aegis_sponge_model_rd(m, SP_STATUS) & b) != a) errors++;
		} else if (op[0] == 'M' && fscanf(f, "%" SCNx64 " %" SCNx64, &a, &b) == 2) {
			unsigned i, found = 0;
			checks++;
			for (i = 0; i < n_mem; i++)
				if (mem_a[i] == a) found = (mem_v[i] == b);
			if (!found) errors++;
		} else if (op[0] == 'N' && fscanf(f, "%" SCNx64, &a) == 1) {
			checks++;
			if (beats != a) errors++;
		} else {
			fprintf(stderr, "bad script line %u\n", ops);
			return 2;
		}
	}
	printf("replay_model: %u operations, %u checks, %u errors\n", ops, checks, errors);
	return errors != 0;
}
