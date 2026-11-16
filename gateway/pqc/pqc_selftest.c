/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * On-board self-test of the aegis_pqc fabric core against software references:
 *   - Keccak-f[1600] on random states (and the all-zero known answer),
 *   - ML-KEM NTT / NTT^-1 (FIPS 203 Alg. 9/10) and ML-DSA NTT / NTT^-1 (FIPS 204 Alg. 41/42)
 *     on random canonical inputs,
 * and timing of each operation: core cycles (from the core's counters, 50 MHz) and wall time
 * seen by Linux including MMIO transfers, next to the software time on one U54 core.
 *
 *   pqc_selftest [iterations]          prints one JSON object; exit code 0 only if all match
 *   pqc_selftest --sw-only [iter]      software references self-check (no hardware access)
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "aegis_pqc_drv.h"

/* ---- references ------------------------------------------------------------------------- */

static const uint64_t RC[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL, 0x8000000080008000ULL,
	0x000000000000808bULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008aULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800aULL, 0x800000008000000aULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
static const int RHO[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

static uint64_t rol(uint64_t x, int n)
{
	return n ? (x << n) | (x >> (64 - n)) : x;
}

static void keccak_ref(uint64_t a[25])
{
	for (int r = 0; r < 24; r++) {
		uint64_t c[5], b[25];

		for (int x = 0; x < 5; x++) {
			c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		}
		for (int x = 0; x < 5; x++) {
			uint64_t d = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);

			for (int y = 0; y < 5; y++) {
				a[x + 5 * y] ^= d;
			}
		}
		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++) {
				b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], RHO[x + 5 * y]);
			}
		}
		for (int x = 0; x < 5; x++) {
			for (int y = 0; y < 5; y++) {
				a[x + 5 * y] = b[x + 5 * y] ^ (~b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
			}
		}
		a[0] ^= RC[r];
	}
}

static uint32_t pw(uint64_t b, uint64_t e, uint64_t q)
{
	uint64_t r = 1;

	b %= q;
	while (e) {
		if (e & 1) r = r * b % q;
		b = b * b % q;
		e >>= 1;
	}
	return (uint32_t)r;
}

static unsigned brv(unsigned x, int bits)
{
	unsigned r = 0;

	for (int i = 0; i < bits; i++) r |= ((x >> i) & 1u) << (bits - 1 - i);
	return r;
}

/* mode 0: ML-KEM (q 3329, zeta 17, 7 layers, len 128..2); mode 1: ML-DSA (q 8380417, zeta 1753, len 128..1) */
static void ntt_ref(int mode, int inverse, uint32_t f[256])
{
	const uint64_t q = mode ? 8380417u : 3329u, zeta = mode ? 1753u : 17u;
	const int bits = mode ? 8 : 7;
	const unsigned minlen = mode ? 1 : 2;
	unsigned k;

	if (!inverse) {
		k = mode ? 0 : 1;
		for (unsigned len = 128; len >= minlen; len >>= 1) {
			for (unsigned start = 0; start < 256; start += 2 * len) {
				uint64_t z;

				if (mode) k++;
				z = pw(zeta, brv(k, bits), q);
				if (!mode) k++;
				for (unsigned j = start; j < start + len; j++) {
					uint64_t t = z * f[j + len] % q;

					f[j + len] = (uint32_t)((f[j] + q - t) % q);
					f[j] = (uint32_t)((f[j] + t) % q);
				}
			}
		}
	} else {
		k = mode ? 256 : 127;
		for (unsigned len = minlen; len <= 128; len <<= 1) {
			for (unsigned start = 0; start < 256; start += 2 * len) {
				uint64_t z;

				/* FIPS 204 Alg. 42 uses -zeta * (t - w[j+len]) = zeta * (w[j+len] - t), the same
				 * butterfly as FIPS 203 Alg. 10. */
				if (mode) {
					k--;
					z = pw(zeta, brv(k, bits), q);
				} else {
					z = pw(zeta, brv(k, bits), q);
					k--;
				}
				for (unsigned j = start; j < start + len; j++) {
					uint64_t t = f[j];

					f[j] = (uint32_t)((t + f[j + len]) % q);
					f[j + len] = (uint32_t)((z * ((f[j + len] + q - t) % q)) % q);
				}
			}
		}
		{
			uint64_t s = mode ? 8347681u : 3303u;

			for (int j = 0; j < 256; j++) f[j] = (uint32_t)((uint64_t)f[j] * s % q);
		}
	}
}

/* Schoolbook product in Z_q[X]/(X^256 + 1). */
static void negacyclic_mul(uint64_t q, const uint32_t *a, const uint32_t *b, uint32_t *c)
{
	uint64_t acc[256] = {0};

	for (int i = 0; i < 256; i++) {
		for (int j = 0; j < 256; j++) {
			uint64_t p = (uint64_t)a[i] * b[j] % q;
			int k = i + j;

			if (k < 256) acc[k] = (acc[k] + p) % q;
			else acc[k - 256] = (acc[k - 256] + q - p) % q;
		}
	}
	for (int i = 0; i < 256; i++) c[i] = (uint32_t)acc[i];
}

/* NTT-domain product: ML-DSA pointwise; ML-KEM base-case multiply (FIPS 203 Alg. 11/12). */
static void ntt_mul(int mode, const uint32_t *a, const uint32_t *b, uint32_t *c)
{
	if (mode) {
		for (int i = 0; i < 256; i++) c[i] = (uint32_t)((uint64_t)a[i] * b[i] % 8380417u);
		return;
	}
	for (int i = 0; i < 128; i++) {
		uint64_t q = 3329, g = pw(17, 2 * brv((unsigned)i, 7) + 1, q);
		uint64_t a0 = a[2 * i], a1 = a[2 * i + 1], b0 = b[2 * i], b1 = b[2 * i + 1];

		c[2 * i] = (uint32_t)((a0 * b0 + a1 * b1 % q * g) % q);
		c[2 * i + 1] = (uint32_t)((a0 * b1 + a1 * b0) % q);
	}
}

/* ---- helpers ---------------------------------------------------------------------------- */

static uint64_t rng = 0x9E3779B97F4A7C15ULL;

static uint64_t rnd64(void)
{
	rng ^= rng << 13;
	rng ^= rng >> 7;
	rng ^= rng << 17;
	return rng;
}

static double now_us(void)
{
	struct timespec t;

	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

struct stat_t {
	double hw_us, sw_us;
	unsigned long n, bad;
	uint32_t cycles;
};

int main(int argc, char **argv)
{
	int sw_only = argc > 1 && strcmp(argv[1], "--sw-only") == 0;
	int iters = atoi(argc > 1 + sw_only ? argv[1 + sw_only] : "200");
	struct stat_t ks = {0}, ns[2][2];
	int zero_ok = 0, roundtrip_bad = 0;
	uint64_t z[25] = {0};

	memset(ns, 0, sizeof(ns));
	if (iters <= 0) iters = 200;
	if (sw_only) {
		/* references only: forward/inverse round trip and the Keccak zero-state answer */
		keccak_ref(z);
		zero_ok = z[0] == 0xF1258F7940E1DDE7ULL;
		for (int it = 0; it < iters; it++) {
			for (int m = 0; m < 2; m++) {
				uint32_t q = m ? 8380417u : 3329u, a[256], b[256];

				for (int i = 0; i < 256; i++) a[i] = b[i] = (uint32_t)(rnd64() % q);
				ntt_ref(m, 0, b);
				ntt_ref(m, 1, b);
				roundtrip_bad += memcmp(a, b, sizeof(a)) != 0;
			}
		}
		{
			int mul_bad = 0;

			for (int it = 0; it < 20; it++) {
				for (int m = 0; m < 2; m++) {
					uint32_t q = m ? 8380417u : 3329u, a[256], b[256], c[256], an[256], bn[256], cn[256];

					for (int i = 0; i < 256; i++) {
						an[i] = a[i] = (uint32_t)(rnd64() % q);
						bn[i] = b[i] = (uint32_t)(rnd64() % q);
					}
					negacyclic_mul(q, a, b, c);
					ntt_ref(m, 0, an);
					ntt_ref(m, 0, bn);
					ntt_mul(m, an, bn, cn);
					ntt_ref(m, 1, cn);
					mul_bad += memcmp(c, cn, sizeof(c)) != 0;
				}
			}
			printf("{\"mode\":\"sw-only\",\"keccak_zero_kat\":%s,\"ntt_roundtrip_failures\":%d,"
			       "\"ntt_multiplication_failures\":%d,\"iterations\":%d}\n",
			       zero_ok ? "true" : "false", roundtrip_bad, mul_bad, iters);
			return !(zero_ok && roundtrip_bad == 0 && mul_bad == 0);
		}
	}
	if (aegis_pqc_open() != 0) {
		fprintf(stderr, "aegis_pqc core not reachable\n");
		return 2;
	}
	aegis_pqc_keccak_f1600(z, &ks.cycles);
	zero_ok = z[0] == 0xF1258F7940E1DDE7ULL;

	for (int it = 0; it < iters; it++) {
		uint64_t a[25], b[25];
		double t0, t1, t2;

		for (int i = 0; i < 25; i++) a[i] = b[i] = rnd64();
		t0 = now_us();
		aegis_pqc_keccak_f1600(a, &ks.cycles);
		t1 = now_us();
		keccak_ref(b);
		t2 = now_us();
		ks.hw_us += t1 - t0;
		ks.sw_us += t2 - t1;
		ks.n++;
		ks.bad += memcmp(a, b, sizeof(a)) != 0;

		for (int m = 0; m < 2; m++) {
			for (int inv = 0; inv < 2; inv++) {
				uint32_t q = m ? 8380417u : 3329u, x[256], y[256];
				struct stat_t *s = &ns[m][inv];

				for (int i = 0; i < 256; i++) x[i] = y[i] = (uint32_t)(rnd64() % q);
				t0 = now_us();
				aegis_pqc_ntt(m, inv, x, &s->cycles);
				t1 = now_us();
				ntt_ref(m, inv, y);
				t2 = now_us();
				s->hw_us += t1 - t0;
				s->sw_us += t2 - t1;
				s->n++;
				s->bad += memcmp(x, y, sizeof(x)) != 0;
			}
		}
		/* hardware round trip */
		for (int m = 0; m < 2; m++) {
			uint32_t q = m ? 8380417u : 3329u, x[256], o[256];

			for (int i = 0; i < 256; i++) x[i] = o[i] = (uint32_t)(rnd64() % q);
			aegis_pqc_ntt(m, 0, x, NULL);
			aegis_pqc_ntt(m, 1, x, NULL);
			roundtrip_bad += memcmp(x, o, sizeof(x)) != 0;
		}
	}
	printf("{\"id\":\"0x%08x\",\"iterations\":%d,\"keccak_zero_kat\":%s,", (unsigned)aegis_pqc_id(), iters,
	       zero_ok ? "true" : "false");
	printf("\"keccak\":{\"mismatches\":%lu,\"core_cycles\":%u,\"hw_wall_us\":%.2f,\"sw_ref_us\":%.2f},", ks.bad,
	       ks.cycles, ks.hw_us / ks.n, ks.sw_us / ks.n);
	for (int m = 0; m < 2; m++) {
		for (int inv = 0; inv < 2; inv++) {
			struct stat_t *s = &ns[m][inv];

			printf("\"%s_%s\":{\"mismatches\":%lu,\"core_cycles\":%u,\"hw_wall_us\":%.2f,\"sw_ref_us\":%.2f},",
			       m ? "mldsa" : "mlkem", inv ? "intt" : "ntt", s->bad, s->cycles, s->hw_us / s->n,
			       s->sw_us / s->n);
		}
	}
	printf("\"hw_roundtrip_failures\":%d}\n", roundtrip_bad);
	return !(zero_ok && ks.bad == 0 && ns[0][0].bad == 0 && ns[0][1].bad == 0 && ns[1][0].bad == 0 &&
		 ns[1][1].bad == 0 && roundtrip_bad == 0);
}
