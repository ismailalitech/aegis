/* SPDX-License-Identifier: Apache-2.0
 * KMAC256 (NIST SP 800-185) on top of cSHAKE256: rate 136 bytes, domain bits 00.
 *   KMAC256(K, X, L, S) = cSHAKE256(bytepad(encode_string(K), 136) || X || right_encode(L), L, "KMAC", S)
 */
#include <string.h>
#include "aegis_kmac.h"

#define RATE 136

static const uint64_t rc[24] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808AULL, 0x8000000080008000ULL,
	0x000000000000808BULL, 0x0000000080000001ULL, 0x8000000080008081ULL, 0x8000000000008009ULL,
	0x000000000000008AULL, 0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000AULL,
	0x000000008000808BULL, 0x800000000000008BULL, 0x8000000000008089ULL, 0x8000000000008003ULL,
	0x8000000000008002ULL, 0x8000000000000080ULL, 0x000000000000800AULL, 0x800000008000000AULL,
	0x8000000080008081ULL, 0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL};
/* rotation offsets r[x + 5*y] */
static const uint8_t rot[25] = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};

static uint64_t rol(uint64_t v, unsigned n)
{
	return n ? (v << n) | (v >> (64 - n)) : v;
}

static void keccak_f(uint64_t a[25])
{
	uint64_t b[25], c[5], d;
	for (int r = 0; r < 24; r++) {
		for (int x = 0; x < 5; x++) c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		for (int x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ rol(c[(x + 1) % 5], 1);
			for (int y = 0; y < 25; y += 5) a[y + x] ^= d;
		}
		for (int x = 0; x < 5; x++)
			for (int y = 0; y < 5; y++)
				b[y + 5 * ((2 * x + 3 * y) % 5)] = rol(a[x + 5 * y], rot[x + 5 * y]);
		for (int y = 0; y < 25; y += 5)
			for (int x = 0; x < 5; x++) a[y + x] = b[y + x] ^ (~b[y + (x + 1) % 5] & b[y + (x + 2) % 5]);
		a[0] ^= rc[r];
	}
}

static void absorb(struct aegis_kmac *k, const uint8_t *p, size_t n)
{
	while (n--) {
		k->a[k->pos / 8] ^= (uint64_t)*p++ << (8 * (k->pos % 8));
		if (++k->pos == RATE) {
			keccak_f(k->a);
			k->pos = 0;
		}
	}
}

/* left_encode / right_encode of a bit count (fits in 8 bytes) */
static void enc(struct aegis_kmac *k, uint64_t x, int right)
{
	uint8_t b[9];
	int n = 1;
	while (n < 8 && (x >> (8 * n))) n++;
	for (int i = 0; i < n; i++) b[i] = (uint8_t)(x >> (8 * (n - 1 - i)));
	if (!right) absorb(k, (const uint8_t *)&(uint8_t){(uint8_t)n}, 1);
	absorb(k, b, (size_t)n);
	if (right) absorb(k, (const uint8_t *)&(uint8_t){(uint8_t)n}, 1);
}

static void encode_string(struct aegis_kmac *k, const uint8_t *s, size_t len)
{
	enc(k, (uint64_t)len * 8, 0);
	absorb(k, s, len);
}

static void pad_to_rate(struct aegis_kmac *k)
{
	static const uint8_t zero = 0;
	while (k->pos) absorb(k, &zero, 1);
}

void aegis_kmac256_init(struct aegis_kmac *k, const uint8_t *key, size_t key_len,
			const uint8_t *custom, size_t custom_len)
{
	memset(k, 0, sizeof(*k));
	enc(k, RATE, 0); /* bytepad(encode_string("KMAC") || encode_string(S), 136) */
	encode_string(k, (const uint8_t *)"KMAC", 4);
	encode_string(k, custom, custom_len);
	pad_to_rate(k);
	enc(k, RATE, 0); /* bytepad(encode_string(K), 136) */
	encode_string(k, key, key_len);
	pad_to_rate(k);
}

void aegis_kmac256_update(struct aegis_kmac *k, const uint8_t *data, size_t len)
{
	absorb(k, data, len);
}

void aegis_kmac256_final(struct aegis_kmac *k, uint8_t *out, size_t out_len)
{
	enc(k, (uint64_t)out_len * 8, 1);
	k->a[k->pos / 8] ^= (uint64_t)0x04 << (8 * (k->pos % 8)); /* cSHAKE domain 00, then pad10*1 */
	k->a[(RATE - 1) / 8] ^= (uint64_t)0x80 << 56;
	keccak_f(k->a);
	for (size_t i = 0, p = 0; i < out_len; i++, p++) {
		if (p == RATE) {
			keccak_f(k->a);
			p = 0;
		}
		out[i] = (uint8_t)(k->a[p / 8] >> (8 * (p % 8)));
	}
	memset(k, 0, sizeof(*k));
}
