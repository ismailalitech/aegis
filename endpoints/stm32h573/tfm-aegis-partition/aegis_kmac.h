/* SPDX-License-Identifier: Apache-2.0
 * KMAC256 (NIST SP 800-185) for the Aegis partition: init, update, final. Self-contained (own Keccak-f[1600]),
 * so the same file is built into the secure image and tested on the PC (tests/host/test_kmac_c.py). */
#ifndef AEGIS_KMAC_H
#define AEGIS_KMAC_H
#include <stddef.h>
#include <stdint.h>

struct aegis_kmac {
	uint64_t a[25];
	size_t pos;
};

void aegis_kmac256_init(struct aegis_kmac *k, const uint8_t *key, size_t key_len,
			const uint8_t *custom, size_t custom_len);
void aegis_kmac256_update(struct aegis_kmac *k, const uint8_t *data, size_t len);
/* out_len bytes of output; the length is part of the MAC (a 32-byte and a 64-byte tag are unrelated). */
void aegis_kmac256_final(struct aegis_kmac *k, uint8_t *out, size_t out_len);
#endif
