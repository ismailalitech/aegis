/* SPDX-License-Identifier: Apache-2.0
 * HMAC-SHA-256 for the PC tests, on the repository's one-shot SHA-256 (sdk/src/aegis_sha256.c), in the
 * shape aegis_handoff_kdf.h asks for. Short messages only. */
#ifndef HOST_HMAC_H
#define HOST_HMAC_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "aegis_handoff_kdf.h"
#include "aegis_sha256.h"

static int host_hmac_fails;

static int host_hmac_sha256(const uint8_t *key, size_t key_len, const struct aegis_kdf_part *part, size_t n,
			    uint8_t mac[32])
{
	uint8_t inner[64 + 512], outer[64 + 32];
	size_t len = 64;

	if (host_hmac_fails || key_len > 64)
		return -1;
	memset(inner, 0x36, 64);
	memset(outer, 0x5c, 64);
	for (size_t i = 0; i < key_len; i++) {
		inner[i] ^= key[i];
		outer[i] ^= key[i];
	}
	for (size_t i = 0; i < n; i++) {
		if (part[i].len > sizeof(inner) - len)
			abort();
		if (part[i].len)
			memcpy(inner + len, part[i].data, part[i].len);
		len += part[i].len;
	}
	aegis_sha256(inner, len, outer + 64);
	aegis_sha256(outer, sizeof(outer), mac);
	return 0;
}

#endif
