/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AEGIS_PROTO_H
#define AEGIS_PROTO_H
#include <stddef.h>
#include <stdint.h>

#define AEGIS_DEVICE_PROFILE "aegis-rw612-els-v1"
#define AEGIS_DEVICE_FW      "rw612"
#define AEGIS_DEVICE_VERSION "0.1.0"
/* the longest request: PQKEMFIN, a 1088-byte ciphertext and a credential of up to 6144 bytes, in hex */
#define AEGIS_LINE_MAX 14600u
#define AEGIS_REPLY_MAX 9600u

struct aegis_proto_platform {
	int (*random)(uint8_t *out, size_t n);           /* hardware randomness; 0 on success */
	void (*measure)(uint8_t out[32], size_t *len);   /* SHA-256 of the running image, and its length */
	uint32_t (*uptime_s)(void);
};

/* seed: the ML-DSA-65 key seed, root: the provisioning root (both device-unique), gateway_pk: the pinned key */
int aegis_proto_init(const struct aegis_proto_platform *pl, const uint8_t seed[32], const uint8_t root[32],
		     const uint8_t gateway_pk[1952]);
const uint8_t *aegis_proto_pk(void);
/* One request line (changed in place) -> reply without line end in out; returns its length. */
int aegis_proto_handle(char *line, char *out, size_t cap);
#endif
