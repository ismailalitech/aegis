/* SPDX-License-Identifier: Apache-2.0 */
#ifndef AEGIS_PROTO_H
#define AEGIS_PROTO_H
#include <stddef.h>
#include <stdint.h>

#ifndef AEGIS_DEVICE_PROFILE
#define AEGIS_DEVICE_PROFILE "aegis-rw612-els-v1"
#endif
#ifndef AEGIS_DEVICE_FW
#define AEGIS_DEVICE_FW      "rw612"
#endif
#ifndef AEGIS_DEVICE_VERSION
#define AEGIS_DEVICE_VERSION "0.1.0"
#endif
/* the longest request: PQKEMFIN, a 1088-byte ciphertext and a credential of up to 6144 bytes, in hex */
#define AEGIS_LINE_MAX 14600u
#define AEGIS_REPLY_MAX 9600u

/* One reported software component (PSA claim names): its type label, SHA-256 value and a description. */
struct aegis_measurement {
	const char *label;
	uint8_t value[32];
	char desc[64];
};
/* The defaults fit every endpoint but the ZynqMP TA, whose build raises both (endpoints/zynqmp/optee/ta/sub.mk).
 * The claims take 121 bytes plus, per component, 81 + its label + its description (2 more from 24 characters). */
#ifndef AEGIS_MAX_MEASUREMENTS
#define AEGIS_MAX_MEASUREMENTS 4
#endif
#ifndef AEGIS_CLAIMS_MAX
#define AEGIS_CLAIMS_MAX 1024u
#endif

struct aegis_proto_platform {
	int (*random)(uint8_t *out, size_t n);           /* hardware randomness; 0 on success */
	void (*measure)(uint8_t out[32], size_t *len);   /* SHA-256 of the running image, and its length (APP) */
	uint32_t (*uptime_s)(void);
	/* Optional, used when set (the TF-M partition sets them; the Zephyr prover leaves them 0): */
	const char *profile;                                               /* claims profile */
	size_t (*measure_all)(struct aegis_measurement *m, size_t max);    /* several components instead of APP */
	int (*status)(char *buf, size_t cap);                              /* heartbeat status text */
};

/* seed: the ML-DSA-65 key seed, root: the provisioning root (both device-unique), gateway_pk: the pinned key */
int aegis_proto_init(const struct aegis_proto_platform *pl, const uint8_t seed[32], const uint8_t root[32],
		     const uint8_t gateway_pk[1952]);
const uint8_t *aegis_proto_pk(void);
/* One request line (changed in place) -> reply without line end in out; returns its length. */
int aegis_proto_handle(char *line, char *out, size_t cap);
#endif
