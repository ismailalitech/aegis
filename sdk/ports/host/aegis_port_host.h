/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Prover SDK, reference port: a PC (Linux, glibc). It is the worked example of sdk/README.md's porting guide
 * and what the host tests and the shared fuzz harness run the core through. It protects nothing: seed and keys are
 * in ordinary process memory. A product's port gives the same six things from its secure world.
 */
#ifndef AEGIS_PORT_HOST_H
#define AEGIS_PORT_HOST_H
#include "aegis_sdk.h"

#define AEGIS_HOST_MAX_IMAGES   4u
#define AEGIS_HOST_EVIDENCE_MAX 1024u /* the claims with four components fit (121 + 4 * about 150 bytes) */

struct aegis_host {
	struct aegis_prover prover;    /* the core's context: this port owns the storage, the core the content */
	struct aegis_platform platform;
	uint8_t work[AEGIS_WORK_LEN(AEGIS_HOST_EVIDENCE_MAX)];
	/* the measured "images": files, hashed again at every quote */
	struct {
		const char *label, *path, *what;
	} image[AEGIS_HOST_MAX_IMAGES];
	struct aegis_measurement meas[AEGIS_HOST_MAX_IMAGES];
	size_t images;
	const char *fw;                /* the default status text names "<fw>-<version>" */
	const char *status;            /* a fixed status text instead of the default, or NULL */
	uint64_t started;              /* time() at aegis_host_prepare, for the status text's uptime */
	/* the variant with the identity key held by the platform (aegis_host_start with platform_key) */
	uint8_t id_pk[AEGIS_PK_LEN], id_sk[AEGIS_SK_LEN];
};

/* Fill in the platform functions of this port. The caller may then change h->platform (the tests do: another
 * clock rate, a token in place of the claims) before aegis_host_start. */
void aegis_host_prepare(struct aegis_host *h, const char *profile, const char *fw, const char *version);
/* One more measured file: its component label ("APP", "SPE", ...) and what the description calls it. */
int aegis_host_add_image(struct aegis_host *h, const char *label, const char *path, const char *what);
/* Start the core: AEGIS_PROVER_INIT with this port's platform and buffers. seed and root are the device secrets a
 * product derives from its hardware key; verifier_pk must stay valid. With platform_key the port makes the key pair
 * itself and gives the core only the public key and a signing function, as a secure element would. */
int aegis_host_start(struct aegis_host *h, const uint8_t seed[AEGIS_SEED_LEN], const uint8_t root[AEGIS_SEED_LEN],
		     const uint8_t *verifier_pk, int platform_key);

/* Test seams: when set, they take the place of the operating system's random bytes and clock. */
extern int (*aegis_host_test_random)(uint8_t *out, size_t n);
extern int (*aegis_host_test_clock)(uint64_t *now);
#endif
