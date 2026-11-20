/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Prover SDK, reference port for a PC (see aegis_port_host.h). The platform layer in the order of
 * struct aegis_platform; sdk/README.md walks through it.
 */
#include <stdio.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

#if !defined(MLD_CONFIG_FILE)
#define MLD_CONFIG_FILE "aegis_mldsa_config.h"
#endif
#include "mldsa_native.h"

#include "aegis_port_host.h"
#include "aegis_sha256.h"

int (*aegis_host_test_random)(uint8_t *out, size_t n);
int (*aegis_host_test_clock)(uint64_t *now);

/* 1. Randomness: the kernel's generator. A product: the chip's TRNG, or a DRBG seeded from it, read in the secure
 * world. Whatever fails here makes the core refuse the request. */
static int host_random(void *user, uint8_t *out, size_t n)
{
	(void)user;
	if (aegis_host_test_random != NULL) return aegis_host_test_random(out, n);
	return getrandom(out, n, 0) == (ssize_t)n ? 0 : -1;
}

/* 2. Time: seconds that only go forward. A product: a counter the non-secure side cannot set, slow or stop (the
 * STM32 port's RTC on its own oscillator, the RW612 port's secure SysTick, OP-TEE's secure time); and it returns
 * nonzero as soon as that can no longer be said. */
static int host_clock(void *user, uint64_t *now)
{
	struct timespec ts;

	(void)user;
	if (aegis_host_test_clock != NULL) return aegis_host_test_clock(now);
	if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return -1;
	*now = (uint64_t)ts.tv_sec;
	return 0;
}

/* 3. Measurements: SHA-256 of each file as it is now. A product measures before the measured code runs, or has the
 * boot stage before it do so, and only reports here (the TF-M ports); a port that hashes at every quote, like this
 * one, reports what is in storage, not what was started. */
static int host_measurements(void *user, const struct aegis_measurement **list, size_t *count)
{
	static uint8_t img[4 << 20];
	struct aegis_host *h = user;

	for (size_t i = 0; i < h->images; i++) {
		FILE *f = fopen(h->image[i].path, "rb");
		size_t n;
		int whole;

		if (f == NULL) return -1; /* nothing to report: the quote is refused, not signed with a made-up value */
		n = fread(img, 1, sizeof(img), f);
		/* all of it or nothing: a read error, or a file longer than the buffer, is not hashed as far as it got */
		whole = !ferror(f) && (n < sizeof(img) || fgetc(f) == EOF);
		fclose(f);
		if (!whole) return -1;
		h->meas[i].label = h->image[i].label;
		aegis_sha256(img, n, h->meas[i].value);
		snprintf(h->meas[i].desc, sizeof(h->meas[i].desc), "SHA256 of the %s (%u bytes)", h->image[i].what, (unsigned)n);
	}
	*list = h->meas;
	*count = h->images;
	return 0;
}

/* 4. Identity, the variant where the platform holds the key: the core gets the public key and a signing function.
 * Pure ML-DSA-65 with an empty context, hedged with fresh randomness (FIPS 204). */
static int host_identity_public_key(void *user, uint8_t pk[AEGIS_PK_LEN])
{
	struct aegis_host *h = user;

	memcpy(pk, h->id_pk, AEGIS_PK_LEN);
	return 0;
}

static int host_identity_sign(void *user, const uint8_t *msg, size_t msg_len, uint8_t sig[AEGIS_SIG_LEN])
{
	const uint8_t pre[2] = {0, 0}; /* M' = 0 || 0 (empty context) || M */
	struct aegis_host *h = user;
	uint8_t rnd[32];
	int rc;

	if (host_random(user, rnd, sizeof(rnd)) != 0) return -1; /* no randomness, no signature */
	rc = aegis_mldsa_signature_internal(sig, msg, msg_len, pre, sizeof(pre), rnd, h->id_sk, 0);
	aegis_wipe(rnd, sizeof(rnd));
	return rc;
}

/* 5. Status text for the heartbeat (line transport). */
static int host_status(void *user, char *buf, size_t cap)
{
	struct aegis_host *h = user;

	if (h->status != NULL) return snprintf(buf, cap, "%s", h->status);
	return snprintf(buf, cap, "uptime_s=%u;link=1;fw=%s-%s", (unsigned)((uint64_t)time(NULL) - h->started), h->fw,
			h->platform.version);
}

void aegis_host_prepare(struct aegis_host *h, const char *profile, const char *fw, const char *version)
{
	memset(h, 0, sizeof(*h));
	h->fw = fw;
	h->started = (uint64_t)time(NULL);
	h->platform.user = h;
	h->platform.random = host_random;
	h->platform.clock = host_clock;
	h->platform.clock_hz = 1;
	h->platform.measurements = host_measurements;
	h->platform.profile = profile;
	h->platform.version = version;
	h->platform.status = host_status;
}

int aegis_host_add_image(struct aegis_host *h, const char *label, const char *path, const char *what)
{
	if (h->images == AEGIS_HOST_MAX_IMAGES) return -1;
	h->image[h->images].label = label;
	h->image[h->images].path = path;
	h->image[h->images].what = what;
	h->images++;
	return 0;
}

/* 6. Start: the secrets, the pinned verifier key and the buffers go to the core. */
int aegis_host_start(struct aegis_host *h, const uint8_t seed[AEGIS_SEED_LEN], const uint8_t root[AEGIS_SEED_LEN],
		     const uint8_t *verifier_pk, int platform_key)
{
	struct aegis_config cfg = {
		.platform = &h->platform,
		.verifier_pk = verifier_pk,
		.identity_seed = seed,
		.exchange_root = root,
		.work = h->work,
		.work_len = sizeof(h->work),
	};

	if (platform_key) {
		if (aegis_mldsa_keypair_internal(h->id_pk, h->id_sk, seed) != 0) return AEGIS_ERR_IDENTITY;
		h->platform.identity_public_key = host_identity_public_key;
		h->platform.identity_sign = host_identity_sign;
		cfg.identity_seed = NULL;
	}
	return AEGIS_PROVER_INIT(&h->prover, &cfg);
}
