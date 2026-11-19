// SPDX-License-Identifier: Apache-2.0
/*
 * PC test of the keys OP-TEE takes from the hand-off's seed (aegis_handoff_kdf.c, taken out of ../os-patches by
 * run.sh) against values computed by Python's hmac module (kdf_kat.h, written by run.sh).
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "aegis_handoff_kdf.h"
#include "host_hmac.h"
#include "kdf_kat.h"

static int failures;

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			printf("FAIL %s:%d: %s\n", __func__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

static const uint8_t seed[32] = KAT_SEED;

static int all_zero(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++)
		if (p[i])
			return 0;
	return 1;
}

static void test_from_seed(void)
{
	static const uint8_t want_root[32] = KAT_ROOT, want_huk[16] = KAT_HUK;
	uint8_t root[32], huk[16], seed2[32];

	CHECK(aegis_kdf_from_seed(seed, host_hmac_sha256, root, huk) == 0);
	CHECK(!memcmp(root, want_root, 32));
	CHECK(!memcmp(huk, want_huk, 16));
	/* the HUK is not a piece of the root */
	CHECK(memcmp(huk, root, 16) && memcmp(huk, root + 16, 16));

	/* one bit of the seed changes both */
	memcpy(seed2, seed, 32);
	seed2[31] ^= 0x80;
	CHECK(aegis_kdf_from_seed(seed2, host_hmac_sha256, root, huk) == 0);
	CHECK(memcmp(root, want_root, 32) && memcmp(huk, want_huk, 16));

	memset(root, 0xff, sizeof(root));
	memset(huk, 0xff, sizeof(huk));
	host_hmac_fails = 1;
	CHECK(aegis_kdf_from_seed(seed, host_hmac_sha256, root, huk) == -1);
	host_hmac_fails = 0;
	CHECK(all_zero(root, 32) && all_zero(huk, 16));
}

static void test_subkey(void)
{
	static const uint8_t root[32] = KAT_ROOT, want_ta[32] = KAT_SUBKEY_TA, want_ssk[32] = KAT_SUBKEY_SSK,
			     want_big[32] = KAT_SUBKEY_BIG_USAGE, data[] = KAT_TA_DATA;
	uint8_t k[33];

	/* usage 3 (HUK_SUBKEY_UNIQUE_TA) with the system PTA's data: the TA's UUID and the label it passes */
	CHECK(aegis_kdf_subkey(root, 3, data, sizeof(data), host_hmac_sha256, k, 32) == 0);
	CHECK(!memcmp(k, want_ta, 32));
	/* usage 1 (HUK_SUBKEY_SSK), no data, given as NULL or as an empty buffer */
	CHECK(aegis_kdf_subkey(root, 1, NULL, 0, host_hmac_sha256, k, 32) == 0);
	CHECK(!memcmp(k, want_ssk, 32));
	CHECK(aegis_kdf_subkey(root, 1, data, 0, host_hmac_sha256, k, 32) == 0);
	CHECK(!memcmp(k, want_ssk, 32));
	/* the usage goes in as 4 bytes, lowest first */
	CHECK(aegis_kdf_subkey(root, 0x04030201u, NULL, 0, host_hmac_sha256, k, 32) == 0);
	CHECK(!memcmp(k, want_big, 32));

	/* a shorter key is the start of the longer one, and nothing is written past it */
	for (size_t n = 0; n <= 32; n++) {
		memset(k, 0xee, sizeof(k));
		CHECK(aegis_kdf_subkey(root, 3, data, sizeof(data), host_hmac_sha256, k, n) == 0);
		CHECK(!memcmp(k, want_ta, n) && k[n] == 0xee);
	}

	memset(k, 0xee, sizeof(k));
	CHECK(aegis_kdf_subkey(root, 3, data, sizeof(data), host_hmac_sha256, k, 33) == -1);
	CHECK(all_zero(k, 33));
	memset(k, 0xee, sizeof(k));
	host_hmac_fails = 1;
	CHECK(aegis_kdf_subkey(root, 3, data, sizeof(data), host_hmac_sha256, k, 32) == -1);
	host_hmac_fails = 0;
	CHECK(all_zero(k, 32) && k[32] == 0xee);
}

int main(void)
{
	test_from_seed();
	test_subkey();
	if (failures) {
		printf("%d check(s) FAILED\n", failures);
		return 1;
	}
	printf("hand-off key derivation: all checks passed (values from Python's hmac)\n");
	return 0;
}
