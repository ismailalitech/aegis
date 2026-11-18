// SPDX-License-Identifier: Apache-2.0
/*
 * PC test of the checks OP-TEE applies to the FSBL's hand-off page (aegis_handoff_parse.c, taken out of
 * ../os-patches by run.sh) on made-up pages. The SHA3-384 here is the test's own; run.sh adds a page whose digest
 * comes from Python's hashlib.
 *   test_handoff_parse [page.bin]
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "aegis_handoff_parse.h"
#include "aegis_ta.h"

static int failures;
static int hash_calls;
static int hash_fails;

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			printf("FAIL %s:%d: %s\n", __func__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

/* ---- Keccak-f[1600] and the 384-bit sponge; pad 0x06 is SHA3-384 (FIPS 202), pad 0x01 the original Keccak ---- */

static uint64_t rol(uint64_t x, int n)
{
	return (x << n) | (x >> (64 - n));
}

static void keccak_f(uint64_t a[25])
{
	static const uint64_t rc[24] = {
		0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull, 0x8000000080008000ull,
		0x000000000000808bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
		0x000000000000008aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
		0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull, 0x8000000000008003ull,
		0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800aull, 0x800000008000000aull,
		0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull };
	static const int rot[24] = { 1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
				     27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44 };
	static const int pil[24] = { 10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
				     15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1 };

	for (int r = 0; r < 24; r++) {
		uint64_t c[5], t;

		for (int i = 0; i < 5; i++)
			c[i] = a[i] ^ a[i + 5] ^ a[i + 10] ^ a[i + 15] ^ a[i + 20];
		for (int i = 0; i < 5; i++) {
			t = c[(i + 4) % 5] ^ rol(c[(i + 1) % 5], 1);
			for (int j = 0; j < 25; j += 5)
				a[j + i] ^= t;
		}
		t = a[1];
		for (int i = 0; i < 24; i++) {
			uint64_t u = a[pil[i]];

			a[pil[i]] = rol(t, rot[i]);
			t = u;
		}
		for (int j = 0; j < 25; j += 5) {
			for (int i = 0; i < 5; i++)
				c[i] = a[j + i];
			for (int i = 0; i < 5; i++)
				a[j + i] ^= ~c[(i + 1) % 5] & c[(i + 2) % 5];
		}
		a[0] ^= rc[r];
	}
}

static void sponge_384(const uint8_t *data, size_t len, uint8_t pad, uint8_t digest[48])
{
	const size_t rate = 104;
	uint8_t block[104];
	uint64_t a[25] = { 0 };

	for (;;) {
		size_t n = len < rate ? len : rate;

		memset(block, 0, sizeof(block));
		memcpy(block, data, n);
		if (n < rate) {
			block[n] ^= pad;
			block[rate - 1] ^= 0x80;
		}
		for (size_t i = 0; i < rate / 8; i++) {
			uint64_t w = 0;

			for (int b = 7; b >= 0; b--)
				w = (w << 8) | block[8 * i + b];
			a[i] ^= w;
		}
		keccak_f(a);
		if (n < rate)
			break;
		data += n;
		len -= n;
	}
	for (size_t i = 0; i < 48; i++)
		digest[i] = (uint8_t)(a[i / 8] >> (8 * (i % 8)));
}

static int t_sha3_384(const uint8_t *data, size_t len, uint8_t digest[48])
{
	hash_calls++;
	if (hash_fails)
		return -1;
	sponge_384(data, len, 0x06, digest);
	return 0;
}

/* ---- pages ---- */

#define DIGESTED offsetof(struct aegis_zynqmp_handoff, sha3_384)

static void seal(struct aegis_zynqmp_handoff *h)
{
	sponge_384((const uint8_t *)h, DIGESTED, 0x06, h->sha3_384);
}

static void good_page(struct aegis_zynqmp_handoff *h)
{
	static const char *const labels[6] = { "FSBL", "PMUFW", "PL", "TFA", "TEE", "UBOOT" };

	memset(h, 0, sizeof(*h));
	h->magic = AEGIS_HANDOFF_MAGIC;
	h->version = AEGIS_HANDOFF_VERSION;
	h->flags = AEGIS_HO_SEED_VALID | AEGIS_HO_KEY_BH_BLACK | AEGIS_HO_AES_CLEARED;
	h->count = 6;
	h->bh_key_src = 0xa5c3c5a7u;
	h->csu_status = 0x00000002u;
	for (size_t i = 0; i < sizeof(h->seed); i++)
		h->seed[i] = (uint8_t)(0xc0 + i);
	for (uint32_t i = 0; i < h->count; i++) {
		strncpy(h->meas[i].label, labels[i], sizeof(h->meas[i].label));
		for (size_t j = 0; j < sizeof(h->meas[i].value); j++)
			h->meas[i].value[j] = (uint8_t)(16 * (i + 1) + j);
		h->meas[i].length = 0x10000u * (i + 1) + 7;
		h->meas[i].attrib = 0x800u + i;
	}
	seal(h);
}

static int all_zero(const void *p, size_t n)
{
	const uint8_t *b = p;

	for (size_t i = 0; i < n; i++)
		if (b[i])
			return 0;
	return 1;
}

/* everything but the status is zero */
static int info_empty(const struct aegis_ho_info *info)
{
	struct aegis_ho_info z = *info;

	z.status = 0;
	return all_zero(&z, sizeof(z));
}

static int contains(const void *hay, size_t hn, const void *needle, size_t nn)
{
	for (size_t i = 0; i + nn <= hn; i++)
		if (!memcmp((const uint8_t *)hay + i, needle, nn))
			return 1;
	return 0;
}

/* ---- tests ---- */

static void test_sha3_known_answers(void)
{
	static const uint8_t empty[48] = {
		0x0c, 0x63, 0xa7, 0x5b, 0x84, 0x5e, 0x4f, 0x7d, 0x01, 0x10, 0x7d, 0x85, 0x2e, 0x4c, 0x24, 0x85,
		0xc5, 0x1a, 0x50, 0xaa, 0xaa, 0x94, 0xfc, 0x61, 0x99, 0x5e, 0x71, 0xbb, 0xee, 0x98, 0x3a, 0x2a,
		0xc3, 0x71, 0x38, 0x31, 0x26, 0x4a, 0xdb, 0x47, 0xfb, 0x6b, 0xd1, 0xe0, 0x58, 0xd5, 0xf0, 0x04 };
	static const uint8_t abc[48] = {
		0xec, 0x01, 0x49, 0x82, 0x88, 0x51, 0x6f, 0xc9, 0x26, 0x45, 0x9f, 0x58, 0xe2, 0xc6, 0xad, 0x8d,
		0xf9, 0xb4, 0x73, 0xcb, 0x0f, 0xc0, 0x8c, 0x25, 0x96, 0xda, 0x7c, 0xf0, 0xe4, 0x9b, 0xe4, 0xb2,
		0x98, 0xd8, 0x8c, 0xea, 0x92, 0x7a, 0xc7, 0xf5, 0x39, 0xf1, 0xed, 0xf2, 0x28, 0x37, 0x6d, 0x25 };
	uint8_t d[48];

	sponge_384((const uint8_t *)"", 0, 0x06, d);
	CHECK(!memcmp(d, empty, 48));
	sponge_384((const uint8_t *)"abc", 3, 0x06, d);
	CHECK(!memcmp(d, abc, 48));
}

static void test_absent(void)
{
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;

	memset(&h, 0, sizeof(h));
	memset(&info, 0xff, sizeof(info));
	hash_calls = 0;
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_ABSENT);
	CHECK(info.status == AEGIS_BOOT_HO_ABSENT && info_empty(&info));

	/* a good page with one bit of the magic wrong is no hand-off either */
	good_page(&h);
	h.magic ^= 1;
	memset(&info, 0xff, sizeof(info));
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_ABSENT);
	CHECK(info_empty(&info));
	CHECK(hash_calls == 0);
}

static void test_valid(void)
{
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;

	good_page(&h);
	memset(&info, 0xff, sizeof(info));
	hash_calls = 0;
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_VALID);
	CHECK(hash_calls == 1);
	CHECK(info.status == AEGIS_BOOT_HO_VALID);
	CHECK(info.flags == 7 && info.count == 6);
	CHECK(info.bh_key_src == 0xa5c3c5a7u && info.csu_status == 2);
	CHECK(!memcmp(info.meas, h.meas, 6 * sizeof(h.meas[0])));
	CHECK(all_zero(&info.meas[6], 2 * sizeof(info.meas[0])));
	CHECK(!strcmp(info.meas[5].label, "UBOOT") && info.meas[5].length == 0x60007u);
	/* no part of the seed is kept */
	CHECK(!contains(&info, sizeof(info), h.seed, 8));
	CHECK(!contains(&info, sizeof(info), h.seed + 24, 8));
}

static void test_count_limits(void)
{
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;

	good_page(&h);
	h.count = 0;
	seal(&h);
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_VALID);
	CHECK(info.count == 0 && all_zero(info.meas, sizeof(info.meas)));

	/* entries past count are not copied */
	good_page(&h);
	h.count = 3;
	seal(&h);
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_VALID);
	CHECK(info.count == 3 && all_zero(&info.meas[3], 5 * sizeof(info.meas[0])));

	good_page(&h);
	h.count = AEGIS_HANDOFF_MAX_MEAS;
	strcpy(h.meas[6].label, "KERNEL");
	strcpy(h.meas[7].label, "DTB");
	seal(&h);
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_VALID);
	CHECK(info.count == 8 && !strcmp(info.meas[7].label, "DTB"));

	for (uint32_t bad = AEGIS_HANDOFF_MAX_MEAS + 1; bad != 0; bad = bad < 0x80000000u ? bad * 2 : 0) {
		good_page(&h);
		h.count = bad;
		seal(&h);
		hash_calls = 0;
		memset(&info, 0xff, sizeof(info));
		CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_REJECTED);
		CHECK(info_empty(&info) && hash_calls == 0);
	}
	good_page(&h);
	h.count = 0xffffffffu;
	seal(&h);
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_REJECTED);
}

static void test_version(void)
{
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;

	for (uint32_t v = 0; v < 4; v++) {
		good_page(&h);
		h.version = v;
		seal(&h);
		hash_calls = 0;
		memset(&info, 0xff, sizeof(info));
		if (v == AEGIS_HANDOFF_VERSION) {
			CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_VALID);
		} else {
			CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_REJECTED);
			CHECK(info_empty(&info) && hash_calls == 0);
		}
	}
}

/* any single bit changed after the digest was taken, in the data or in the digest: rejected, nothing kept */
static void test_every_bit(void)
{
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;
	unsigned int rejected = 0, absent = 0;

	for (size_t bit = 0; bit < 8 * sizeof(h); bit++) {
		uint32_t st;

		good_page(&h);
		((uint8_t *)&h)[bit / 8] ^= (uint8_t)(1u << (bit % 8));
		st = aegis_handoff_parse(&h, t_sha3_384, &info);
		if (st == AEGIS_BOOT_HO_REJECTED)
			rejected++;
		else if (st == AEGIS_BOOT_HO_ABSENT && bit < 32)
			absent++;
		else
			CHECK(!"a changed page was accepted");
		if (!info_empty(&info))
			CHECK(!"a refused page left data");
	}
	CHECK(absent == 32 && rejected == 8 * sizeof(h) - 32);
}

static void test_hash_failure(void)
{
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;

	good_page(&h);
	hash_fails = 1;
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_REJECTED);
	CHECK(info_empty(&info));
	hash_fails = 0;
}

/* the digest must be SHA3-384 as in FIPS 202; the CSU's other padding (original Keccak) is refused */
static void test_keccak_padding(void)
{
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;

	good_page(&h);
	sponge_384((const uint8_t *)&h, DIGESTED, 0x01, h.sha3_384);
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_REJECTED);
}

static void test_labels(void)
{
	static const char expect1[16] = "A?b?c??";
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;

	good_page(&h);
	memcpy(h.meas[0].label, "0123456789abcdef", 16);       /* no NUL */
	memcpy(h.meas[1].label, "A b\tc\x7f\xe9\0hidden\0\0", 16); /* space, control, DEL, high bit; text after the end */
	memset(h.meas[2].label, 0, 16);                           /* empty */
	seal(&h);
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_VALID);
	CHECK(!memcmp(info.meas[0].label, "0123456789abcde\0", 16));
	CHECK(!memcmp(info.meas[1].label, expect1, 16));
	CHECK(all_zero(info.meas[2].label, 16));
	CHECK(!strcmp(info.meas[3].label, "TFA"));
	for (uint32_t i = 0; i < info.count; i++)
		CHECK(info.meas[i].label[15] == '\0');
	/* values and lengths are untouched */
	CHECK(!memcmp(info.meas[1].value, h.meas[1].value, 32) && info.meas[1].length == h.meas[1].length);
}

static void test_chip_bound(void)
{
	for (uint32_t f = 0; f < 16; f++)
		CHECK(aegis_handoff_seed_chip_bound(f) ==
		      ((f & AEGIS_HO_SEED_VALID) && (f & AEGIS_HO_KEY_BH_BLACK)));
	CHECK(aegis_handoff_seed_chip_bound(0xffffffffu));
	CHECK(!aegis_handoff_seed_chip_bound(AEGIS_HO_AES_CLEARED));
}

struct uuid {
	uint32_t a;
	uint16_t b, c;
	uint8_t d[8];
};

/* the PTA's only client is the Aegis TA, and the PTA has a UUID of its own */
static void test_uuids(void)
{
	static const struct uuid ta = AEGIS_TA_UUID, client = PTA_AEGIS_BOOT_CLIENT_UUID, pta = PTA_AEGIS_BOOT_UUID;

	CHECK(!memcmp(&ta, &client, sizeof(ta)));
	CHECK(memcmp(&ta, &pta, sizeof(ta)));
}

/* a whole 4 KiB page made by run.sh with Python's hashlib */
static void test_page_file(const char *path)
{
	static uint8_t page[AEGIS_HANDOFF_SIZE + 1];
	struct aegis_zynqmp_handoff h;
	struct aegis_ho_info info;
	FILE *f = fopen(path, "rb");
	size_t n = 0;

	CHECK(f != NULL);
	if (!f)
		return;
	n = fread(page, 1, sizeof(page), f);
	fclose(f);
	CHECK(n == AEGIS_HANDOFF_SIZE);
	memcpy(&h, page, sizeof(h));
	CHECK(aegis_handoff_parse(&h, t_sha3_384, &info) == AEGIS_BOOT_HO_VALID);
	CHECK(info.flags == 3 && info.count == 2);
	CHECK(info.bh_key_src == 0x11223344u && info.csu_status == 0x55667788u);
	CHECK(!strcmp(info.meas[0].label, "FSBL") && info.meas[0].length == 123456 && info.meas[0].attrib == 0x815);
	CHECK(!strcmp(info.meas[1].label, "TEE") && info.meas[1].value[0] == 0xbb && info.meas[1].value[31] == 0xbb);
	CHECK(aegis_handoff_seed_chip_bound(info.flags));
}

int main(int argc, char **argv)
{
	test_sha3_known_answers();
	test_absent();
	test_valid();
	test_count_limits();
	test_version();
	test_every_bit();
	test_hash_failure();
	test_keccak_padding();
	test_labels();
	test_chip_bound();
	test_uuids();
	if (argc > 1)
		test_page_file(argv[1]);
	if (failures) {
		printf("%d check(s) FAILED\n", failures);
		return 1;
	}
	printf("hand-off parsing: all checks passed%s\n", argc > 1 ? " (with the Python-made page)" : "");
	return 0;
}
