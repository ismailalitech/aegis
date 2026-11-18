// SPDX-License-Identifier: Apache-2.0
/*
 * PC test of the Aegis TA (../ta/aegis_ta.c with the real protocol code) on a stand-in for OP-TEE (stub/): which
 * profile and which measurements a quote carries for each answer of the aegis.boot PTA, that the largest hand-off
 * fits the claims buffer, and which ML-DSA-65 key the TA gets. The stand-in derives the TA's keys as OP-TEE does:
 * without a seed of the chip's, OP-TEE 4.7.0's own construction with the development HUK, which must give the key
 * the board had in phase A (evidence/zynqmp/optee-phase-a.txt); with one, the patch's (aegis_handoff_kdf.c).
 * Built and run by run.sh (ASan, UBSan).
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tee_internal_api.h>
#include <pta_system.h>

#include "aegis_boot_pta.h"
#include "aegis_handoff_kdf.h"
#include "aegis_proto.h"
#include "aegis_sha256.h"
#include "aegis_ta.h"
#include "host_hmac.h"

#define CHIP   "aegis-zynqmp-optee-v1"
#define DEVHUK "aegis-zynqmp-optee-devhuk-v1"
/* sha256 of the ML-DSA-65 public key the board reported in phase A (development HUK) */
#define PHASE_A_KEY "5aefce9c1df80ffd6c0402b4f348d33576f49b0d6b8a81d79d2ca664ae00b684"
#define HUK_SUBKEY_UNIQUE_TA 3u /* OP-TEE: enum huk_subkey_usage */

/* ---- the stand-in for OP-TEE ---- */

static struct {
	int present;         /* 0: opening aegis.boot gives TEE_ERROR_ITEM_NOT_FOUND */
	TEE_Result invoke;   /* result of GET_INFO when not TEE_SUCCESS */
	uint32_t status, flags, count, huk;
	size_t size_delta;   /* added to the returned memref size */
	int chip_keys;       /* OP-TEE took its keys from seed[] (a valid hand-off with both flags) */
	uint8_t seed[32];
	struct aegis_ho_meas meas[AEGIS_HANDOFF_MAX_MEAS + 1];
} pta;

struct stub_session {
	int is_boot;
};

static struct stub_session sys_session = { 0 }, boot_session = { 1 };
static int failures;
char stub_log[2048];

#define CHECK(cond) \
	do { \
		if (!(cond)) { \
			printf("FAIL %s:%d: %s\n", __func__, __LINE__, #cond); \
			failures++; \
		} \
	} while (0)

void stub_msg(const char *fmt, ...)
{
	size_t n = strlen(stub_log);
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(stub_log + n, sizeof(stub_log) - n, fmt, ap);
	va_end(ap);
}

void TEE_GenerateRandom(void *buf, size_t n)
{
	static uint8_t x;

	for (size_t i = 0; i < n; i++)
		((uint8_t *)buf)[i] = x += 0x9d;
}

void TEE_GetSystemTime(TEE_Time *t)
{
	t->seconds = 42;
	t->millis = 0;
}

void TEE_MemFill(void *buf, uint32_t x, size_t n)
{
	memset(buf, (int)x, n);
}

TEE_Result TEE_OpenTASession(const TEE_UUID *dest, uint32_t timeout, uint32_t pt, TEE_Param params[TEE_NUM_PARAMS],
			     TEE_TASessionHandle *sess, uint32_t *origin)
{
	static const TEE_UUID sys = PTA_SYSTEM_UUID, boot = PTA_AEGIS_BOOT_UUID;

	(void)timeout; (void)pt; (void)params; (void)origin;
	if (!memcmp(dest, &sys, sizeof(sys))) {
		*sess = &sys_session;
		return TEE_SUCCESS;
	}
	if (!memcmp(dest, &boot, sizeof(boot)) && pta.present) {
		*sess = &boot_session;
		return TEE_SUCCESS;
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

void TEE_CloseTASession(TEE_TASessionHandle sess)
{
	(void)sess;
}

/*
 * PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY as OP-TEE 4.7.0 serves it (core/pta/system.c): huk_subkey_derive() with usage
 * HUK_SUBKEY_UNIQUE_TA over the calling TA's UUID (the 16 bytes of its TEE_UUID) followed by the TA's label.
 *   Without a seed of the chip's: core/kernel/huk_subkey.c, HMAC-SHA-256 keyed with the 16-byte hardware unique
 *   key, here the development one (zero), over the usage as 4 bytes and that data.
 *   With one: the patch's replacement, aegis_kdf_subkey() keyed with the 32-byte root.
 */
static TEE_Result system_derive(const void *label, size_t label_len, uint8_t *out, size_t out_len)
{
	static const TEE_UUID ta = AEGIS_TA_UUID;
	static const uint8_t dev_huk[16];
	const uint8_t usage[4] = { HUK_SUBKEY_UNIQUE_TA, 0, 0, 0 };
	uint8_t data[sizeof(ta) + 64], root[32], huk[16], mac[32];

	if (label_len > 64 || out_len < 16 || out_len > 32)
		return TEE_ERROR_BAD_PARAMETERS;
	memcpy(data, &ta, sizeof(ta));
	memcpy(data + sizeof(ta), label, label_len);
	if (pta.chip_keys) {
		if (aegis_kdf_from_seed(pta.seed, host_hmac_sha256, root, huk) ||
		    aegis_kdf_subkey(root, HUK_SUBKEY_UNIQUE_TA, data, sizeof(ta) + label_len, host_hmac_sha256, out,
				     out_len))
			return TEE_ERROR_GENERIC;
	} else {
		const struct aegis_kdf_part part[2] = { { usage, sizeof(usage) }, { data, sizeof(ta) + label_len } };

		if (host_hmac_sha256(dev_huk, sizeof(dev_huk), part, 2, mac))
			return TEE_ERROR_GENERIC;
		memcpy(out, mac, out_len);
	}
	return TEE_SUCCESS;
}

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle sess, uint32_t timeout, uint32_t cmd, uint32_t pt,
			       TEE_Param p[TEE_NUM_PARAMS], uint32_t *origin)
{
	(void)timeout; (void)origin;
	if (!sess->is_boot) {
		if (cmd != PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY ||
		    pt != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, 0, 0))
			return TEE_ERROR_BAD_PARAMETERS;
		return system_derive(p[0].memref.buffer, p[0].memref.size, p[1].memref.buffer, p[1].memref.size);
	}
	if (cmd != PTA_AEGIS_BOOT_CMD_GET_INFO ||
	    pt != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
				  TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT))
		return TEE_ERROR_BAD_PARAMETERS;
	if (pta.invoke != TEE_SUCCESS)
		return pta.invoke;
	p[0].value.a = pta.status;
	p[0].value.b = pta.flags;
	p[1].value.a = 0xa5c3c5a7u;
	p[1].value.b = 2;
	p[2].value.a = pta.count;
	p[2].value.b = pta.huk;
	if (pta.count <= AEGIS_HANDOFF_MAX_MEAS) {
		CHECK(p[3].memref.size >= pta.count * sizeof(pta.meas[0]));
		memcpy(p[3].memref.buffer, pta.meas, pta.count * sizeof(pta.meas[0]));
	}
	p[3].memref.size = pta.count * sizeof(pta.meas[0]) + pta.size_delta;
	return TEE_SUCCESS;
}

/* ---- one boot of the TA and one quote ---- */

static uint8_t claims[4096];
static size_t claims_len;

static int has(const void *needle, size_t n)
{
	for (size_t i = 0; i + n <= claims_len; i++)
		if (!memcmp(claims + i, needle, n))
			return 1;
	return 0;
}

static int has_text(const char *s)
{
	return has(s, strlen(s));
}

static size_t count_text(const char *s)
{
	size_t n = strlen(s), c = 0;

	for (size_t i = 0; i + n <= claims_len; i++)
		if (!memcmp(claims + i, s, n))
			c++;
	return c;
}

/* sha256 of the TA's ML-DSA-65 public key, in hex */
static const char *key_hash(void)
{
	static char hex[65];
	uint8_t h[32];

	sha256(aegis_proto_pk(), 1952, h);
	for (int i = 0; i < 32; i++)
		sprintf(hex + 2 * i, "%02x", h[i]);
	return hex;
}

/* every component carries the version text once */
static size_t components(void)
{
	return count_text(AEGIS_DEVICE_VERSION);
}

static void boot_and_quote(void)
{
	static char req[] = "PQCHAL 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	static char reply[AEGIS_TA_REPLY_MAX + 1];
	TEE_Param p[TEE_NUM_PARAMS];
	unsigned int len = 0, sig_len = 0;
	int off = 0;

	memset(p, 0, sizeof(p));
	stub_log[0] = '\0';
	claims_len = 0;
	CHECK(TA_CreateEntryPoint() == TEE_SUCCESS);
	p[0].memref.buffer = req;
	p[0].memref.size = strlen(req);
	p[1].memref.buffer = reply;
	p[1].memref.size = AEGIS_TA_REPLY_MAX;
	CHECK(TA_InvokeCommandEntryPoint(NULL, AEGIS_TA_CMD_LINE,
					 TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, 0, 0),
					 p) == TEE_SUCCESS);
	CHECK(p[1].memref.size <= AEGIS_TA_REPLY_MAX);
	reply[p[1].memref.size] = '\0';
	CHECK(sscanf(reply, "PQTOKEN %u %n", &len, &off) == 1 && len <= sizeof(claims));
	if (off == 0 || len > sizeof(claims))
		return;
	for (unsigned int i = 0; i < len; i++) {
		unsigned int b = 0;

		CHECK(sscanf(reply + off + 2 * i, "%2x", &b) == 1);
		claims[i] = (uint8_t)b;
	}
	claims_len = len;
	CHECK(sscanf(reply + off + 2 * len, " %u ", &sig_len) == 1 && sig_len == 3309);
	CHECK(len <= AEGIS_CLAIMS_MAX);
	CHECK(count_text(CHIP) + count_text(DEVHUK) == 1);
}

static void six_measurements(void)
{
	static const char *const labels[6] = { "FSBL", "PMUFW", "PL", "TFA", "TEE", "UBOOT" };

	memset(&pta, 0, sizeof(pta));
	pta.present = 1;
	pta.status = AEGIS_BOOT_HO_VALID;
	pta.count = 6;
	for (uint32_t i = 0; i < 6; i++) {
		strcpy(pta.meas[i].label, labels[i]);
		memset(pta.meas[i].value, 0xa0 + (int)i, sizeof(pta.meas[i].value));
		pta.meas[i].length = 0x10000u * (i + 1) + 7;
	}
}

static void check_six_measurements(void)
{
	CHECK(components() == 6);
	for (uint32_t i = 0; i < 6; i++) {
		CHECK(has_text(pta.meas[i].label));
		CHECK(has(pta.meas[i].value, 32));
	}
	CHECK(has_text("SHA3-384/256 of partition FSBL as stored (65543 bytes)"));
	CHECK(has_text("SHA3-384/256 of partition UBOOT as stored (393223 bytes)"));
	CHECK(!has_text("BOOTCHAIN") && !has_text("not measured"));
}

static void check_placeholder(const char *why)
{
	static const uint8_t zero[32];

	CHECK(has_text(DEVHUK));
	CHECK(!strcmp(key_hash(), PHASE_A_KEY));
	CHECK(components() == 1);
	CHECK(has_text("BOOTCHAIN") && has_text(why) && has(zero, 32));
	CHECK(!has_text("SHA3-384"));
}

/* an OP-TEE without the patch: the phase A answer, unchanged */
static void test_no_pta(void)
{
	memset(&pta, 0, sizeof(pta));
	boot_and_quote();
	check_placeholder("not measured (phase A: no boot hand-off)");
	CHECK(claims_len == 121 + 81 + 9 + 2 + 40);
}

static void test_no_handoff(void)
{
	memset(&pta, 0, sizeof(pta));
	pta.present = 1;
	pta.status = AEGIS_BOOT_HO_ABSENT;
	boot_and_quote();
	check_placeholder("not measured (phase A: no boot hand-off)");
}

static void test_rejected(void)
{
	six_measurements();
	pta.status = AEGIS_BOOT_HO_REJECTED;
	pta.count = 0;
	pta.flags = 0;
	boot_and_quote();
	check_placeholder("not measured (boot hand-off rejected)");
}

static void chip_boot(uint8_t seed_byte)
{
	six_measurements();
	pta.flags = AEGIS_HO_SEED_VALID | AEGIS_HO_KEY_BH_BLACK | AEGIS_HO_AES_CLEARED;
	pta.huk = AEGIS_BOOT_HUK_SEED;
	pta.chip_keys = 1;
	memset(pta.seed, seed_byte, sizeof(pta.seed));
	boot_and_quote();
}

static void test_chip_key(void)
{
	char first[65], other[65];

	chip_boot(0x11);
	CHECK(has_text(CHIP) && !has_text(DEVHUK));
	check_six_measurements();
	CHECK(strstr(stub_log, "profile " CHIP) != NULL);
	/* another key than phase A's, the same on the next boot, another one for another seed */
	strcpy(first, key_hash());
	CHECK(strcmp(first, PHASE_A_KEY));
	chip_boot(0x12);
	strcpy(other, key_hash());
	CHECK(strcmp(other, first) && strcmp(other, PHASE_A_KEY));
	chip_boot(0x11);
	CHECK(!strcmp(key_hash(), first));
}

/* measured, but the key is not the chip's: every combination short of "both flags and the HUK from the seed" */
static void test_measured_dev_key(void)
{
	static const struct {
		uint32_t flags, huk;
	} c[] = {
		{ 0, AEGIS_BOOT_HUK_DEFAULT },
		{ AEGIS_HO_SEED_VALID | AEGIS_HO_AES_CLEARED, AEGIS_BOOT_HUK_DEFAULT },
		{ AEGIS_HO_KEY_BH_BLACK, AEGIS_BOOT_HUK_DEFAULT },
		{ AEGIS_HO_SEED_VALID | AEGIS_HO_KEY_BH_BLACK, AEGIS_BOOT_HUK_DEFAULT },
		{ AEGIS_HO_SEED_VALID, AEGIS_BOOT_HUK_SEED },
		{ AEGIS_HO_SEED_VALID | AEGIS_HO_KEY_BH_BLACK, 2 },
	};

	for (size_t i = 0; i < sizeof(c) / sizeof(c[0]); i++) {
		six_measurements();
		pta.flags = c[i].flags;
		pta.huk = c[i].huk;
		boot_and_quote();
		CHECK(has_text(DEVHUK) && !has_text(CHIP));
		CHECK(!strcmp(key_hash(), PHASE_A_KEY));
		check_six_measurements();
	}
}

/* the chip profile does not outlive a later start that has no chip key */
static void test_profile_is_reset(void)
{
	test_chip_key();
	test_no_pta();
}

static void test_valid_without_measurements(void)
{
	six_measurements();
	pta.count = 0;
	boot_and_quote();
	check_placeholder("not measured (the boot hand-off has no measurement)");
}

static void test_bad_answers(void)
{
	six_measurements();
	pta.invoke = TEE_ERROR_BAD_STATE;
	boot_and_quote();
	check_placeholder("not measured (phase A: no boot hand-off)");

	six_measurements();
	pta.flags = 3;
	pta.huk = AEGIS_BOOT_HUK_SEED;
	pta.count = AEGIS_HANDOFF_MAX_MEAS + 1;
	boot_and_quote();
	check_placeholder("not measured (phase A: no boot hand-off)");

	six_measurements();
	pta.flags = 3;
	pta.huk = AEGIS_BOOT_HUK_SEED;
	pta.size_delta = 8;
	boot_and_quote();
	check_placeholder("not measured (phase A: no boot hand-off)");
}

/* the largest claims: 8 entries, 15-character labels (one arrives without its NUL), descriptions cut at 63 */
static void test_largest(void)
{
	memset(&pta, 0, sizeof(pta));
	pta.present = 1;
	pta.status = AEGIS_BOOT_HO_VALID;
	pta.count = AEGIS_HANDOFF_MAX_MEAS;
	for (uint32_t i = 0; i < pta.count; i++) {
		memcpy(pta.meas[i].label, "ABCDEFGHIJKLMNO", 16);
		pta.meas[i].label[0] = (char)('0' + i);
		memset(pta.meas[i].value, 0x30 + (int)i, sizeof(pta.meas[i].value));
		pta.meas[i].length = 0xffffffffu;
	}
	pta.meas[7].label[15] = 'P';
	boot_and_quote();
	CHECK(has_text(DEVHUK));
	CHECK(components() == 8);
	CHECK(has_text("7BCDEFGHIJKLMNO") && !has_text("7BCDEFGHIJKLMNOP"));
	CHECK(has_text("SHA3-384/256 of partition 0BCDEFGHIJKLMNO as stored (4294967295") && !has_text("bytes)"));
	CHECK(claims_len == 121 + 8 * 161);
	CHECK(claims_len <= AEGIS_CLAIMS_MAX);
}

int main(void)
{
	test_no_pta();
	test_no_handoff();
	test_rejected();
	test_chip_key();
	test_measured_dev_key();
	test_profile_is_reset();
	test_valid_without_measurements();
	test_bad_answers();
	test_largest();
	if (failures) {
		printf("%d check(s) FAILED\n", failures);
		return 1;
	}
	printf("Aegis TA on the PC: all checks passed\n");
	return 0;
}
