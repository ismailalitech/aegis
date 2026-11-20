// SPDX-License-Identifier: Apache-2.0
/*
 * PC test of the Aegis TA (../ta/aegis_ta.c with the real protocol code) on a stand-in for OP-TEE (stub/): which
 * profile and which measurements a quote carries for each answer of the aegis.boot PTA, that the largest hand-off
 * fits the claims buffer, and which ML-DSA-65 key the TA gets. The stand-in derives the TA's keys as OP-TEE does:
 * without a seed of the chip's, OP-TEE 4.7.0's own construction with the development HUK, which must give the key
 * the board had in phase A (evidence/zynqmp/optee-phase-a.txt); with one, the patch's (aegis_handoff_kdf.c).
 * And the session clock: the TA starts a session only on a system time the normal world cannot change. And the
 * transcript (docs/architecture.md, "One transcript"): the TA signs its ML-KEM key over the quote it continues.
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
#include "mldsa_native.h"

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

/* OP-TEE's system time and its protection level (1000: the physical counter; 100: a time the normal world controls) */
static uint32_t stub_seconds = 42, stub_time_level = 1000;
static int stub_no_time_level;

void TEE_GetSystemTime(TEE_Time *t)
{
	t->seconds = stub_seconds;
	t->millis = 0;
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle set, const char *name, uint32_t *value)
{
	if (set != TEE_PROPSET_TEE_IMPLEMENTATION || strcmp(name, "gpd.tee.systemTime.protectionLevel") ||
	    stub_no_time_level)
		return TEE_ERROR_ITEM_NOT_FOUND;
	*value = stub_time_level;
	return TEE_SUCCESS;
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

/* one request line to the TA; the reply as text */
static const char *line(const char *req)
{
	static char in[256], reply[AEGIS_TA_REPLY_MAX + 1];
	TEE_Param p[TEE_NUM_PARAMS];

	memset(p, 0, sizeof(p));
	snprintf(in, sizeof(in), "%s", req);
	p[0].memref.buffer = in;
	p[0].memref.size = strlen(in);
	p[1].memref.buffer = reply;
	p[1].memref.size = AEGIS_TA_REPLY_MAX;
	CHECK(TA_InvokeCommandEntryPoint(NULL, AEGIS_TA_CMD_LINE,
					 TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, 0, 0),
					 p) == TEE_SUCCESS);
	reply[p[1].memref.size <= AEGIS_TA_REPLY_MAX ? p[1].memref.size : 0] = '\0';
	return reply;
}

/* The session clock. With a trusted system time a PQKEMFIN reaches the credential checks (here: a malformed one);
 * with a time the normal world controls, or an OP-TEE that does not say, the TA has no clock and refuses before
 * them, so no session can start. (The lifetime itself is tested with the gateway's code in
 * tests/host/test_rw612_proto.py and in tests/fuzz: the protocol code is the same file.) */
static void test_session_clock(void)
{
	static const char init[] = "PQKEMINIT 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";

	six_measurements();
	boot_and_quote();
	CHECK(strstr(stub_log, "session clock trusted (level 1000)") != NULL);
	CHECK(!strcmp(line("PQHB 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"), "ERR pq no-session"));
	CHECK(!strncmp(line(init), "PQKEMEK ", 8));
	CHECK(!strcmp(line("PQKEMFIN 00 00"), "ERR bad-request"));

	stub_time_level = 100;
	boot_and_quote();
	CHECK(strstr(stub_log, "session clock NOT trusted") != NULL);
	CHECK(!strncmp(line(init), "PQKEMEK ", 8));
	CHECK(!strcmp(line("PQKEMFIN 00 00"), "ERR clock"));
	stub_time_level = 1000;

	stub_no_time_level = 1;
	boot_and_quote();
	CHECK(!strncmp(line(init), "PQKEMEK ", 8));
	CHECK(!strcmp(line("PQKEMFIN 00 00"), "ERR clock"));
	stub_no_time_level = 0;

	boot_and_quote();
	CHECK(!strncmp(line(init), "PQKEMEK ", 8));
	CHECK(!strcmp(line("PQKEMFIN 00 00"), "ERR bad-request"));
}

/* ---- one transcript (docs/architecture.md, common/transcript.py), with a SHA3-256 of this file's own ---- */

static void keccak_f(uint64_t a[25])
{
	static const uint64_t rc[24] = {
		0x0000000000000001ull, 0x0000000000008082ull, 0x800000000000808aull, 0x8000000080008000ull,
		0x000000000000808bull, 0x0000000080000001ull, 0x8000000080008081ull, 0x8000000000008009ull,
		0x000000000000008aull, 0x0000000000000088ull, 0x0000000080008009ull, 0x000000008000000aull,
		0x000000008000808bull, 0x800000000000008bull, 0x8000000000008089ull, 0x8000000000008003ull,
		0x8000000000008002ull, 0x8000000000000080ull, 0x000000000000800aull, 0x800000008000000aull,
		0x8000000080008081ull, 0x8000000000008080ull, 0x0000000080000001ull, 0x8000000080008008ull };
	static const int rot[25] = { 0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2,
				     61, 56, 14 };
	uint64_t b[25], c[5], d;

	for (int r = 0; r < 24; r++) {
		for (int x = 0; x < 5; x++)
			c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
		for (int x = 0; x < 5; x++) {
			d = c[(x + 4) % 5] ^ (c[(x + 1) % 5] << 1 | c[(x + 1) % 5] >> 63);
			for (int y = 0; y < 25; y += 5)
				a[x + y] ^= d;
		}
		for (int x = 0; x < 5; x++)
			for (int y = 0; y < 5; y++) {
				uint64_t v = a[x + 5 * y];
				int n = rot[x + 5 * y];

				b[y + 5 * ((2 * x + 3 * y) % 5)] = n ? (v << n | v >> (64 - n)) : v;
			}
		for (int i = 0; i < 25; i++)
			a[i] = b[i] ^ (~b[(i % 5 + 1) % 5 + i / 5 * 5] & b[(i % 5 + 2) % 5 + i / 5 * 5]);
		a[0] ^= rc[r];
	}
}

/* SHA3-256 of up to three parts */
static void sha3(uint8_t out[32], const void *p1, size_t n1, const void *p2, size_t n2, const void *p3, size_t n3)
{
	const void *p[3] = { p1, p2, p3 };
	size_t n[3] = { n1, n2, n3 }, pos = 0;
	uint64_t a[25] = { 0 };

	for (int k = 0; k < 3; k++)
		for (size_t i = 0; i < n[k]; i++) {
			a[pos / 8] ^= (uint64_t)((const uint8_t *)p[k])[i] << (8 * (pos % 8));
			if (++pos == 136) {
				keccak_f(a);
				pos = 0;
			}
		}
	a[pos / 8] ^= (uint64_t)0x06 << (8 * (pos % 8));
	a[135 / 8] ^= (uint64_t)0x80 << (8 * (135 % 8));
	keccak_f(a);
	for (int i = 0; i < 32; i++)
		out[i] = (uint8_t)(a[i / 8] >> (8 * (i % 8)));
}

/* the key and signature of a PQKEMEK reply; 0 if it is not one */
static int kem_reply(const char *r, uint8_t ek[1184], uint8_t sig[3309])
{
	unsigned int el = 0, sl = 0, b;
	int off = 0, off2 = 0;

	if (sscanf(r, "PQKEMEK %u %n", &el, &off) != 1 || el != 1184)
		return 0;
	for (unsigned int i = 0; i < el; i++) {
		if (sscanf(r + off + 2 * i, "%2x", &b) != 1)
			return 0;
		ek[i] = (uint8_t)b;
	}
	if (sscanf(r + off + 2 * el, " %u %n", &sl, &off2) != 1 || sl != 3309)
		return 0;
	off += 2 * el + off2;
	for (unsigned int i = 0; i < sl; i++) {
		if (sscanf(r + off + 2 * i, "%2x", &b) != 1)
			return 0;
		sig[i] = (uint8_t)b;
	}
	return !strcmp(r + off + 2 * sl, " END");
}

/* ML-DSA-65 by the TA's key over label || 0x00 || m (the framing of fleet.py and aegis_proto.c) */
static int signed_by_ta(const uint8_t sig[3309], const char *label, const uint8_t *m1, size_t n1, const uint8_t *m2,
			size_t n2)
{
	static uint8_t msg[64 + 32 + 1184];
	static const uint8_t pre[2] = { 0, 0 };
	size_t l = strlen(label) + 1;

	memcpy(msg, label, l);
	memcpy(msg + l, m1, n1);
	if (n2)
		memcpy(msg + l + n1, m2, n2);
	return aegis_mldsa_verify_internal(sig, msg, l + n1 + n2, pre, sizeof(pre), aegis_proto_pk(), 0) == 0;
}

/* The TA's side of the transcript, against this file's reading of the layout: a PQKEMINIT with the challenge of the
 * last quote is signed over T2 (and not the first version's way); a quote is continued once; a later PQCHAL, or one
 * whose answer was never given, takes the place of the older quote. */
static void test_transcript(void)
{
	static const char init[] = "PQKEMINIT 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
	static uint8_t ek[1184], sig[3309];
	uint8_t ch[32], h_tok[32], t1[32], t2[32];

	for (int i = 0; i < 32; i++)
		ch[i] = (uint8_t)i;
	six_measurements();
	boot_and_quote();                       /* challenge 00 01 .. 1f; claims[] holds the signed token */
	CHECK(claims_len > 0);
	sha3(h_tok, claims, claims_len, NULL, 0, NULL, 0);
	sha3(t1, "aegis-transcript-v2/quote", 25, ch, 32, h_tok, 32);
	CHECK(kem_reply(line(init), ek, sig));
	sha3(t2, "aegis-transcript-v2/kem-init", 28, t1, 32, ek, 1184);
	CHECK(signed_by_ta(sig, "aegis-kem-init-v2", t2, 32, NULL, 0));
	CHECK(!signed_by_ta(sig, "aegis-kem-init-v1", ch, 32, ek, 1184));

	/* the quote is used up: the same challenge again is the first version's exchange */
	CHECK(kem_reply(line(init), ek, sig));
	CHECK(signed_by_ta(sig, "aegis-kem-init-v1", ch, 32, ek, 1184));
	sha3(t2, "aegis-transcript-v2/kem-init", 28, t1, 32, ek, 1184);
	CHECK(!signed_by_ta(sig, "aegis-kem-init-v2", t2, 32, NULL, 0));

	/* another verifier's quote in between: the earlier one is not continued */
	boot_and_quote();
	CHECK(!strncmp(line("PQCHAL ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), "PQTOKEN ", 8));
	CHECK(kem_reply(line(init), ek, sig));
	CHECK(signed_by_ta(sig, "aegis-kem-init-v1", ch, 32, ek, 1184));

	/* a malformed PQCHAL returns before it touches the quote: that one is still continued */
	boot_and_quote();
	CHECK(!strcmp(line("PQCHAL 00"), "ERR bad-request"));
	CHECK(kem_reply(line(init), ek, sig));
	sha3(t2, "aegis-transcript-v2/kem-init", 28, t1, 32, ek, 1184);
	CHECK(signed_by_ta(sig, "aegis-kem-init-v2", t2, 32, NULL, 0));
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
	test_session_clock();
	test_transcript();
	if (failures) {
		printf("%d check(s) FAILED\n", failures);
		return 1;
	}
	printf("Aegis TA on the PC: all checks passed\n");
	return 0;
}
