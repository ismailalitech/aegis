// SPDX-License-Identifier: Apache-2.0
/*
 * The ZynqMP endpoint on the PC, for tests/host/test_zynqmp_ta_port.py: the bridge as it runs on the board
 * (../bridge/aegis_tee_bridge.c, its main() and its socket code unchanged) and the TA (../ta/aegis_ta.c with the
 * Prover SDK's core), joined by this stand-in for both sides of OP-TEE: the client library the bridge calls
 * (stub/tee_client_api.h) and the internal API the TA calls (stub/tee_internal_api.h). A verifier that connects to
 * the bridge's port then talks to the TA's own code, line for line as on the board.
 *
 * What the stand-in gives the TA, chosen by the environment:
 *   AEGIS_TEST_HANDOFF     "chip" (the default): the aegis.boot PTA answers as on the board after phase B: a valid
 *                          hand-off, flags SEED_VALID, KEY_BH_BLACK and AES_CLEARED, the seven measurements of the
 *                          boot image, keys from the device seed. "none": an OP-TEE without the PTA (the development
 *                          key, the same for every seed).
 *   AEGIS_TEST_SEED        a text standing for the chip's seed: another text, another ML-DSA-65 key
 *   AEGIS_TEST_IMAGE       a text standing for the OP-TEE partition's content: another text, another TEE measurement
 *   AEGIS_TEST_CLOCK       a file holding seconds to add to the system time (the test moves the session clock)
 *   AEGIS_TEST_TIME_LEVEL  the system time's protection level (1000 by default; 100: a time Linux controls)
 *   AEGIS_TEST_STACK       if set, every entry into the TA runs on a stack of TA_STACK_SIZE bytes (the size the TA
 *                          asks OP-TEE for in user_ta_header_defines.h) above a page without access, and the request
 *                          "TEST-STACK" is answered here with "STACK <most bytes used> <size>"
 * The keys are derived from the seed text with SHA-256, not with OP-TEE's construction: which key the TA gets from
 * which hardware unique key is test_ta.c's subject. Random numbers are the PC's (getrandom).
 *
 * Shared memory: the TA gets the request and the room for the reply in two blocks of exactly the sizes the bridge
 * gave, so a read or a write beyond them is one beyond an allocation (the test builds with ASan).
 */
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/random.h>
#include <time.h>
#include <unistd.h>

#include <tee_client_api.h>
#include <tee_internal_api.h>
#include <pta_system.h>

#include "aegis_boot_pta.h"
#include "aegis_sha256.h"
#include "aegis_ta.h"
#include "user_ta_header_defines.h"

struct stub_session {
	int is_boot;
};

static struct stub_session sys_session = { 0 }, boot_session = { 1 };
char stub_log[2048];

static const char *env(const char *name, const char *otherwise)
{
	const char *v = getenv(name);

	return v && *v ? v : otherwise;
}

static int chip(void)
{
	return strcmp(env("AEGIS_TEST_HANDOFF", "chip"), "none") != 0;
}

/* ---- the internal API, as the TA sees OP-TEE ---- */

/* the TA's messages: the secure console's lines, here on standard output */
void stub_msg(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fputs("I/TA: ", stdout);
	vprintf(fmt, ap);
	fputc('\n', stdout);
	fflush(stdout);
	va_end(ap);
}

void TEE_GenerateRandom(void *buf, size_t n)
{
	uint8_t *p = buf;

	while (n) {
		ssize_t k = getrandom(p, n, 0);

		if (k <= 0)
			abort();
		p += k;
		n -= (size_t)k;
	}
}

void TEE_GetSystemTime(TEE_Time *t)
{
	const char *path = getenv("AEGIS_TEST_CLOCK");
	struct timespec ts;
	long add = 0;
	FILE *f;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	f = path ? fopen(path, "r") : NULL;
	if (f) {
		if (fscanf(f, "%ld", &add) != 1)
			add = 0;
		fclose(f);
	}
	t->seconds = (uint32_t)(ts.tv_sec + add);
	t->millis = (uint32_t)(ts.tv_nsec / 1000000);
}

TEE_Result TEE_GetPropertyAsU32(TEE_PropSetHandle set, const char *name, uint32_t *value)
{
	if (set != TEE_PROPSET_TEE_IMPLEMENTATION || strcmp(name, "gpd.tee.systemTime.protectionLevel"))
		return TEE_ERROR_ITEM_NOT_FOUND;
	*value = (uint32_t)strtoul(env("AEGIS_TEST_TIME_LEVEL", "1000"), NULL, 10);
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
	if (!memcmp(dest, &boot, sizeof(boot)) && chip()) {
		*sess = &boot_session;
		return TEE_SUCCESS;
	}
	return TEE_ERROR_ITEM_NOT_FOUND;
}

void TEE_CloseTASession(TEE_TASessionHandle sess)
{
	(void)sess;
}

/* SHA-256 of up to three texts, each with its terminator */
static void digest(uint8_t out[32], const char *a, const char *b, const void *c, size_t c_len)
{
	uint8_t buf[512];
	size_t n = 0;

	if (strlen(a) + strlen(b) + 2 + c_len > sizeof(buf))
		abort();
	memcpy(buf + n, a, strlen(a) + 1);
	n += strlen(a) + 1;
	memcpy(buf + n, b, strlen(b) + 1);
	n += strlen(b) + 1;
	if (c_len)
		memcpy(buf + n, c, c_len);
	aegis_sha256(buf, n + c_len, out);
}

/* the boot image's partitions as the FSBL lists them on the board (evidence/zynqmp/puf-phase-b.txt) */
static const struct {
	const char *label;
	uint32_t length;
} parts[] = {
	{ "PMUFW", 129888 }, { "FSBL", 148000 }, { "PL", 7797692 }, { "TFA", 40960 }, { "TFA.1", 13540 },
	{ "TEE", 576984 }, { "UBOOT", 1453680 },
};
#define N_PARTS (sizeof(parts) / sizeof(parts[0]))

TEE_Result TEE_InvokeTACommand(TEE_TASessionHandle sess, uint32_t timeout, uint32_t cmd, uint32_t pt,
			       TEE_Param p[TEE_NUM_PARAMS], uint32_t *origin)
{
	(void)timeout; (void)origin;
	if (!sess->is_boot) {
		static const TEE_UUID ta = AEGIS_TA_UUID;
		uint8_t data[sizeof(ta) + 64];

		if (cmd != PTA_SYSTEM_DERIVE_TA_UNIQUE_KEY ||
		    pt != TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT, 0, 0) ||
		    p[0].memref.size > 64 || p[1].memref.size != 32)
			return TEE_ERROR_BAD_PARAMETERS;
		memcpy(data, &ta, sizeof(ta));
		memcpy(data + sizeof(ta), p[0].memref.buffer, p[0].memref.size);
		digest(p[1].memref.buffer, "stand-in for huk_subkey_derive", chip() ? env("AEGIS_TEST_SEED", "seed") : "",
		       data, sizeof(ta) + p[0].memref.size);
		return TEE_SUCCESS;
	}
	if (cmd != PTA_AEGIS_BOOT_CMD_GET_INFO ||
	    pt != TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_VALUE_OUTPUT,
				  TEE_PARAM_TYPE_VALUE_OUTPUT, TEE_PARAM_TYPE_MEMREF_OUTPUT))
		return TEE_ERROR_BAD_PARAMETERS;
	if (p[3].memref.size < N_PARTS * sizeof(struct aegis_ho_meas))
		return TEE_ERROR_SHORT_BUFFER;
	for (size_t i = 0; i < N_PARTS; i++) {
		struct aegis_ho_meas *m = (struct aegis_ho_meas *)p[3].memref.buffer + i;

		memset(m, 0, sizeof(*m));
		strcpy(m->label, parts[i].label);
		digest(m->value, "stand-in for the partition", parts[i].label,
		       env("AEGIS_TEST_IMAGE", ""), strcmp(parts[i].label, "TEE") ? 0 : strlen(env("AEGIS_TEST_IMAGE", "")));
		m->length = parts[i].length;
	}
	p[0].value.a = AEGIS_BOOT_HO_VALID;
	p[0].value.b = AEGIS_HO_SEED_VALID | AEGIS_HO_KEY_BH_BLACK | AEGIS_HO_AES_CLEARED;
	p[1].value.a = 0xa35c7c53u; /* the boot header's key source: the black key */
	p[1].value.b = 3;
	p[2].value.a = N_PARTS;
	p[2].value.b = AEGIS_BOOT_HUK_SEED;
	p[3].memref.size = N_PARTS * sizeof(struct aegis_ho_meas);
	return TEE_SUCCESS;
}

/* ---- entering the TA, on its own stack if asked ---- */

struct entry {
	int invoke; /* 0: create the instance and open a session; 1: invoke a command */
	uint32_t cmd, pt;
	TEE_Param *p;
	TEE_Result res;
};

static uint8_t *ta_stack; /* TA_STACK_SIZE bytes above a page without access */
static size_t ta_stack_used;

static void *enter(void *arg)
{
	static int created;
	struct entry *e = arg;
	void *ctx = NULL;

	if (e->invoke) {
		e->res = TA_InvokeCommandEntryPoint(NULL, e->cmd, e->pt, e->p);
		return NULL;
	}
	e->res = created ? TEE_SUCCESS : TA_CreateEntryPoint(); /* one instance (TA_FLAG_SINGLE_INSTANCE) */
	if (e->res == TEE_SUCCESS) {
		created = 1;
		e->res = TA_OpenSessionEntryPoint(0, e->p, &ctx);
	}
	return NULL;
}

static void ta_enter(struct entry *e)
{
	pthread_attr_t attr;
	pthread_t t;
	size_t used = 0;

	if (!getenv("AEGIS_TEST_STACK")) {
		enter(e);
		return;
	}
	if (!ta_stack) {
		long page = sysconf(_SC_PAGESIZE);
		uint8_t *m = mmap(NULL, (size_t)page + TA_STACK_SIZE, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (m == MAP_FAILED || mprotect(m, (size_t)page, PROT_NONE))
			abort();
		ta_stack = m + page;
		memset(ta_stack, 0xa5, TA_STACK_SIZE);
	}
	if (pthread_attr_init(&attr) || pthread_attr_setstack(&attr, ta_stack, TA_STACK_SIZE) ||
	    pthread_create(&t, &attr, enter, e) || pthread_join(t, NULL))
		abort();
	pthread_attr_destroy(&attr);
	while (used < TA_STACK_SIZE && ta_stack[used] == 0xa5)
		used++;
	if (TA_STACK_SIZE - used > ta_stack_used)
		ta_stack_used = TA_STACK_SIZE - used;
}

/* ---- the client API, as the bridge sees OP-TEE ---- */

TEEC_Result TEEC_InitializeContext(const char *name, TEEC_Context *ctx)
{
	(void)name; (void)ctx;
	return TEEC_SUCCESS;
}

TEEC_Result TEEC_OpenSession(TEEC_Context *ctx, TEEC_Session *sess, const TEEC_UUID *dest, uint32_t method,
			     const void *data, TEEC_Operation *op, uint32_t *origin)
{
	static const TEEC_UUID ta = AEGIS_TA_UUID;
	TEE_Param p[TEE_NUM_PARAMS] = { };
	struct entry e = { .invoke = 0, .p = p };

	(void)ctx; (void)sess; (void)method; (void)data; (void)op; (void)origin;
	if (memcmp(dest, &ta, sizeof(ta)))
		return TEEC_ERROR_ITEM_NOT_FOUND;
	ta_enter(&e);
	return e.res;
}

TEEC_Result TEEC_InvokeCommand(TEEC_Session *sess, uint32_t cmd, TEEC_Operation *op, uint32_t *origin)
{
	const size_t in_len = op->params[0].tmpref.size, cap = op->params[1].tmpref.size;
	TEE_Param p[TEE_NUM_PARAMS] = { };
	struct entry e = { .invoke = 1, .cmd = cmd, .pt = op->paramTypes, .p = p };

	(void)sess; (void)origin;
	if (op->paramTypes != TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE, TEEC_NONE))
		return TEEC_ERROR_BAD_PARAMETERS; /* the only shape the bridge uses; the values are the internal API's */
	if (getenv("AEGIS_TEST_STACK") && in_len == 10 && !memcmp(op->params[0].tmpref.buffer, "TEST-STACK", 10)) {
		op->params[1].tmpref.size = (size_t)snprintf(op->params[1].tmpref.buffer, cap, "STACK %zu %u",
							     ta_stack_used, (unsigned int)TA_STACK_SIZE);
		return TEEC_SUCCESS;
	}
	p[0].memref.size = in_len;
	p[0].memref.buffer = malloc(in_len ? in_len : 1);
	p[1].memref.size = cap;
	p[1].memref.buffer = malloc(cap ? cap : 1);
	if (!p[0].memref.buffer || !p[1].memref.buffer)
		abort();
	memcpy(p[0].memref.buffer, op->params[0].tmpref.buffer, in_len);
	ta_enter(&e);
	if (e.res == TEE_SUCCESS) {
		if (p[1].memref.size > cap)
			abort(); /* a reply longer than the room the TA was given */
		memcpy(op->params[1].tmpref.buffer, p[1].memref.buffer, p[1].memref.size);
	}
	if (e.res == TEE_SUCCESS || e.res == TEE_ERROR_SHORT_BUFFER)
		op->params[1].tmpref.size = p[1].memref.size;
	free(p[0].memref.buffer);
	free(p[1].memref.buffer);
	return e.res;
}
