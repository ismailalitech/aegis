/* SPDX-License-Identifier: Apache-2.0
 *
 * The Prover SDK's standard evidence (the option AEGIS_EAT_COSE, docs/evidence-format.md) at its boundaries. Built
 * and run by tests/host/test_sdk_eat.py, with and without ASan/UBSan: this program makes the objects and checks what
 * C can see (results, lengths, bytes around every buffer, what a refusal leaves behind); the test reads every object
 * it prints with the verifier's decoder and with a COSE library, and compares the transcript hash.
 *
 * Every length that changes an encoding is crossed: a platform token of 1, 21, 22, 253, 254 and 255 bytes and one
 * that fills the room it is given (the byte string around it has a head of 1, 2 or 3 bytes, and so has the payload),
 * labels and versions of 23, 24 and 64 bytes, 1 and 16 measurements. Refused, with nothing signed and no quote kept:
 * a token one byte longer than its room, of no length, a platform that fails, a label of 65 bytes or none, a version
 * of 65 bytes, no measurement or 17, a work buffer one byte short. A caller's buffer that holds the object exactly
 * is filled, one byte less is refused and not written. The challenge is read once.
 *
 *   eat_check
 * prints  KEY <public key>
 *         EAT <case> <challenge> <COSE_Sign1> <T1 the core kept>      one line per object, all in hex
 *         eat check: <n> checks, <m> failed
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void inputs_taken(void);
#define AEGIS_TEST_INPUTS_TAKEN() inputs_taken()
#if !defined(AEGIS_EAT_COSE)
#define AEGIS_EAT_COSE 1
#endif
#include "aegis_proto.c"

static int checks, failed;
#define CHECK(c) do { checks++; if (!(c)) { failed++; fprintf(stderr, "FAILED, line %d: %s\n", __LINE__, #c); } } while (0)

#define GUARD 64u
#define FILL  0xC3
#define FILL_ROOM ((size_t)-1)

static uint8_t *guarded(size_t n)
{
	uint8_t *p = malloc(n + GUARD);

	if (!p) abort();
	memset(p, 0xEE, n);
	memset(p + n, FILL, GUARD);
	return p;
}

static int guard_ok(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < GUARD; i++) if (p[n + i] != FILL) return 0;
	return 1;
}

static int all(const uint8_t *p, size_t n, uint8_t v)
{
	for (size_t i = 0; i < n; i++) if (p[i] != v) return 0;
	return 1;
}

/* ---- the platform ---- */
static struct {
	size_t token_len;  /* the token the platform writes; FILL_ROOM: as much as it is given room for */
	int token_mode;    /* 0 as written, 1 reports one byte more than its room, 2 reports no length, 3 fails */
	size_t room;       /* the room the core gave the last time */
	struct aegis_measurement m[20];
	size_t count;
	int no_list, meas_fail, signs;
} T;
static uint8_t rng_state;
static uint8_t id_sk[AEGIS_SK_LEN], id_pk[AEGIS_PK_LEN];
static uint8_t *taken; /* the caller's challenge, overwritten once the core has taken it */

static void inputs_taken(void)
{
	if (taken != NULL) memset(taken, 0xA5, 32);
}

static int t_random(void *u, uint8_t *out, size_t n)
{
	(void)u;
	for (size_t i = 0; i < n; i++) out[i] = (uint8_t)(rng_state++ * 37u + 11u);
	return 0;
}

static int t_clock(void *u, uint64_t *now)
{
	(void)u;
	*now = 1000;
	return 0;
}

static int t_measurements(void *u, const struct aegis_measurement **list, size_t *count)
{
	(void)u;
	if (T.meas_fail) return -1;
	*list = T.no_list ? NULL : T.m;
	*count = T.count;
	return 0;
}

static uint8_t token_byte(size_t i)
{
	return (uint8_t)(i * 7u + 3u);
}

static int t_evidence(void *u, const uint8_t ch[32], uint8_t *out, size_t cap, size_t *len)
{
	size_t n = T.token_len == FILL_ROOM ? cap : T.token_len;

	(void)u; (void)ch;
	T.room = cap;
	if (T.token_mode == 3 || n > cap) return -1;
	for (size_t i = 0; i < n; i++) out[i] = token_byte(i);
	*len = T.token_mode == 1 ? cap + 1 : T.token_mode == 2 ? 0 : n;
	return 0;
}

static int t_public_key(void *u, uint8_t pk[AEGIS_PK_LEN])
{
	(void)u;
	memcpy(pk, id_pk, AEGIS_PK_LEN);
	return 0;
}

/* a platform that holds the key: pure ML-DSA-65 over the message, empty context (aegis_sdk.h) */
static int t_sign(void *u, const uint8_t *msg, size_t n, uint8_t sig[AEGIS_SIG_LEN])
{
	const uint8_t pre[2] = {0, 0};
	uint8_t rnd[32];

	(void)u;
	T.signs++;
	t_random(NULL, rnd, sizeof(rnd));
	return aegis_mldsa_signature_internal(sig, msg, n, pre, sizeof(pre), rnd, id_sk, 0);
}

static const uint8_t SEED[32] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
				 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32};
static const uint8_t ROOT[32] = {9, 9, 9, 1};
static uint8_t gw_pk[AEGIS_PK_LEN];
static struct aegis_platform plat;
static struct aegis_prover P;
static uint8_t *work;
static size_t work_len;

/* token: the platform gives its own token; platkey: it also holds the identity key */
static void start(int token, int platkey, size_t wl, const char *version)
{
	struct aegis_config cfg = {.platform = &plat, .verifier_pk = gw_pk, .exchange_root = ROOT};

	memset(&plat, 0, sizeof(plat));
	plat.random = t_random;
	plat.clock = t_clock;
	plat.clock_hz = 1;
	if (token) {
		plat.evidence = t_evidence;
	} else {
		plat.measurements = t_measurements;
		plat.profile = "aegis-rw612-tfm-v1";
		plat.version = version;
	}
	if (platkey) {
		plat.identity_public_key = t_public_key;
		plat.identity_sign = t_sign;
	} else {
		cfg.identity_seed = SEED;
	}
	free(work);
	work = guarded(wl);
	work_len = wl;
	cfg.work = work;
	cfg.work_len = wl;
	if (AEGIS_PROVER_INIT(&P, &cfg) != AEGIS_OK) {
		fprintf(stderr, "init failed\n");
		exit(2);
	}
}

static void hex(const uint8_t *p, size_t n)
{
	for (size_t i = 0; i < n; i++) printf("%02x", p[i]);
}

static uint8_t challenge_no;

/* One object through the binary operation into a buffer of exactly cap bytes (0: plenty). Returns the result; an
 * object is printed. *len_out: the object's length. */
static int eat(const char *name, size_t cap, size_t *len_out)
{
	uint8_t ch[32], sent[32], *out;
	size_t len = 0x5a5a, room = cap ? cap : 70000;
	int rc;

	for (size_t i = 0; i < 32; i++) sent[i] = ch[i] = (uint8_t)(challenge_no + i);
	challenge_no += 41;
	out = guarded(room);
	taken = ch;
	rc = aegis_prover_quote_eat(&P, ch, out, room, &len);
	taken = NULL;
	CHECK(guard_ok(out, room));
	CHECK(guard_ok(work, work_len));
	if (rc == AEGIS_OK) {
		CHECK(len >= AEGIS_EAT_LEN(0) && len <= room);
		CHECK(P.quote_ready == 1 && !memcmp(P.quote_ch, sent, 32));
		CHECK(all(out + len, room - len, 0xEE));
		printf("EAT %s ", name);
		hex(sent, 32);
		printf(" ");
		hex(out, len);
		printf(" ");
		hex(P.quote_t1, 32);
		printf("\n");
	} else {
		/* nothing written, and no quote to continue: not this one, not the one before */
		CHECK(len == 0x5a5a && all(out, room, 0xEE));
		CHECK(P.quote_ready == 0);
	}
	if (len_out != NULL) *len_out = len;
	free(out);
	return rc;
}

static void label_of(char *buf, size_t n, char c)
{
	memset(buf, c, n);
	buf[n] = '\0';
}

static void measurements(void)
{
	static char l23[24], l24[25], l64[65], l65[66], v23[24], v24[25], v64[65], v65[66];
	static char names[16][4];
	size_t len;

	label_of(l23, 23, 'a'); label_of(l24, 24, 'b'); label_of(l64, 64, 'c'); label_of(l65, 65, 'd');
	label_of(v23, 23, '1'); label_of(v24, 24, '2'); label_of(v64, 64, '3'); label_of(v65, 65, '4');
	memset(&T, 0, sizeof(T));
	for (size_t i = 0; i < 20; i++) {
		memset(T.m[i].value, (int)(0x10 + i), 32);
		memset(T.m[i].desc, 'x', sizeof(T.m[i].desc)); /* no terminator: the description is not part of an EAT */
	}
	for (size_t i = 0; i < 16; i++) {
		snprintf(names[i], sizeof(names[i]), "C%02u", (unsigned)i);
	}

	start(0, 0, AEGIS_WORK_LEN(1440), "0.1.0");
	T.m[0].label = "APP";
	T.count = 1;
	CHECK(eat("one-measurement", 0, &len) == AEGIS_OK);
	/* a buffer of exactly the object's length takes it; one byte less does not, and nothing is written */
	CHECK(eat("exact-buffer", len, NULL) == AEGIS_OK);
	CHECK(eat("short-buffer", len - 1, NULL) == AEGIS_ERR_EVIDENCE);
	CHECK(eat("no-buffer", AEGIS_EAT_LEN(0) - 1, NULL) == AEGIS_ERR_BUFFER);
	T.m[0].label = "SPE"; T.m[1].label = "NSPE";
	T.count = 2;
	CHECK(eat("two-measurements", 0, NULL) == AEGIS_OK);
	T.m[0].label = l23; T.m[1].label = l24; T.m[2].label = l64;
	T.count = 3;
	CHECK(eat("labels-23-24-64", 0, NULL) == AEGIS_OK);
	for (size_t i = 0; i < 16; i++) T.m[i].label = names[i];
	T.count = 16;
	CHECK(eat("sixteen", 0, NULL) == AEGIS_OK);
	T.count = 17;
	T.m[16].label = "X";
	CHECK(eat("seventeen", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.count = 0;
	CHECK(eat("none", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.count = 1;
	T.m[0].label = l65;
	CHECK(eat("label-65", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.m[0].label = "";
	CHECK(eat("label-empty", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.m[0].label = NULL;
	CHECK(eat("label-null", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.m[0].label = "APP";
	T.no_list = 1;
	CHECK(eat("no-list", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.no_list = 0;
	T.meas_fail = 1;
	CHECK(eat("platform-fails", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.meas_fail = 0;
	/* a refusal ends the quote before it: there is nothing to continue until the next one is signed */
	CHECK(eat("again", 0, NULL) == AEGIS_OK && P.quote_ready == 1);

	start(0, 0, AEGIS_WORK_LEN(1440), "");
	CHECK(eat("version-empty", 0, NULL) == AEGIS_OK);
	start(0, 0, AEGIS_WORK_LEN(1440), v23);
	CHECK(eat("version-23", 0, NULL) == AEGIS_OK);
	start(0, 0, AEGIS_WORK_LEN(1440), v24);
	CHECK(eat("version-24", 0, NULL) == AEGIS_OK);
	start(0, 0, AEGIS_WORK_LEN(1440), v64);
	CHECK(eat("version-64", 0, NULL) == AEGIS_OK);
	start(0, 0, AEGIS_WORK_LEN(1440), v65);
	CHECK(eat("version-65", 0, NULL) == AEGIS_ERR_EVIDENCE);

	/* the work buffer: the smallest that serves, and one byte less */
	start(0, 0, AEGIS_EAT_WORK_MIN, "0.1.0");
	CHECK(eat("work-min", 0, NULL) == AEGIS_OK);
	start(0, 0, AEGIS_EAT_WORK_MIN - 1, "0.1.0");
	CHECK(eat("work-short", 0, NULL) == AEGIS_ERR_EVIDENCE);
	/* claims that do not fit the work buffer: sixteen measurements with the longest labels */
	start(0, 0, AEGIS_EAT_WORK_MIN, v64);
	for (size_t i = 0; i < 16; i++) T.m[i].label = l64;
	T.count = 16;
	CHECK(eat("work-full", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.count = 1;
	CHECK(eat("work-full-then-fits", 0, NULL) == AEGIS_OK);

	/* the key held by the platform: the same object, signed by its function */
	start(0, 1, AEGIS_WORK_LEN(1440), "0.1.0");
	T.m[0].label = "APP";
	T.signs = 0;
	CHECK(eat("platform-key", 0, NULL) == AEGIS_OK && T.signs == 1);
}

static void tokens(void)
{
	static const size_t lens[] = {1, 21, 22, 23, 253, 254, 255, 256, 400, 1440};
	char name[32];
	size_t len, full;

	memset(&T, 0, sizeof(T));
	start(1, 0, AEGIS_WORK_LEN(1440), NULL);
	for (size_t i = 0; i < sizeof(lens) / sizeof(lens[0]); i++) {
		T.token_len = lens[i];
		snprintf(name, sizeof(name), "token-%u", (unsigned)lens[i]);
		CHECK(eat(name, 0, NULL) == AEGIS_OK);
	}
	/* the room is the work buffer's: a token that fills it is signed, one byte more is not, nor is no length */
	T.token_len = FILL_ROOM;
	CHECK(eat("token-fills-work", 0, &full) == AEGIS_OK);
	CHECK(T.room == work_len - 230u);
	T.token_mode = 1;
	CHECK(eat("token-one-more", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.token_mode = 2;
	CHECK(eat("token-no-length", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.token_mode = 3;
	CHECK(eat("token-fails", 0, NULL) == AEGIS_ERR_EVIDENCE);
	T.token_mode = 0;
	/* the room is the caller's buffer: the token that fills it makes an object of exactly that buffer */
	for (size_t cap = full - 300; cap <= full - 298; cap++) {
		snprintf(name, sizeof(name), "token-fills-buffer-%u", (unsigned)cap);
		CHECK(eat(name, cap, &len) == AEGIS_OK && len == cap);
	}
	/* around the payload's head of three bytes: 255 and 256 bytes of claims */
	for (size_t cap = AEGIS_EAT_LEN(0) + 250; cap <= AEGIS_EAT_LEN(0) + 260; cap++) {
		snprintf(name, sizeof(name), "token-buffer-%u", (unsigned)cap);
		CHECK(eat(name, cap, &len) == AEGIS_OK && len <= cap && len + 2 >= cap);
	}
	T.token_len = 400;
	CHECK(eat("token-too-long-for-buffer", AEGIS_EAT_LEN(0) + 300, NULL) == AEGIS_ERR_EVIDENCE);
	start(1, 1, AEGIS_EAT_WORK_MIN, NULL);
	T.token_len = FILL_ROOM;
	CHECK(eat("token-platform-key-work-min", 0, NULL) == AEGIS_OK);
}

/* the line transport: the same object in hex, in a reply buffer of exactly cap bytes */
static void line(const char *name, size_t cap, int want_ok)
{
	char req[80] = "PQEAT ", *rep = (char *)guarded(cap);
	uint8_t ch[32];
	int n;

	for (size_t i = 0; i < 32; i++) {
		ch[i] = (uint8_t)(challenge_no + i);
		snprintf(req + 6 + 2 * i, 3, "%02x", ch[i]);
	}
	challenge_no += 41;
	n = aegis_prover_handle_line(&P, req, rep, cap);
	CHECK(guard_ok((const uint8_t *)rep, cap));
	CHECK(n > 0 && (size_t)n < cap && rep[n] == '\0' && strlen(rep) == (size_t)n);
	if (want_ok) {
		unsigned len = 0;
		char *sp;

		CHECK(!strncmp(rep, "PQEAT ", 6) && sscanf(rep + 6, "%u", &len) == 1 && n > 4 && !strcmp(rep + n - 4, " END"));
		sp = strchr(rep + 6, ' ');
		CHECK(sp != NULL && (size_t)(rep + n - 4 - (sp + 1)) == 2u * len);
		CHECK(P.quote_ready == 1 && !memcmp(P.quote_ch, ch, 32));
		if (sp != NULL) {
			rep[n - 4] = '\0';
			printf("EAT %s ", name);
			hex(ch, 32);
			printf(" %s ", sp + 1);
			hex(P.quote_t1, 32);
			printf("\n");
		}
	} else {
		CHECK(!strcmp(rep, "ERR evidence") && P.quote_ready == 0);
	}
	free(rep);
}

static void lines(void)
{
	char bad[] = "PQEAT 00", two[] = "PQEAT 00 11";

	memset(&T, 0, sizeof(T));
	T.m[0].label = "APP";
	memset(T.m[0].value, 0x77, 32);
	T.count = 1;
	start(0, 0, AEGIS_WORK_LEN(1440), "0.1.0");
	line("line-measurement", AEGIS_REPLY_MAX, 1);
	{
		char rep[AEGIS_REPLY_MAX];

		/* a malformed request is refused before it touches the quote */
		CHECK(aegis_prover_handle_line(&P, bad, rep, sizeof(rep)) > 0 && !strcmp(rep, "ERR bad-request"));
		CHECK(aegis_prover_handle_line(&P, two, rep, sizeof(rep)) > 0 && !strcmp(rep, "ERR unknown"));
		CHECK(P.quote_ready == 1);
	}
	start(1, 0, AEGIS_WORK_LEN(1440), NULL);
	T.token_len = 300;
	line("line-token", AEGIS_REPLY_MAX, 1);
	/* the reply sets the room: the token that fills it, in the smallest reply buffer the transport takes and one
	 * byte and two bytes more (a hex digit pair needs two) */
	T.token_len = FILL_ROOM;
	for (size_t cap = AEGIS_REPLY_LEN(AEGIS_KEM_EK_LEN); cap < AEGIS_REPLY_LEN(AEGIS_KEM_EK_LEN) + 3; cap++) {
		char name[32];

		snprintf(name, sizeof(name), "line-token-fills-%u", (unsigned)cap);
		line(name, cap, 1);
	}
	T.token_mode = 1;
	line("line-token-one-more", AEGIS_REPLY_MAX, 0);
}

int main(void)
{
	uint8_t pk[AEGIS_PK_LEN];

	if (aegis_mldsa_keypair_internal(id_pk, id_sk, SEED) != 0) return 2;
	memcpy(pk, id_pk, sizeof(pk));
	memset(gw_pk, 0x42, sizeof(gw_pk));
	printf("KEY ");
	hex(pk, sizeof(pk));
	printf("\n");
	measurements();
	tokens();
	lines();
	free(work);
	printf("eat check: %d checks, %d failed\n", checks, failed);
	return failed ? 1 : 0;
}
