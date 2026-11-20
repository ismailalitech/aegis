/* SPDX-License-Identifier: Apache-2.0
 *
 * The contracts of the Prover SDK's core that a careless change would break without any protocol test noticing,
 * each checked at its exact boundary, with bytes of a known pattern around every buffer (so a write past one is seen
 * without a sanitizer too). Built and run by tests/host/test_sdk_core_contract.py, with and without ASan/UBSan.
 *
 *   1. Inputs are read once. The core calls AEGIS_TEST_INPUTS_TAKEN() where an operation has taken its inputs; here
 *      that overwrites the caller's challenge, nonce, ciphertext and credential. The quote, the transcript, the
 *      confirmation tag, the session and the credential's hash must be those of the bytes as they were passed: what
 *      is accepted is what was checked, whatever happens to the caller's memory meanwhile.
 *   2. A credential's body must fit the work buffer: the longest that fits is accepted, one byte more is refused.
 *   3. The platform's evidence: a length of exactly the room it was given is signed; one byte more, or none, is
 *      refused and nothing is signed or kept; also through the line transport, where the reply sets the room.
 *   4. A heartbeat's status buffer: with room for exactly the text and its ";ttl=" it is answered; one byte short
 *      it is refused, nothing is written and the counter does not move.
 *   5. The random generator: 32 equal bytes, or the bytes of the draw before, make no exchange key.
 *   6. Start: a seed or an exchange root of zeros is refused.
 *   7. Measurements: one without a label refuses the quote; a description without a terminator is not read beyond.
 *   8. The PC port's measurements: a file larger than its buffer, or one that cannot be read, refuses the quote.
 *
 *   core_contract_check <an empty directory for its files>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static void inputs_taken(void);
#define AEGIS_TEST_INPUTS_TAKEN() inputs_taken()
#include "aegis_proto.c"
#include "aegis_port_host.h"

static int checks, failed;
#define CHECK(c) do { checks++; if (!(c)) { failed++; fprintf(stderr, "FAILED, line %d: %s\n", __LINE__, #c); } } while (0)

#define GUARD 64u
#define FILL  0xC3

/* n bytes with GUARD bytes of FILL behind them */
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

/* ---- 1: the caller's buffers, overwritten when the core has taken them ---- */
static struct { uint8_t *p; size_t n; } victim[2];
static int victims, taken;

static void inputs_taken(void)
{
	taken++;
	for (int i = 0; i < victims; i++) memset(victim[i].p, 0x5a, victim[i].n);
}

/* ---- the platform: the PC port, with a generator and a clock the test sets ---- */
static uint64_t rng_state = 0x9e3779b97f4a7c15ull;
static uint8_t rng_out[32];       /* the last output */
static int rng_force;             /* the next draw gives rng_forced instead */
static uint8_t rng_forced[32];
static uint64_t now_s = 1000;

static int t_random(uint8_t *out, size_t n)
{
	if (rng_force) {
		rng_force = 0;
		memcpy(out, rng_forced, n < 32 ? n : 32);
	} else {
		for (size_t i = 0; i < n; i++) {
			rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
			out[i] = (uint8_t)(rng_state >> 24);
		}
	}
	memcpy(rng_out, out, n < 32 ? n : 32);
	return 0;
}

static int t_clock(uint64_t *now)
{
	*now = now_s;
	return 0;
}

static struct aegis_measurement *meas;
static size_t meas_n;

static int t_measurements(void *user, const struct aegis_measurement **list, size_t *count)
{
	(void)user;
	*list = meas;
	*count = meas_n;
	return 0;
}

static int ev_kind;      /* 0 an honest token of 120 bytes, 1 one byte more than the room, 2 exactly the room, 3 none */
static size_t ev_cap;    /* the room the core gave last */

static int t_evidence(void *user, const uint8_t challenge[32], uint8_t *out, size_t cap, size_t *len)
{
	size_t n = ev_kind == 2 ? cap : 120;

	(void)user;
	ev_cap = cap;
	memset(out, 0xa7, n);
	memcpy(out, challenge, 32);
	*len = ev_kind == 1 ? cap + 1 : ev_kind == 3 ? 0 : n;
	return 0;
}

/* ---- the gateway's side ---- */
static uint8_t gw_pub[PK_LEN], gw_sec[MLDSA_SECRETKEYBYTES(65)];
static const uint8_t SEED[32] = {0xd5, 1, 2, 3}, ROOT[32] = {0x7e, 9, 8, 7};

/* A device: the PC port's platform, started with a work buffer of exactly work_len bytes (guarded). */
static uint8_t *start(struct aegis_host *h, int token, size_t work_len)
{
	uint8_t *work = guarded(work_len);
	struct aegis_config cfg = {.platform = &h->platform, .verifier_pk = gw_pub, .identity_seed = SEED,
				   .exchange_root = ROOT, .work = work, .work_len = work_len};

	aegis_host_prepare(h, "contract-check", "check", "0.0.1");
	h->platform.measurements = token ? NULL : t_measurements;
	h->platform.evidence = token ? t_evidence : NULL;
	if (AEGIS_PROVER_INIT(&h->prover, &cfg) != AEGIS_OK) abort();
	return work;
}

static int dev_verify(const struct aegis_prover *p, const char *label, const uint8_t *m, size_t n, const uint8_t *s)
{
	static uint8_t buf[64 + AEGIS_WORK_CRED];
	const uint8_t pre[2] = {0, 0};
	size_t l = strlen(label) + 1;

	memcpy(buf, label, l);
	memcpy(buf + l, m, n);
	return aegis_mldsa_verify_internal(s, buf, l + n, pre, 2, p->pk, 0);
}

static char *hex32(const uint8_t v[32], char out[65])
{
	*put_hex(out, v, 32) = 0;
	return out;
}

/* A credential as the gateway signs it for this ciphertext, key and (if not NULL) transcript, its body padded to
 * exactly body_len bytes (0: as short as it is). Returns the credential's length. */
static size_t make_cred(const struct aegis_prover *p, const uint8_t *ct, const uint8_t *ek, const uint8_t *t2,
			size_t body_len, uint8_t *cred)
{
	static uint8_t msg[32 + AEGIS_CRED_MAX];
	const uint8_t pre[2] = {0, 0}, rnd[32] = {0};
	uint8_t h_ct[32], h_ek[32];
	char a[65], b[65], c[65], d[65], *body = (char *)cred;
	size_t n;

	sha3_256(ct, KEM_CT_LEN, h_ct);
	sha3_256(ek, KEM_EK_LEN, h_ek);
	n = (size_t)sprintf(body, "{\"endpoint_pq_pk_sha256\":\"%s\",\"expires\":1795003600,\"issued\":1795000000,"
			    "\"kem_ct_sha3_256\":\"%s\",\"kem_ek_sha3_256\":\"%s\"",
			    hex32(p->pk_sha256, a), hex32(h_ct, b), hex32(h_ek, c));
	if (t2) n += (size_t)sprintf(body + n, ",\"transcript_sha3_256\":\"%s\"", hex32(t2, d));
	if (body_len) {
		n += (size_t)sprintf(body + n, ",\"x\":\"");
		if (n + 2 > body_len) abort();
		memset(body + n, 'x', body_len - 2 - n);
		n = body_len - 2;
		body[n++] = '"';
	}
	body[n++] = '}';
	memcpy(msg, CRED_LABEL, sizeof(CRED_LABEL));
	memcpy(msg + sizeof(CRED_LABEL), body, n);
	cred[n] = '\n';
	if (aegis_mldsa_signature_internal(cred + n + 1, msg, sizeof(CRED_LABEL) + n, pre, 2, rnd, gw_sec, 0) != 0) abort();
	return n + 1 + SIG_LEN;
}

/* One exchange without a quote, finished with a credential whose body has body_len bytes; the result. */
static int exchange(struct aegis_prover *p, size_t body_len)
{
	static uint8_t cred[AEGIS_CRED_MAX + 64], ct[KEM_CT_LEN];
	const uint8_t *ek, *sig;
	uint8_t nonce[32] = {7}, coins[32] = {3}, k[32], tag[32];
	size_t cl;

	if (aegis_prover_kem_init(p, nonce, &ek, &sig) != AEGIS_OK) return -1;
	if (aegis_mlkem_enc_derand(ct, k, ek, coins) != 0) abort();
	cl = make_cred(p, ct, ek, NULL, body_len, cred);
	return aegis_prover_kem_finish(p, ct, cred, cl, tag);
}

/* ---- the checks ---- */

static void inputs_are_read_once(void)
{
	static struct aegis_host h;
	static uint8_t cred[AEGIS_CRED_MAX], cred0[AEGIS_CRED_MAX], ct[KEM_CT_LEN], ct0[KEM_CT_LEN], ek0[KEM_EK_LEN];
	static uint8_t t2msg[32];
	const uint8_t *ev, *sig, *ek;
	uint8_t ch0[32], ch[32], nonce[32], coins[32] = {5}, k[32], h_ev[32], t1[32], t2[32], t3[32], h_ct[32], h_cred[32];
	uint8_t tag[32], want[32], info[AEGIS_SESSION_LEN], skey[32];
	uint8_t *work = start(&h, 0, AEGIS_WORK_CRED);
	struct aegis_prover *p = &h.prover;
	size_t evn, cl;

	for (int i = 0; i < 32; i++) ch0[i] = (uint8_t)(0xc0 + i);
	/* the quote: the challenge is overwritten as soon as the core has taken it */
	memcpy(ch, ch0, 32);
	victim[0].p = ch; victim[0].n = 32; victims = 1; taken = 0;
	CHECK(aegis_prover_quote(p, ch, &ev, &evn, &sig) == AEGIS_OK);
	CHECK(taken == 1 && all(ch, 32, 0x5a));
	CHECK(memmem(ev, evn, ch0, 32) != NULL);                 /* the claims carry the challenge as passed */
	CHECK(dev_verify(p, QUOTE_LABEL, ev, evn, sig) == 0);
	sha3_256(ev, evn, h_ev);
	hash_parts(t1, T_QUOTE, ch0, 32, h_ev, 32, NULL, 0, NULL, 0);
	/* the exchange that continues it: its nonce too */
	memcpy(nonce, ch0, 32);
	victim[0].p = nonce;
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_OK);
	CHECK(taken == 2 && all(nonce, 32, 0x5a));
	memcpy(ek0, ek, KEM_EK_LEN);
	hash_parts(t2, T_KEM_INIT, t1, 32, ek0, KEM_EK_LEN, NULL, 0, NULL, 0);
	memcpy(t2msg, t2, 32);
	CHECK(dev_verify(p, KEM2_LABEL, t2msg, 32, sig) == 0);   /* bound to the quote of the challenge as passed */
	/* the finish: ciphertext and credential */
	if (aegis_mlkem_enc_derand(ct0, k, ek0, coins) != 0) abort();
	cl = make_cred(p, ct0, ek0, t2, 0, cred0);
	memcpy(ct, ct0, KEM_CT_LEN);
	memcpy(cred, cred0, cl);
	victim[0].p = ct; victim[0].n = KEM_CT_LEN;
	victim[1].p = cred; victim[1].n = cl; victims = 2;
	CHECK(aegis_prover_kem_finish(p, ct, cred, cl, tag) == AEGIS_OK);
	CHECK(taken == 3 && all(ct, KEM_CT_LEN, 0x5a) && all(cred, cl, 0x5a));
	victims = 0;
	sha3_256(ct0, KEM_CT_LEN, h_ct);
	sha3_256(cred0, cl, h_cred);
	hash_parts(t3, T_KEM_FIN, t2, 32, h_ct, 32, h_cred, 32, NULL, 0);
	hash_parts(want, "aegis-confirm-v2", k, 32, t3, 32, NULL, 0, NULL, 0);
	CHECK(memcmp(tag, want, 32) == 0);                       /* the tag of what was passed, not of what is there now */
	hash_parts(skey, "aegis-session-v2", k, 32, t3, 32, NULL, 0, NULL, 0);
	hash_parts(want, "aegis-session-id-v1", skey, 32, NULL, 0, NULL, 0, NULL, 0);
	CHECK(aegis_prover_session(p, info) == AEGIS_OK);
	CHECK(memcmp(info, want, 32) == 0 && memcmp(info + 32, h_cred, 32) == 0);
	/* an exchange that continues no quote signs the nonce as passed */
	for (int i = 0; i < 32; i++) nonce[i] = (uint8_t)(0x40 + i);
	memcpy(ch, nonce, 32);
	victim[0].p = nonce; victim[0].n = 32; victims = 1;
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_OK);
	victims = 0;
	{
		static uint8_t m[32 + KEM_EK_LEN];

		memcpy(m, ch, 32);
		memcpy(m + 32, ek, KEM_EK_LEN);
		CHECK(dev_verify(p, KEM_LABEL, m, sizeof(m), sig) == 0);
	}
	CHECK(guard_ok(work, AEGIS_WORK_CRED));
	free(work);
}

static void credential_body_and_work_buffer(void)
{
	static struct aegis_host h;
	const size_t most = AEGIS_WORK_MIN - AEGIS_WORK_CRED_HEAD; /* 1214 */
	uint8_t *work = start(&h, 0, AEGIS_WORK_MIN);

	CHECK(exchange(&h.prover, most) == AEGIS_OK);
	CHECK(exchange(&h.prover, most + 1) == AEGIS_ERR_CRED_SIGNATURE);
	CHECK(exchange(&h.prover, most - 1) == AEGIS_OK);
	CHECK(exchange(&h.prover, AEGIS_CRED_BODY_MAX) == AEGIS_ERR_CRED_SIGNATURE);
	CHECK(guard_ok(work, AEGIS_WORK_MIN));
	free(work);
	/* the buffer AEGIS_WORK_LEN() gives takes every credential the protocol allows */
	work = start(&h, 0, AEGIS_WORK_CRED);
	CHECK(exchange(&h.prover, most + 1) == AEGIS_OK);
	CHECK(exchange(&h.prover, AEGIS_CRED_BODY_MAX) == AEGIS_OK);
	CHECK(guard_ok(work, AEGIS_WORK_CRED));
	free(work);
	/* and one byte of work buffer less than a body needs refuses it */
	work = start(&h, 0, AEGIS_WORK_CRED - 1);
	CHECK(exchange(&h.prover, AEGIS_CRED_BODY_MAX) == AEGIS_ERR_CRED_SIGNATURE);
	CHECK(exchange(&h.prover, AEGIS_CRED_BODY_MAX - 1) == AEGIS_OK);
	CHECK(guard_ok(work, AEGIS_WORK_CRED - 1));
	free(work);
}

static void evidence_length(void)
{
	static struct aegis_host h;
	const size_t wl = AEGIS_WORK_MIN, room = wl - AEGIS_WORK_QUOTE_HEAD;
	const uint8_t *ev = NULL, *sig = NULL, *ek;
	uint8_t ch[32] = {0x11, 0x22}, *work = start(&h, 1, wl), *reply;
	struct aegis_prover *p = &h.prover;
	char line[80];
	size_t n = 0;
	int r;

	ev_kind = 0;
	CHECK(aegis_prover_quote(p, ch, &ev, &n, &sig) == AEGIS_OK && n == 120 && ev_cap == room);
	/* one byte more than the room: refused, nothing given out, and no quote left to continue */
	ev_kind = 1; ev = NULL; sig = NULL; n = 777;
	CHECK(aegis_prover_quote(p, ch, &ev, &n, &sig) == AEGIS_ERR_EVIDENCE);
	CHECK(ev == NULL && sig == NULL && n == 777 && !p->quote_ready);
	CHECK(aegis_prover_kem_init(p, ch, &ek, &sig) == AEGIS_OK && !p->kem_bound);
	ev_kind = 3;
	CHECK(aegis_prover_quote(p, ch, &ev, &n, &sig) == AEGIS_ERR_EVIDENCE && !p->quote_ready);
	/* exactly the room: the longest evidence there is, signed whole */
	ev_kind = 2;
	CHECK(aegis_prover_quote(p, ch, &ev, &n, &sig) == AEGIS_OK && n == room);
	CHECK(dev_verify(p, QUOTE_LABEL, ev, n, sig) == 0 && all(ev + 32, n - 32, 0xa7));
	CHECK(guard_ok(work, wl));
	free(work);
	/* the line transport: the reply buffer sets the room, here below what the work buffer could hold */
	work = start(&h, 1, AEGIS_WORK_CRED);
	p = &h.prover;
	reply = guarded(AEGIS_REPLY_MAX);
	strcpy(line, "PQCHAL ");
	*put_hex(line + 7, ch, 32) = 0;
	ev_kind = 2;
	r = aegis_prover_handle_line(p, line, (char *)reply, AEGIS_REPLY_MAX);
	CHECK(ev_cap == (AEGIS_REPLY_MAX - 64u) / 2u - SIG_LEN && ev_cap < AEGIS_WORK_CRED - AEGIS_WORK_QUOTE_HEAD);
	CHECK(r > 0 && (size_t)r < AEGIS_REPLY_MAX && strlen((char *)reply) == (size_t)r && !memcmp(reply, "PQTOKEN ", 8));
	CHECK((size_t)r == 8 + 4 + 1 + 2 * ev_cap + 1 + 4 + 1 + 2 * SIG_LEN + 4);
	CHECK(guard_ok(reply, AEGIS_REPLY_MAX));
	ev_kind = 1;
	*put_hex(line + 7, ch, 32) = 0;
	line[6] = ' ';
	r = aegis_prover_handle_line(p, line, (char *)reply, AEGIS_REPLY_MAX);
	CHECK(r == 12 && !strcmp((char *)reply, "ERR evidence") && !p->quote_ready);
	CHECK(guard_ok(reply, AEGIS_REPLY_MAX) && guard_ok(work, AEGIS_WORK_CRED));
	ev_kind = 0;
	free(reply);
	free(work);
}

static void heartbeat_status_buffer(void)
{
	static struct aegis_host h;
	uint8_t *work = start(&h, 0, AEGIS_WORK_CRED), nonce[32] = {1}, out[AEGIS_HB_LEN];
	struct aegis_prover *p = &h.prover;
	const char want[] = "a=1;ttl=3825"; /* a lifetime of 3600 s and its sixteenth, nothing of it used yet */
	const size_t full = sizeof(want) - 1;
	uint8_t *st;
	size_t len;

	CHECK(exchange(p, 0) == AEGIS_OK);
	/* exactly enough room */
	st = guarded(full);
	memcpy(st, "a=1", 3);
	len = 3;
	CHECK(aegis_prover_heartbeat(p, nonce, (char *)st, &len, full, 0, out) == AEGIS_OK);
	CHECK(len == full && !memcmp(st, want, full) && guard_ok(st, full) && out[0] == 1);
	free(st);
	/* one byte short: refused, nothing written, not counted */
	st = guarded(full - 1);
	memcpy(st, "a=1", 3);
	len = 3;
	memset(out, 0xEE, sizeof(out));
	CHECK(aegis_prover_heartbeat(p, nonce, (char *)st, &len, full - 1, 0, out) == AEGIS_ERR_BUFFER);
	CHECK(len == 3 && !memcmp(st, "a=1", 3) && all(st + 3, full - 1 - 3, 0xEE) && guard_ok(st, full - 1));
	CHECK(all(out, sizeof(out), 0xEE));
	/* the same buffer takes the status as it is */
	CHECK(aegis_prover_heartbeat(p, nonce, (char *)st, &len, full - 1, AEGIS_HB_RAW, out) == AEGIS_OK);
	CHECK(len == 3 && out[0] == 2 && guard_ok(st, full - 1));
	/* a status longer than its buffer is refused in either way */
	len = full;
	CHECK(aegis_prover_heartbeat(p, nonce, (char *)st, &len, full - 1, AEGIS_HB_RAW, out) == AEGIS_ERR_BUFFER);
	CHECK(aegis_prover_heartbeat(p, nonce, (char *)st, &len, full - 1, 0, out) == AEGIS_ERR_BUFFER);
	CHECK(len == full && guard_ok(st, full - 1));
	free(st);
	st = guarded(full);
	memcpy(st, "a=1", 3);
	len = 3;
	CHECK(aegis_prover_heartbeat(p, nonce, (char *)st, &len, full, 0, out) == AEGIS_OK && out[0] == 3);
	free(st);
	free(work);
}

static void generator_that_repeats(void)
{
	static struct aegis_host h;
	const uint8_t *a, *b, *ek, *sig;
	uint8_t *work = start(&h, 0, AEGIS_WORK_CRED), nonce[32] = {9}, ek1[KEM_EK_LEN];
	struct aegis_prover *p = &h.prover;
	size_t n;

	/* 32 equal bytes, zeros or others: no key */
	rng_force = 1; memset(rng_forced, 0, 32);
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_ERR_RNG && !p->kem_pending);
	rng_force = 1; memset(rng_forced, 0x55, 32);
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_ERR_RNG && !p->kem_pending);
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_OK);
	memcpy(ek1, ek, KEM_EK_LEN);
	/* the bytes of the draw before (that exchange's signature): a generator that stands still */
	rng_force = 1; memcpy(rng_forced, rng_out, 32);
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_ERR_RNG && !p->kem_pending);
	/* the same after a quote's signature, and after a draw that was itself refused */
	CHECK(aegis_prover_quote(p, nonce, &a, &n, &b) == AEGIS_OK);
	rng_force = 1; memcpy(rng_forced, rng_out, 32);
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_ERR_RNG);
	rng_force = 1; memcpy(rng_forced, rng_out, 32);
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_ERR_RNG);
	/* a generator that works again is used again, and gives another key */
	CHECK(aegis_prover_kem_init(p, nonce, &ek, &sig) == AEGIS_OK && memcmp(ek, ek1, KEM_EK_LEN) != 0);
	free(work);
}

static void start_refuses_zero_secrets(void)
{
	static struct aegis_host h;
	static const uint8_t zero[32];
	uint8_t work[AEGIS_WORK_MIN];
	struct aegis_config cfg = {.platform = &h.platform, .verifier_pk = gw_pub, .identity_seed = SEED,
				   .exchange_root = ROOT, .work = work, .work_len = sizeof(work)};

	aegis_host_prepare(&h, "contract-check", "check", "0.0.1");
	h.platform.measurements = t_measurements;
	cfg.identity_seed = zero;
	CHECK(AEGIS_PROVER_INIT(&h.prover, &cfg) == AEGIS_ERR_IDENTITY && aegis_prover_public_key(&h.prover) == NULL);
	cfg.identity_seed = SEED;
	cfg.exchange_root = zero;
	CHECK(AEGIS_PROVER_INIT(&h.prover, &cfg) == AEGIS_ERR_IDENTITY && aegis_prover_public_key(&h.prover) == NULL);
	cfg.exchange_root = ROOT;
	/* seed and root may lie in the work buffer (the STM32 port's way) */
	memcpy(work, SEED, 32);
	memcpy(work + 32, ROOT, 32);
	cfg.identity_seed = work;
	cfg.exchange_root = work + 32;
	CHECK(AEGIS_PROVER_INIT(&h.prover, &cfg) == AEGIS_OK);
	{
		static struct aegis_host ref;
		uint8_t *w = start(&ref, 0, AEGIS_WORK_MIN);

		CHECK(memcmp(aegis_prover_public_key(&h.prover), aegis_prover_public_key(&ref.prover), PK_LEN) == 0);
		CHECK(memcmp(h.prover.prov_root, ROOT, 32) == 0);
		free(w);
	}
}

static void measurements_without_label_or_terminator(void)
{
	static struct aegis_host h;
	static const uint8_t head[3] = {0x06, 0x78, 0x40}; /* key 6, a text of 64 bytes */
	const uint8_t *ev, *sig, *at;
	uint8_t ch[32] = {4}, *work = start(&h, 0, AEGIS_WORK_CRED);
	struct aegis_measurement *save = meas;
	size_t save_n = meas_n, n;

	/* the last entry ends where its memory ends: a read beyond the description is a read beyond the block */
	meas = malloc(2 * sizeof(*meas));
	meas_n = 2;
	if (!meas) abort();
	memset(meas, 0, 2 * sizeof(*meas));
	meas[0].label = "A";
	strcpy(meas[0].desc, "first");
	meas[1].label = "B";
	memset(meas[1].desc, 'd', sizeof(meas[1].desc)); /* no terminator */
	CHECK(aegis_prover_quote(&h.prover, ch, &ev, &n, &sig) == AEGIS_OK);
	at = memmem(ev, n, head, sizeof(head));
	CHECK(at != NULL && at + 3 + 64 == ev + n && all(at + 3, 64, 'd')); /* 64 bytes of it, and the claims end there */
	meas[1].label = NULL;
	CHECK(aegis_prover_quote(&h.prover, ch, &ev, &n, &sig) == AEGIS_ERR_EVIDENCE && !h.prover.quote_ready);
	free(meas);
	meas = save;
	meas_n = save_n;
	free(work);
}

static void host_port_measurements(const char *dir)
{
	static struct aegis_host h;
	static char reply[AEGIS_REPLY_MAX], line[80], big[600], small[600];
	FILE *f;

	snprintf(big, sizeof(big), "%s/big", dir);
	snprintf(small, sizeof(small), "%s/small", dir);
	f = fopen(small, "wb");
	if (!f || fwrite("image", 1, 5, f) != 5 || fclose(f) != 0) abort();
	f = fopen(big, "wb");
	if (!f || ftruncate(fileno(f), (4 << 20) + 1) != 0 || fclose(f) != 0) abort();
	for (int k = 0; k < 4; k++) {
		/* 0: a file it can hash; 1: one byte more than its buffer; 2: exactly its buffer; 3: a directory */
		aegis_host_prepare(&h, "contract-check", "check", "0.0.1");
		aegis_host_add_image(&h, "APP", k == 0 ? small : k == 3 ? dir : big, "firmware image");
		if (k == 2 && truncate(big, 4 << 20) != 0) abort();
		if (aegis_host_start(&h, SEED, ROOT, gw_pub, 0) != AEGIS_OK) abort();
		strcpy(line, "PQCHAL 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
		aegis_prover_handle_line(&h.prover, line, reply, sizeof(reply));
		if (k == 0 || k == 2) CHECK(!strncmp(reply, "PQTOKEN ", 8));
		else CHECK(!strcmp(reply, "ERR evidence"));
	}
}

int main(int argc, char **argv)
{
	static struct aegis_measurement two[2] = {{.label = "SPE", .desc = "SHA256 of the secure partition"},
						  {.label = "NSPE", .desc = "SHA256 of the non-secure partition"}};
	uint8_t gseed[32];

	if (argc != 2) return 2;
	memset(gseed, 0x47, sizeof(gseed));
	if (aegis_mldsa_keypair_internal(gw_pub, gw_sec, gseed) != 0) return 2;
	meas = two;
	meas_n = 2;
	aegis_host_test_random = t_random;
	aegis_host_test_clock = t_clock;
	inputs_are_read_once();
	credential_body_and_work_buffer();
	evidence_length();
	heartbeat_status_buffer();
	generator_that_repeats();
	start_refuses_zero_secrets();
	measurements_without_label_or_terminator();
	host_port_measurements(argv[1]);
	printf("core contract: %d checks, %d failed\n", checks, failed);
	return failed ? 1 : 0;
}
