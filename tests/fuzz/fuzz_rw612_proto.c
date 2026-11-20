/* SPDX-License-Identifier: Apache-2.0
 *
 * libFuzzer harness for the protocol code the RW612 TF-M partition runs on non-secure input
 * (endpoints/rw612/prover/src/aegis_proto.c), built with AddressSanitizer and UndefinedBehaviorSanitizer.
 * Build and run: tests/fuzz/run.sh.
 *
 * The harness calls aegis_proto_handle() exactly as endpoints/rw612/tfm/aegis_pq/aegis_pq.c does: up to
 * AEGIS_LINE_MAX raw bytes (NUL bytes included) in a buffer of that size plus a terminator, a reply buffer of exactly
 * AEGIS_REPLY_MAX bytes, and the same reply-length check. The platform is the partition's: profile
 * aegis-rw612-tfm-v1, two measurements (SPE, NSPE), a status text.
 *
 * Random lines alone stop at the gateway's signature, so the harness also plays the gateway: it holds the pinned
 * gateway key, encapsulates to the device's ML-KEM key and signs credentials whose body the input changes. An input
 * is a list of operations, each "op, length (2 bytes, little-endian), payload":
 *   0  a raw request line (anything at all)
 *   1  PQKEMINIT with a nonce from the payload (the challenge of the last PQCHAL: the exchange continues that quote)
 *   2  PQKEMFIN built as the gateway would, then changed by the payload (fields left out or wrong, text added,
 *      signature or ciphertext damaged, a newline inside the body, or the payload signed as the whole body); the op
 *      byte's upper bits change the validity: bits 3-5 pick 0 as the gateway writes it, 1 no "issued", 2 no
 *      "expires", 3 a lifetime of zero, 4 "expires" twice, 5 eleven digits, 6 a string, 7 a second too long; bits 6-7
 *      pick the lifetime (3600, 1, 86400 or 40 seconds). The gateway names the transcript T2 exactly when the
 *      exchange continues a quote; payload byte 32, bit 0 turns that round (left out where it is needed, added where
 *      it is not), bit 1 names another transcript
 *   3  PQHB with a nonce from the payload
 *   4  PQCHAL with a challenge from the payload
 *   5  PQSESSION
 *   6  after K good random draws, the next N fail (K, N from the payload); with upper bits in the op byte, the
 *      session clock instead: 1 forward by the payload's seconds (32 bits), 2 it fails or works again, 3 backwards
 *   7  set the platform's status text (from the payload; never empty, as on the board)
 *
 * Besides the sanitizers, it checks every answer against a model of the protocol and aborts when they differ:
 *   - every reply fits, ends at the returned length and is printable ASCII;
 *   - a credential is accepted if and only if an exchange is pending, the clock works, the ciphertext has the right
 *     length, the body has no newline, the gateway's ML-DSA-65 signature over it is valid, it names SHA3-256(ct),
 *     SHA3-256(ek) of the pending exchange and SHA-256(device pk), and it carries "issued" and "expires" once each
 *     with a lifetime of 1 to 86400 seconds, all checked here independently;
 *   - a session answers until the clock shows its lifetime plus a sixteenth after the accepted PQKEMFIN, and from
 *     that second on, or when the clock fails or runs backwards, PQHB and PQSESSION answer "ERR pq expired" (before
 *     any session: "ERR pq no-session"), whatever requests came in between; every heartbeat status ends with the
 *     seconds left;
 *   - a raw line is never accepted as a credential (no forged or replayed credential);
 *   - a refused PQKEMINIT leaves no exchange pending;
 *   - the confirmation tag, the session id, the credential hash and every heartbeat tag are what the gateway computes,
 *     the heartbeat counter counts up by one, a refused exchange leaves the session as it was;
 *   - every quote and KEM key is signed by the device key, and the quote carries the challenge and the profile;
 *   - one transcript: a PQKEMINIT continues a quote if and only if its nonce is the challenge of the last PQCHAL that
 *     was answered and no PQKEMINIT has continued that quote yet (another PQCHAL, a refused one and a first use each
 *     end it). The KEM key's signature is then over "aegis-kem-init-v2" and
 *     T2 = H(kem-init || H(quote || challenge || SHA3(claims)) || ek), computed here from the claims the PQCHAL
 *     returned, and otherwise over "aegis-kem-init-v1" and nonce || ek: never the other one. Such an exchange accepts
 *     a credential only if it also names T2 ("ERR cred other-transcript"), and its tag and session key are the
 *     transcript's (T3 = H(kem-fin || T2 || SHA3(ct) || SHA3(credential))); an exchange that continues no quote gives
 *     the first version's tag and key whatever the credential says about a transcript.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the file under test, included so the harness can reset its state between inputs; it is not changed */
#include "aegis_proto.c"

#define DIE(...) do { fprintf(stderr, "ORACLE: " __VA_ARGS__); fputc('\n', stderr); abort(); } while (0)

static uint8_t gw_pub[PK_LEN], gw_sec[MLDSA_SECRETKEYBYTES(65)];
static const uint8_t *dev_pk;
static uint8_t dev_pk_sha256[32];

/* ---- the platform: a deterministic generator (an input replays exactly), failures on demand ---- */
static uint64_t rng_state;
static unsigned rng_skip, rng_fail; /* after rng_skip good draws, the next rng_fail draws fail */
static char status_text[256];

static int fz_random(uint8_t *out, size_t n)
{
	if (rng_skip) {
		rng_skip--;
	} else if (rng_fail) {
		rng_fail--;
		return -1;
	}
	for (size_t i = 0; i < n; i++) {
		rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
		out[i] = (uint8_t)(rng_state >> 24);
	}
	return 0;
}

static size_t fz_measure_all(struct aegis_measurement *m, size_t max)
{
	if (max < 2) return 0;
	m[0].label = "SPE";
	memset(m[0].value, 0x5e, 32);
	snprintf(m[0].desc, sizeof(m[0].desc), "SHA256 of the secure partition (%u bytes)", 651264u);
	m[1].label = "NSPE";
	memset(m[1].value, 0x95, 32);
	snprintf(m[1].desc, sizeof(m[1].desc), "SHA256 of the non-secure partition (%u bytes)", 3145728u);
	return 2;
}

static int fz_status(char *buf, size_t cap) { return snprintf(buf, cap, "%s", status_text); }
static void fz_measure(uint8_t out[32], size_t *len) { memset(out, 0, 32); *len = 0; }
static uint32_t fz_uptime(void) { return 7; }

/* the session clock: the harness moves it and makes it fail */
static uint64_t fz_now;
static int fz_clock_fail;

static int fz_monotonic(uint64_t *now)
{
	if (fz_clock_fail) return -1;
	*now = fz_now;
	return 0;
}

static const struct aegis_proto_platform platform = {
	.random = fz_random, .measure = fz_measure, .uptime_s = fz_uptime, .monotonic_s = fz_monotonic,
	.profile = "aegis-rw612-tfm-v1", .measure_all = fz_measure_all, .status = fz_status};

/* ---- the model: what the gateway knows ---- */
static struct {
	int pending;               /* a PQKEMINIT was answered and no PQKEMFIN has used it */
	uint8_t ek[KEM_EK_LEN], nonce[32];
	int quote;                 /* a PQCHAL was answered and no PQKEMINIT has continued it */
	uint8_t q_ch[32], q_t1[32];
	int bound;                 /* the pending exchange continues a quote; its T2 */
	uint8_t t2[32];
	int session;
	int expired;               /* the last session was ended by the clock */
	uint64_t start, limit;     /* the clock when the session started; the seconds it may live */
	uint8_t session_key[32], cred_hash[32];
	uint64_t hb;
} M;

/* what any request does first: a session past its end, or whose age the clock cannot give, is gone */
static void model_sweep(void)
{
	if (M.session && (fz_clock_fail || fz_now < M.start || fz_now - M.start >= M.limit)) {
		M.session = 0;
		M.expired = 1;
	}
}

static const char *model_no_session(void)
{
	return M.expired ? "ERR pq expired" : "ERR pq no-session";
}

/* "<key>":<1 to 10 digits> then ',' or '}', the key exactly once (an independent reading, not the device's) */
static int model_number(const uint8_t *b, size_t n, const char *key, uint64_t *v)
{
	char pat[32], digits[12];
	size_t pl = (size_t)snprintf(pat, sizeof(pat), "\"%s\":", key), d = 0;
	const uint8_t *at = memmem(b, n, pat, pl), *end = b + n;

	if (!at || memmem(at + 1, (size_t)(end - at - 1), pat, pl)) return 0;
	for (at += pl; at < end && *at >= '0' && *at <= '9' && d < 11; at++) digits[d++] = (char)*at;
	if (d < 1 || d > 10 || at == end || (*at != ',' && *at != '}')) return 0;
	digits[d] = 0;
	*v = strtoull(digits, NULL, 10);
	return 1;
}

/* the lifetime a body carries, or 0 */
static uint64_t model_lifetime(const uint8_t *b, size_t n)
{
	uint64_t issued, expires;

	if (!model_number(b, n, "issued", &issued) || !model_number(b, n, "expires", &expires)) return 0;
	return expires > issued && expires - issued <= 86400 ? expires - issued : 0;
}

/* ---- helpers ---- */
static char *hexs(const uint8_t *p, size_t n, char *o)
{
	for (size_t i = 0; i < n; i++) { *o++ = HX[p[i] >> 4]; *o++ = HX[p[i] & 15]; }
	*o = 0;
	return o;
}

static const char *hex32(const uint8_t v[32], char buf[65])
{
	hexs(v, 32, buf);
	return buf;
}

static int unhexs(const char *s, size_t sl, uint8_t *o, size_t n)
{
	if (sl != 2 * n) return -1;
	for (size_t i = 0; i < n; i++) {
		int a = unhex(s[2 * i]), b = unhex(s[2 * i + 1]);

		if (a < 0 || b < 0) return -1;
		o[i] = (uint8_t)(a << 4 | b);
	}
	return 0;
}

static int fields(char *s, char **f, int max)
{
	int n = 0;

	for (char *t = strtok(s, " "); t && n < max; t = strtok(NULL, " ")) f[n++] = t;
	return n;
}

static void sha3v(uint8_t out[32], int n, ...)
{
	struct sha3 h;
	va_list ap;

	sha3_init(&h);
	va_start(ap, n);
	for (int i = 0; i < n; i++) {
		const void *p = va_arg(ap, const void *);
		size_t l = va_arg(ap, size_t);

		sha3_update(&h, p, l);
	}
	va_end(ap);
	sha3_final(&h, out);
}

static int dev_verify(const char *label, const uint8_t *m, size_t n, const uint8_t *s)
{
	static uint8_t buf[64 + KEM_EK_LEN + CLAIMS_MAX];
	const uint8_t pre[2] = {0, 0};
	size_t l = strlen(label) + 1;

	memcpy(buf, label, l);
	memcpy(buf + l, m, n);
	return aegis_mldsa_verify_internal(s, buf, l + n, pre, 2, dev_pk, 0);
}

/* the body names "<key>":"<hex of v>" (an independent check, not the device's names()) */
static int contains(const uint8_t *b, size_t n, const char *key, const uint8_t v[32])
{
	char want[160], hx[65];

	snprintf(want, sizeof(want), "\"%s\":\"%s\"", key, hex32(v, hx));
	return memmem(b, n, want, strlen(want)) != NULL;
}

/* ---- one transcript: the model's own reading of common/transcript.py ---- */
/* a well-formed PQCHAL: whatever it answers, the quote before it can no longer be continued */
static void model_quote(int answered, const uint8_t ch[32], const uint8_t *cl, size_t len)
{
	uint8_t h[32];

	M.quote = 0;
	if (!answered) return;
	sha3_256(cl, len, h);
	sha3v(M.q_t1, 3, "aegis-transcript-v2/quote", (size_t)25, ch, (size_t)32, h, (size_t)32);
	memcpy(M.q_ch, ch, 32);
	M.quote = 1;
}

/* a well-formed PQKEMINIT: does it continue the quote? The quote is used up either way it ends. */
static int model_continues(const uint8_t nonce[32])
{
	int b = M.quote && !memcmp(nonce, M.q_ch, 32);

	if (b) M.quote = 0;
	return b;
}

/* the answered PQKEMINIT: its signature is the transcript's if it continues a quote, the first version's if not */
static void model_kem_key(int continues, const uint8_t nonce[32], const uint8_t *ek, const uint8_t *s)
{
	static uint8_t msg[32 + KEM_EK_LEN];

	if (continues) {
		sha3v(M.t2, 3, "aegis-transcript-v2/kem-init", (size_t)28, M.q_t1, (size_t)32, ek, (size_t)KEM_EK_LEN);
		if (dev_verify("aegis-kem-init-v2", M.t2, 32, s) != 0)
			DIE("the KEM key of an exchange that continues a quote is not signed over its transcript");
	} else {
		memcpy(msg, nonce, 32);
		memcpy(msg + 32, ek, KEM_EK_LEN);
		if (dev_verify("aegis-kem-init-v1", msg, sizeof(msg), s) != 0)
			DIE("the KEM key of an exchange that continues no quote is not signed as the first version's");
	}
	if (ek != M.ek) memcpy(M.ek, ek, KEM_EK_LEN);
	memcpy(M.nonce, nonce, 32);
	M.bound = continues;
	M.pending = 1;
}

/* one request, as the partition makes it; returns the reply (the caller frees it) */
static char *call(const uint8_t *req, size_t n)
{
	char *line = malloc(n + 1), *out = malloc(AEGIS_REPLY_MAX);
	int r;

	memcpy(line, req, n);
	line[n] = 0;
	model_sweep();
	r = aegis_proto_handle(line, out, AEGIS_REPLY_MAX);
	free(line);
	if (r < 0 || (size_t)r >= AEGIS_REPLY_MAX) DIE("reply length %d", r);
	if (strlen(out) != (size_t)r) DIE("reply does not end at its length (%zu, %d)", strlen(out), r);
	for (int i = 0; i < r; i++) {
		if (out[i] < 0x20 || out[i] > 0x7e) DIE("byte 0x%02x in reply", (unsigned char)out[i]);
	}
	return out;
}

/* ---- operations ---- */
static void op_raw(const uint8_t *p, size_t n)
{
	char *req, *t[5], *rep, *f[8];
	int tn = 0;
	uint8_t nonce[32];

	if (n == 0 || n > AEGIS_LINE_MAX) return; /* the partition refuses these before the protocol code */
	/* what the device sees: the request up to its first NUL, split as the device splits it */
	req = malloc(n + 1);
	memcpy(req, p, n);
	req[n] = 0;
	for (char *s = strtok(req, " \t\r\n"); s && tn < 5; s = strtok(NULL, " \t\r\n")) t[tn++] = s;
	rep = call(p, n);
	if (tn == 2 && !strcmp(t[0], "PQKEMINIT") && !unhexs(t[1], strlen(t[1]), nonce, 32)) {
		static uint8_t sig[SIG_LEN];
		int continues = model_continues(nonce);

		M.pending = 0;
		if (!strncmp(rep, "PQKEMEK ", 8)) {
			if (fields(rep, f, 8) != 6 || unhexs(f[2], strlen(f[2]), M.ek, KEM_EK_LEN) ||
			    unhexs(f[4], strlen(f[4]), sig, SIG_LEN))
				DIE("malformed PQKEMEK");
			model_kem_key(continues, nonce, M.ek, sig);
		}
	} else if (tn == 2 && !strcmp(t[0], "PQCHAL") && !unhexs(t[1], strlen(t[1]), nonce, 32)) {
		static uint8_t cl[CLAIMS_MAX];
		unsigned len = 0;
		int answered = !strncmp(rep, "PQTOKEN ", 8);

		if (answered && (fields(rep, f, 8) != 6 || sscanf(f[1], "%u", &len) != 1 || len > CLAIMS_MAX ||
				 unhexs(f[2], strlen(f[2]), cl, len)))
			DIE("malformed PQTOKEN");
		model_quote(answered, nonce, cl, len);
	} else if (tn == 3 && !strcmp(t[0], "PQKEMFIN")) {
		if (!strncmp(rep, "PQKEMOK", 7)) DIE("a raw line was accepted as a credential");
		if (M.pending && fz_clock_fail && strcmp(rep, "ERR clock")) DIE("PQKEMFIN without a clock: %.40s", rep);
		if (strcmp(rep, "ERR cred no-exchange") && strcmp(rep, "ERR bad-request") && strcmp(rep, "ERR clock"))
			M.pending = 0;
	} else if (!strncmp(rep, "PQHB ", 5)) {
		M.hb++;
	}
	free(req);
	free(rep);
}

static void op_kem_init(const uint8_t *p, size_t n)
{
	static uint8_t sig[SIG_LEN];
	uint8_t nonce[32] = {0};
	char line[10 + 64 + 1], *f[8], *rep;
	int continues;

	memcpy(nonce, p, n < 32 ? n : 32);
	memcpy(line, "PQKEMINIT ", 10);
	hexs(nonce, 32, line + 10);
	rep = call((const uint8_t *)line, strlen(line));
	continues = model_continues(nonce);
	if (!strcmp(rep, "ERR rng") || !strcmp(rep, "ERR sign") || !strcmp(rep, "ERR kem")) {
		M.pending = 0; /* refused: no exchange is left pending, not even half of an older one */
		free(rep);
		return;
	}
	if (fields(rep, f, 8) != 6 || strcmp(f[0], "PQKEMEK") || strcmp(f[5], "END") ||
	    unhexs(f[2], strlen(f[2]), M.ek, KEM_EK_LEN) || unhexs(f[4], strlen(f[4]), sig, SIG_LEN))
		DIE("PQKEMINIT reply");
	model_kem_key(continues, nonce, M.ek, sig);
	free(rep);
}

/* mutation flags in the first payload byte of op 2 */
#define F_DROP_CT   0x01  /* leave kem_ct_sha3_256 out */
#define F_DROP_EK   0x02
#define F_DROP_PK   0x04
#define F_BAD_SIG   0x08  /* flip one signature bit */
#define F_BAD_CT    0x10  /* a ciphertext one byte short */
#define F_NEWLINE   0x20  /* keep newlines in the added text */
#define F_STALE_EK  0x40  /* name an encapsulation key the device did not make */
#define F_SIGN_RAW  0x80  /* the added text alone is the whole body */

static void op_kem_fin(uint8_t sel, const uint8_t *p, size_t n)
{
	static const unsigned lifetimes[4] = {3600, 1, 86400, 40};
	const unsigned variant = sel & 7u, life = lifetimes[(sel >> 3) & 3u];
	const unsigned long long issued = 1795000000ull;
	static uint8_t body[CRED_MAX + 512], cred[CRED_MAX + 512 + SIG_LEN + 1];
	static uint8_t msg[sizeof(CRED_LABEL) + CRED_MAX + 512], s[SIG_LEN];
	static char line[2 * (KEM_CT_LEN + CRED_MAX + 512 + SIG_LEN + 1) + 32];
	const uint8_t pre[2] = {0, 0};
	uint8_t flags = n ? p[0] : 0, coins[32] = {0}, ct[KEM_CT_LEN], k[32], h_ct[32], h_ek[32], stale[32], rnd[32] = {0};
	const uint8_t *extra = n > 33 ? p + 33 : p;
	size_t extra_n = n > 33 ? n - 33 : 0, bl = 0, cl, ctl = KEM_CT_LEN;
	/* the transcript's name in the credential: there exactly when the exchange continues a quote, unless bit 0 of
	 * payload byte 32 turns that round; bit 1 names another transcript */
	const unsigned tr = n > 32 ? p[32] & 3u : 0u;
	const int name_tr = !(flags & F_SIGN_RAW) && (M.bound ? !(tr & 1u) : (tr & 1u) != 0);
	int pending = M.pending, expect, bound;
	uint64_t lifetime;
	char *o, *rep;

	if (n > 1) memcpy(coins, p + 1, n - 1 < 32 ? n - 1 : 32);
	if (aegis_mlkem_enc_derand(ct, k, M.ek, coins) != 0) DIE("encaps");
	sha3_256(ct, KEM_CT_LEN, h_ct);
	sha3_256(M.ek, KEM_EK_LEN, h_ek);
	memset(stale, 0xa5, 32);
	if (!(flags & F_SIGN_RAW)) {
		char hx[65];

		bl += (size_t)sprintf((char *)body + bl, "{\"endpoint\":\"frdm-rw612\"");
		if (!(flags & F_DROP_PK))
			bl += (size_t)sprintf((char *)body + bl, ",\"endpoint_pq_pk_sha256\":\"%s\"", hex32(dev_pk_sha256, hx));
		if (!(flags & F_DROP_CT))
			bl += (size_t)sprintf((char *)body + bl, ",\"kem_ct_sha3_256\":\"%s\"", hex32(h_ct, hx));
		if (!(flags & F_DROP_EK))
			bl += (size_t)sprintf((char *)body + bl, ",\"kem_ek_sha3_256\":\"%s\"",
					      hex32((flags & F_STALE_EK) ? stale : h_ek, hx));
		if (name_tr)
			bl += (size_t)sprintf((char *)body + bl, ",\"transcript_sha3_256\":\"%s\"",
					      hex32((tr & 2u) ? stale : M.t2, hx));
		bl += (size_t)sprintf((char *)body + bl, ",\"x\":\"");
	}
	for (size_t i = 0; i < extra_n && bl < CRED_MAX; i++) {
		if (extra[i] == '\n' && !(flags & F_NEWLINE)) continue;
		body[bl++] = extra[i];
	}
	if (!(flags & F_SIGN_RAW)) {
		/* the validity, last in the body: "issued" ends at a comma, "expires" at the closing brace */
		body[bl++] = '"';
		const unsigned long long from = variant == 5 ? issued * 10 : issued; /* 5: eleven digits, same lifetime */

		if (variant != 1) bl += (size_t)sprintf((char *)body + bl, ",\"issued\":%llu", from);
		if (variant == 4) bl += (size_t)sprintf((char *)body + bl, ",\"expires\":%llu", from + life);
		if (variant == 6) bl += (size_t)sprintf((char *)body + bl, ",\"expires\":\"%llu\"", from + life);
		else if (variant != 2)
			bl += (size_t)sprintf((char *)body + bl, ",\"expires\":%llu",
					      from + (variant == 3 ? 0 : variant == 7 ? 86401 : life));
		body[bl++] = '}';
	}
	/* the gateway's signature over "aegis-credential-v1\0" || body; cred = body || '\n' || signature */
	memcpy(msg, CRED_LABEL, sizeof(CRED_LABEL));
	memcpy(msg + sizeof(CRED_LABEL), body, bl);
	if (aegis_mldsa_signature_internal(s, msg, sizeof(CRED_LABEL) + bl, pre, 2, rnd, gw_sec, 0) != 0)
		DIE("gateway sign");
	memcpy(cred, body, bl);
	cred[bl] = '\n';
	memcpy(cred + bl + 1, s, SIG_LEN);
	cl = bl + 1 + SIG_LEN;
	if (flags & F_BAD_SIG) cred[bl + 1 + (n ? p[n - 1] : 0u) * 13u % SIG_LEN] ^= 0x01;
	if (flags & F_BAD_CT) ctl--;
	o = line + sprintf(line, "PQKEMFIN ");
	o = hexs(ct, ctl, o);
	*o++ = ' ';
	o = hexs(cred, cl, o);
	if ((size_t)(o - line) > AEGIS_LINE_MAX) return; /* the partition would refuse it before the protocol code */
	rep = call((const uint8_t *)line, (size_t)(o - line));

	lifetime = model_lifetime(body, bl);
	bound = pending && !fz_clock_fail && ctl == KEM_CT_LEN && cl <= CRED_MAX && !memchr(body, '\n', bl) &&
		!(flags & F_BAD_SIG) && contains(body, bl, "kem_ct_sha3_256", h_ct) &&
		contains(body, bl, "kem_ek_sha3_256", h_ek) && contains(body, bl, "endpoint_pq_pk_sha256", dev_pk_sha256) &&
		(!M.bound || contains(body, bl, "transcript_sha3_256", M.t2));
	expect = bound && lifetime != 0;
	if (!pending) {
		if (strcmp(rep, "ERR cred no-exchange")) DIE("PQKEMFIN without an exchange: %.40s", rep);
	} else if (fz_clock_fail) {
		if (strcmp(rep, "ERR clock")) DIE("PQKEMFIN without a clock: %.40s", rep);
		/* refused before the exchange was used: it stays pending */
	} else if (ctl != KEM_CT_LEN || cl > CRED_MAX) {
		if (strcmp(rep, "ERR bad-request")) DIE("bad lengths: %.40s", rep);
		/* the same */
	} else {
		M.pending = 0;
		if (expect != !strncmp(rep, "PQKEMOK ", 8))
			DIE("credential %s, but the model says %s: %.60s", expect ? "refused" : "accepted",
			    expect ? "valid" : "invalid", rep);
		if (bound && !lifetime && strcmp(rep, "ERR cred validity")) DIE("no lifetime: %.40s", rep);
		/* the transcript is the last thing a credential is refused for before its validity */
		if (M.bound && !bound && !(flags & F_BAD_SIG) && !memchr(body, '\n', bl) &&
		    contains(body, bl, "kem_ct_sha3_256", h_ct) && contains(body, bl, "kem_ek_sha3_256", h_ek) &&
		    contains(body, bl, "endpoint_pq_pk_sha256", dev_pk_sha256) && strcmp(rep, "ERR cred other-transcript"))
			DIE("a credential that does not name the transcript: %.40s", rep);
	}
	if (expect) {
		uint8_t got[32], tag[32], h_cred[32];
		char *f[4];

		if (fields(rep, f, 4) != 3 || unhexs(f[1], strlen(f[1]), got, 32) || strcmp(f[2], "END")) DIE("PQKEMOK");
		sha3_256(cred, cl, h_cred);
		if (M.bound) {
			uint8_t t3[32];

			sha3v(t3, 4, "aegis-transcript-v2/kem-fin", (size_t)27, M.t2, (size_t)32, h_ct, (size_t)32, h_cred,
			      (size_t)32);
			sha3v(tag, 3, "aegis-confirm-v2", (size_t)16, k, (size_t)32, t3, (size_t)32);
			sha3v(M.session_key, 3, "aegis-session-v2", (size_t)16, k, (size_t)32, t3, (size_t)32);
		} else {
			sha3v(tag, 5, "aegis-confirm-v1", (size_t)16, k, (size_t)32, M.nonce, (size_t)32, h_ct, (size_t)32,
			      h_cred, (size_t)32);
			sha3v(M.session_key, 4, "aegis-session-v1", (size_t)16, k, (size_t)32, M.nonce, (size_t)32, h_ct,
			      (size_t)32);
		}
		if (memcmp(tag, got, 32)) DIE("confirmation tag%s", M.bound ? " of the transcript" : "");
		memcpy(M.cred_hash, h_cred, 32);
		M.session = 1;
		M.expired = 0;
		M.start = fz_now;
		M.limit = lifetime + lifetime / 16;
		M.hb = 0;
	}
	free(rep);
}

static void op_hb(const uint8_t *p, size_t n)
{
	uint8_t nonce[32] = {0}, ctr[8], tag[32], got[32], st[320];
	char line[5 + 64 + 1], *rep, *f[8], want[320];
	struct aegis_kmac km;
	size_t sl;

	memcpy(nonce, p, n < 32 ? n : 32);
	memcpy(line, "PQHB ", 5);
	hexs(nonce, 32, line + 5);
	rep = call((const uint8_t *)line, strlen(line));
	/* the status under the MAC: the platform's text, then the seconds the session has left */
	sl = (size_t)snprintf(want, sizeof(want), "%s;ttl=%llu", status_text,
			      M.session ? (unsigned long long)(M.limit - (fz_now - M.start)) : 0ull);
	if (!M.session) {
		if (strcmp(rep, model_no_session())) DIE("PQHB without a session: %.40s", rep);
	} else if (strlen(status_text) >= 96) {
		if (strcmp(rep, "ERR status")) DIE("long status: %.40s", rep);
	} else {
		M.hb++;
		if (fields(rep, f, 8) != 5 || strcmp(f[0], "PQHB") || strcmp(f[4], "END") ||
		    unhexs(f[1], strlen(f[1]), st, sl) || memcmp(st, want, sl) ||
		    unhexs(f[2], strlen(f[2]), ctr, 8) || unhexs(f[3], strlen(f[3]), got, 32))
			DIE("PQHB reply");
		for (int i = 0; i < 8; i++) {
			if (ctr[i] != (uint8_t)(M.hb >> (8 * i))) DIE("heartbeat counter");
		}
		aegis_kmac256_init(&km, M.session_key, 32, (const uint8_t *)"aegis-hb-v2", 11);
		aegis_kmac256_update(&km, nonce, 32);
		aegis_kmac256_update(&km, ctr, 8);
		aegis_kmac256_update(&km, (const uint8_t *)want, sl);
		aegis_kmac256_final(&km, tag, 32);
		if (memcmp(tag, got, 32)) DIE("heartbeat tag");
	}
	free(rep);
}

static void op_chal(const uint8_t *p, size_t n)
{
	static uint8_t cl[CLAIMS_MAX], sig[SIG_LEN];
	uint8_t ch[32] = {0};
	char line[7 + 64 + 1], *rep, *f[8];
	unsigned len;

	memcpy(ch, p, n < 32 ? n : 32);
	memcpy(line, "PQCHAL ", 7);
	hexs(ch, 32, line + 7);
	rep = call((const uint8_t *)line, strlen(line));
	if (!strcmp(rep, "ERR sign")) {
		model_quote(0, ch, NULL, 0);
	} else {
		if (fields(rep, f, 8) != 6 || strcmp(f[0], "PQTOKEN") || sscanf(f[1], "%u", &len) != 1 ||
		    len > CLAIMS_MAX || unhexs(f[2], strlen(f[2]), cl, len) || unhexs(f[4], strlen(f[4]), sig, SIG_LEN) ||
		    strcmp(f[5], "END"))
			DIE("PQTOKEN reply");
		model_quote(1, ch, cl, len);
		if (dev_verify(QUOTE_LABEL, cl, len, sig) != 0) DIE("quote not signed by the device key");
		if (!memmem(cl, len, ch, 32)) DIE("challenge not in the claims");
		if (!memmem(cl, len, "aegis-rw612-tfm-v1", 18)) DIE("profile not in the claims");
	}
	free(rep);
}

static void op_session(void)
{
	uint8_t id[32], got[32], h[32];
	char *rep, *f[5];

	rep = call((const uint8_t *)"PQSESSION", 9);
	if (!M.session) {
		if (strcmp(rep, model_no_session())) DIE("PQSESSION without a session: %.40s", rep);
	} else {
		if (fields(rep, f, 5) != 4 || unhexs(f[1], strlen(f[1]), got, 32) || unhexs(f[2], strlen(f[2]), h, 32))
			DIE("PQSESSION reply");
		sha3v(id, 2, "aegis-session-id-v1", (size_t)19, M.session_key, (size_t)32);
		if (memcmp(id, got, 32) || memcmp(h, M.cred_hash, 32)) DIE("session id or credential hash");
	}
	free(rep);
}

int LLVMFuzzerInitialize(int *argc, char ***argv)
{
	uint8_t gseed[32], dseed[32], root[32];

	(void)argc; (void)argv;
	memset(gseed, 0x47, 32);
	memset(dseed, 0xd5, 32);
	memset(root, 0x7e, 32);
	if (aegis_mldsa_keypair_internal(gw_pub, gw_sec, gseed) != 0) abort();
	rng_state = 1;
	if (aegis_proto_init(&platform, dseed, root, gw_pub) != 0) abort();
	dev_pk = aegis_proto_pk();
	sha256(dev_pk, PK_LEN, dev_pk_sha256);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	size_t i = 0;
	int ops = 0;

	/* a fresh device state for every input (the file's own statics; the key stays) */
	kem_pending = 0; session_ready = 0; hb_counter = 0; kem_counter = 0;
	quote_ready = 0; kem_bound = 0;
	session_expired = 0; session_start = session_limit = 0;
	memset(session_key, 0, sizeof(session_key));
	memset(&M, 0, sizeof(M));
	fz_now = 1000;
	fz_clock_fail = 0;
	rng_state = 0x9e3779b97f4a7c15ull;
	rng_skip = rng_fail = 0;
	strcpy(status_text, "requests=1;stack=na;clk=ref;fw=rw612-tfm-0.2.2");

	while (i + 3 <= size && ops++ < 24) {
		uint8_t op = data[i] & 7, sel = data[i] >> 3;
		size_t n = (size_t)data[i + 1] | (size_t)data[i + 2] << 8;
		const uint8_t *p = data + i + 3;

		if (n > size - i - 3) n = size - i - 3;
		i += 3 + n;
		switch (op) {
		case 0: op_raw(p, n); break;
		case 1: op_kem_init(p, n); break;
		case 2: op_kem_fin(sel, p, n); break;
		case 3: op_hb(p, n); break;
		case 4: op_chal(p, n); break;
		case 5: op_session(); break;
		case 6: {
			uint64_t d = 0;

			for (size_t j = 0; j < 4 && j < n; j++) d |= (uint64_t)p[j] << (8 * j);
			if (sel == 1) fz_now += d;
			else if (sel == 2) fz_clock_fail = n ? p[0] & 1 : 1;
			else if (sel == 3) fz_now -= d < fz_now ? d : fz_now;
			else { rng_skip = n ? p[0] & 3 : 0; rng_fail = n > 1 ? p[1] & 3 : 1; }
			break;
		}
		case 7: {
			/* the partition's status is never empty ("requests=..."), so neither is this one */
			size_t l = n < sizeof(status_text) - 1 ? n : sizeof(status_text) - 1;

			if (l == 0) break;

			memcpy(status_text, p, l);
			status_text[l] = 0;
			for (size_t j = 0; j < l; j++) {
				if (status_text[j] < 0x20 || status_text[j] > 0x7e) status_text[j] = 'x';
			}
			break;
		}
		}
	}
	return 0;
}
