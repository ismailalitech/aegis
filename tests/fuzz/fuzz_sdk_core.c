/* SPDX-License-Identifier: Apache-2.0
 *
 * The one libFuzzer harness for the Prover SDK's protocol core (sdk/src/aegis_proto.c), built with AddressSanitizer
 * and UndefinedBehaviorSanitizer. Build and run: tests/fuzz/run.sh. Every device family runs this core, so this
 * harness and its corpus (seeds/) are shared by all of them; what is a port's own is fuzzed with that port
 * (stm32/fuzz_stm32_partition.c: PSA messages, the session clock's hardware, the stack mark).
 *
 * The core is driven through the reference port (sdk/ports/host): aegis_host_prepare, aegis_host_start, the port's
 * identity functions and status text, and its two test seams for the random bytes and the clock, so that an input
 * replays exactly. Two things are the harness's own instead of the port's: the measurements (the port hashes files;
 * here they are the fixed SPE and NSPE values of the harness this one replaces, so its answers are byte for byte
 * the same), and the work buffer, which is given its exact size on the heap so that the sanitizer sees a write past
 * it.
 *
 * Random requests alone stop at the verifier's signature, so the harness also plays the verifier (the gateway): it
 * holds the pinned key, encapsulates to the device's ML-KEM key and signs credentials whose body the input changes.
 *
 * An input is a list of operations, each "op | selector << 3, length (2 bytes, little-endian), payload", at most 24.
 * Without a prefix it is in the first format (the RW612 harness's): the line transport, one count of the clock a
 * second, every corpus file from before the SDK means what it meant. With the prefix "AEG\x01" and one configuration
 * byte it picks a personality:
 *   bit 0  the front: 0 text lines (aegis_prover_handle_line), 1 the binary operations (aegis_prover_quote and the
 *          others, called directly, with the STM32 harness's operations)
 *   bit 1  the clock counts 250 times a second instead of once
 *   bit 2  AEGIS_COMPAT_HB_COUNTER_FROM_BOOT
 *   bit 3  AEGIS_COMPAT_CRED_WITHOUT_ENDPOINT
 *   bit 4  the evidence is the platform's token (a stand-in that carries the challenge) instead of the claims
 *   bit 5  the identity key is held by the platform (the port's identity functions)
 *   bit 6  the smallest work buffer, AEGIS_WORK_MIN: a credential body over 1214 bytes does not fit
 * 0x5F is the STM32H573 partition's configuration; seeds/stm32-* are that family's seeds under it (merge_seeds.py).
 *
 * The line front (the first format, and bit 0 clear):
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
 *   5  PQSESSION; with the prefix and upper bits in the op byte, the last accepted PQKEMFIN sent again instead
 *   6  after K good random draws, the next N fail (K, N from the payload); with upper bits in the op byte, the
 *      session clock instead: 1 forward by the payload's seconds (32 bits), 2 it fails or works again, 3 backwards.
 *      With the prefix also: payload byte 1, bit 2 makes the failing draws report success and write zero bytes;
 *      4 a reset (the device's protocol state as after a start; the random generator goes on), 5 the clock forward
 *      by the payload's counts, 6 the platform gives no evidence the next N times
 *   7  set the platform's status text (from the payload; never empty, as on the board)
 * The binary front (bit 0 set), with the STM32 harness's operations, as far as they are the core's:
 *   0  a raw message: type, two input sizes, two output sizes, then the input bytes. What that family's transport
 *      refuses for its sizes never reaches the core (only the clock is read: aegis_prover_poll); type 4 with a
 *      ciphertext of the right length is aegis_prover_kem_finish with a credential of any length, 0 to 8191 bytes;
 *      type 6 is aegis_prover_heartbeat with any status and a status buffer of the second output size (none: the
 *      status is MACed as given, AEGIS_HB_RAW)
 *   1  aegis_prover_kem_init with a nonce from the payload
 *   2  aegis_prover_kem_finish with a credential built as above (a ciphertext "one byte short" is here one with a
 *      byte changed: the operation takes exactly 1088 bytes)
 *   3  aegis_prover_heartbeat with a nonce and status text from the payload; the op byte's upper bits pick the
 *      status buffer: 0 room for the text and ";ttl=", 1 none (AEGIS_HB_RAW), 2 exactly what is needed, else
 *      5 * bits; bit 4 of them: AEGIS_HB_RAW with that buffer
 *   4  aegis_prover_quote with a challenge from the payload
 *   5  aegis_prover_session; with upper bits in the op byte, the last accepted credential sent again byte for byte
 *   6  the random draws as above (payload byte 1, bit 2: zero bytes); with upper bits, the clock, a 32-bit counter
 *      given to the core as the STM32 port gives its own (a wrap is a step forward beyond any lifetime): 1 forward
 *      by the payload's seconds, 2 by its counts, 3 back by its counts, 4 one thing goes wrong with the clock's
 *      hardware (the STM32 harness's twelve faults: the register clock changes nothing, a wrap flag is a wrap, any
 *      other is a clock that fails from then on), 5 a reset, on clock hardware from the payload (as there: byte 0
 *      and 1 say whether the clock starts, bytes 2-5 are the counter), 6 the platform gives no evidence the next N
 *      times, 7 the clock fails or works again
 *   7  aegis_prover_public_key
 *
 * Besides the sanitizers, every answer is checked against a model of the protocol that shares no code with the
 * core but SHA3-256 (the harness aborts when they differ):
 *   - every reply line fits, ends at the returned length and is printable ASCII; an operation that fails leaves its
 *     outputs as they were (sdk/include/aegis_sdk.h);
 *   - a credential is accepted if and only if an exchange is pending, the clock works, the lengths are allowed, the
 *     body has no newline and fits the work buffer, the gateway's ML-DSA-65 signature over it is valid, it names
 *     SHA3-256(ct), SHA3-256(ek) of the pending exchange and (without the compatibility flag) SHA-256(device pk),
 *     and it carries "issued" and "expires" once each with a lifetime of 1 to 86400 seconds; and a refusal is the
 *     first of these that fails, in this order: no exchange, clock, lengths (the exchange stays pending for these
 *     three), signature, other exchange, other endpoint, other key, other transcript, validity;
 *   - aegis_prover_kem_pending and aegis_prover_session_state say what the operation after them then answers;
 *   - a session answers until the clock shows its lifetime plus a sixteenth after the accepted credential, and from
 *     that count on, or when the clock fails or runs backwards, the session requests answer "expired" (before any
 *     session: "no session"), whatever came in between; every heartbeat status ends with the seconds left, rounded
 *     up;
 *   - a raw request is never accepted as a credential, and neither is a recorded one sent again, also after a reset;
 *     no ML-KEM key is issued twice, whatever the nonces and resets (-DFZ_STALE_RNG builds a generator that starts
 *     again at a reset, to show that this check then fires);
 *   - an exchange is refused for want of randomness exactly when the draw for its key fails or gives zero bytes, or
 *     the draw for its signature fails, and a quote when its draw fails; a refused exchange leaves none pending;
 *   - the confirmation tag, the session id, the credential hash and every heartbeat tag are what the gateway
 *     computes; the heartbeat counter counts up by one, from the session's start or (the flag) from the device's; a
 *     status buffer too small for the text and its ";ttl=" is refused and not counted;
 *   - every quote and KEM key is signed by the device key, and the quote carries the challenge;
 *   - one transcript: an exchange continues a quote if and only if its nonce is the challenge of the last quote that
 *     was answered since the start and no exchange has continued it yet. The KEM key's signature is then over
 *     "aegis-kem-init-v2" and T2 = H(kem-init || H(quote || challenge || SHA3(evidence)) || ek), and otherwise over
 *     "aegis-kem-init-v1" and nonce || ek: never the other one. Such an exchange accepts a credential only if it
 *     also names T2, and its tag and session key are the transcript's;
 *   - after every operation the core's own state (session, pending exchange, kept quote) is the model's.
 */
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* the file under test, included so the harness can reach its state between inputs; it is not changed */
#include "aegis_proto.c"
#include "aegis_port_host.h"
#include "fz_trace.h"

#define DIE(...) do { fprintf(stderr, "ORACLE: " __VA_ARGS__); fputc('\n', stderr); abort(); } while (0)
#define CRED_MAX     AEGIS_CRED_MAX
#define EV_MAX       AEGIS_HOST_EVIDENCE_MAX
#define FZ_TOKEN_LEN 120u
#define RNG_SEED     0x9e3779b97f4a7c15ull
#define PROFILE      "aegis-rw612-tfm-v1"

static const uint8_t MAGIC[4] = {'A', 'E', 'G', 1};
static uint8_t gw_pub[PK_LEN], gw_sec[MLDSA_SECRETKEYBYTES(65)];
static const uint8_t *dev_pk;
static uint8_t dev_pk_sha256[32];

/* this input's personality */
static struct {
	int magic, binary, hb_from_boot, no_endpoint, token, platkey;
	uint32_t hz;
	size_t work_len;
} C;
/* one device per way of starting the core (configuration bits 4 to 6), all with the same key */
static struct aegis_host hosts[8];
static struct aegis_prover *P;

/* ---- the platform: a deterministic generator (an input replays exactly), failures on demand ---- */
static uint64_t rng_state;
static unsigned rng_skip, rng_fail; /* after rng_skip good draws, the next rng_fail draws fail */
static int rng_zero;                /* the failing draws report success and write zero bytes */
static unsigned ev_fail;            /* the platform gives no evidence the next ev_fail times */
static char status_text[256];

static int fz_random(uint8_t *out, size_t n)
{
	if (rng_skip) {
		rng_skip--;
	} else if (rng_fail) {
		rng_fail--;
		if (!rng_zero) return -1;
		memset(out, 0, n);
		return 0;
	}
	for (size_t i = 0; i < n; i++) {
		rng_state ^= rng_state << 13; rng_state ^= rng_state >> 7; rng_state ^= rng_state << 17;
		out[i] = (uint8_t)(rng_state >> 24);
	}
	return 0;
}

/* what the k-th draw from now will give: 0 random bytes, 1 an error, 2 success and zero bytes */
static int rng_next(unsigned k)
{
	if (k < rng_skip || k - rng_skip >= rng_fail) return 0;
	return rng_zero ? 2 : 1;
}

static int fz_measurements(void *user, const struct aegis_measurement **list, size_t *count)
{
	static struct aegis_measurement m[2];

	(void)user;
	if (ev_fail) {
		ev_fail--;
		return -1;
	}
	m[0].label = "SPE";
	memset(m[0].value, 0x5e, 32);
	snprintf(m[0].desc, sizeof(m[0].desc), "SHA256 of the secure partition (%u bytes)", 651264u);
	m[1].label = "NSPE";
	memset(m[1].value, 0x95, 32);
	snprintf(m[1].desc, sizeof(m[1].desc), "SHA256 of the non-secure partition (%u bytes)", 3145728u);
	*list = m;
	*count = 2;
	return 0;
}

/* the platform's own token: a stand-in that carries the challenge */
static int fz_evidence(void *user, const uint8_t challenge[32], uint8_t *out, size_t cap, size_t *len)
{
	(void)user;
	if (ev_fail) {
		ev_fail--;
		return -1;
	}
	if (cap < FZ_TOKEN_LEN) return -1;
	memset(out, 0xa7, FZ_TOKEN_LEN);
	memcpy(out, "FZTOKEN", 7);
	memcpy(out + 8, challenge, 32);
	*len = FZ_TOKEN_LEN;
	return 0;
}

/* the session clock: the harness moves it and makes it fail */
static uint64_t fz_now;
static int fz_clock_fail;

static int fz_clock(uint64_t *now)
{
	if (fz_clock_fail) return -1;
	*now = fz_now;
	return 0;
}

/* The binary front's clock is a 32-bit counter, given to the core as the STM32 port gives its own: the counts, and
 * above them the wraps, two to the 33rd each, so that a reading after a wrap is further from every reading before it
 * than any session may live. */
static void clk_advance(uint64_t counts)
{
	uint32_t c = (uint32_t)fz_now;
	uint64_t wraps = fz_now >> 33;

	if (counts > 0xFFFFFFFFu - c) wraps++;
	fz_now = wraps << 33 | (uint32_t)(c + (uint32_t)counts);
}

static void clk_back(uint32_t counts)
{
	fz_now = (fz_now >> 33) << 33 | (uint32_t)((uint32_t)fz_now - counts);
}

/* ---- the model: what the gateway knows ---- */
static struct {
	int pending;               /* an exchange was started and no credential has used it */
	uint8_t ek[KEM_EK_LEN], nonce[32];
	int quote;                 /* a quote was answered and no exchange has continued it */
	uint8_t q_ch[32], q_t1[32];
	int bound;                 /* the pending exchange continues a quote; its T2 */
	uint8_t t2[32];
	int session;
	int expired;               /* the last session was ended by the clock */
	uint64_t start, limit;     /* the clock when the session started; the counts it may live */
	uint8_t session_key[32], cred_hash[32];
	uint64_t hb;
} M;

/* What someone on the network keeps: the last accepted credential with its ciphertext, and (as hashes) every KEM
 * key issued. Per input, not per reset of the device. */
static struct {
	int have;
	uint8_t ct[KEM_CT_LEN], cred[CRED_MAX];
	size_t cred_len;
	uint8_t ek_hash[64][32];
	unsigned eks;
} seen;

/* what any request does first: a session past its end, or whose age the clock cannot give, is gone */
static void model_sweep(void)
{
	if (M.session && (fz_clock_fail || fz_now < M.start || fz_now - M.start >= M.limit)) {
		M.session = 0;
		M.expired = 1;
	}
}

static int model_no_session(void)
{
	return M.expired ? AEGIS_ERR_EXPIRED : AEGIS_ERR_NO_SESSION;
}

/* the seconds the session has left, rounded up */
static unsigned long long model_ttl(void)
{
	return M.session ? (unsigned long long)((M.limit - (fz_now - M.start) + C.hz - 1) / C.hz) : 0ull;
}

/* the reply line of a refusal (the model's own table) */
static const char *line_of(int rc)
{
	switch (rc) {
	case AEGIS_ERR_BAD_REQUEST: return "ERR bad-request";
	case AEGIS_ERR_EVIDENCE: return "ERR evidence";
	case AEGIS_ERR_RNG: return "ERR rng";
	case AEGIS_ERR_SIGN_RNG: case AEGIS_ERR_SIGN: return "ERR sign";
	case AEGIS_ERR_KEM: return "ERR kem";
	case AEGIS_ERR_NO_EXCHANGE: return "ERR cred no-exchange";
	case AEGIS_ERR_CLOCK: return "ERR clock";
	case AEGIS_ERR_CRED_SIGNATURE: return "ERR cred signature";
	case AEGIS_ERR_CRED_OTHER_EXCHANGE: return "ERR cred other-exchange";
	case AEGIS_ERR_CRED_OTHER_ENDPOINT: return "ERR cred other-endpoint";
	case AEGIS_ERR_CRED_OTHER_KEY: return "ERR cred other-key";
	case AEGIS_ERR_CRED_OTHER_TRANSCRIPT: return "ERR cred other-transcript";
	case AEGIS_ERR_CRED_VALIDITY: return "ERR cred validity";
	case AEGIS_ERR_NO_SESSION: return "ERR pq no-session";
	case AEGIS_ERR_EXPIRED: return "ERR pq expired";
	case AEGIS_ERR_STATUS: return "ERR status";
	default: return "ERR internal";
	}
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

static size_t u16(const uint8_t *p, size_t n, size_t i) { return i + 1 < n ? (size_t)p[i] | (size_t)p[i + 1] << 8 : 0; }

static int dev_verify(const char *label, const uint8_t *m, size_t n, const uint8_t *s)
{
	static uint8_t buf[64 + KEM_EK_LEN + EV_MAX];
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

static void issued(const uint8_t *ek)
{
	uint8_t h[32];

	sha3_256(ek, KEM_EK_LEN, h);
	for (unsigned i = 0; i < seen.eks; i++)
		if (!memcmp(seen.ek_hash[i], h, 32)) DIE("the KEM key of exchange %u was issued again", i + 1);
	if (seen.eks < 64) memcpy(seen.ek_hash[seen.eks++], h, 32);
}

/* ---- one transcript: the model's own reading of common/transcript.py ---- */
/* a well-formed quote request: whatever it answers, the quote before it can no longer be continued */
static void model_quote(int answered, const uint8_t ch[32], const uint8_t *ev, size_t len)
{
	uint8_t h[32];

	M.quote = 0;
	if (!answered) return;
	sha3_256(ev, len, h);
	sha3v(M.q_t1, 3, "aegis-transcript-v2/quote", (size_t)25, ch, (size_t)32, h, (size_t)32);
	memcpy(M.q_ch, ch, 32);
	M.quote = 1;
}

/* a well-formed start of an exchange: does it continue the quote? The quote is used up either way it ends. */
static int model_continues(const uint8_t nonce[32])
{
	int b = M.quote && !memcmp(nonce, M.q_ch, 32);

	if (b) M.quote = 0;
	return b;
}

/* the answered start: its signature is the transcript's if it continues a quote, the first version's if not */
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
	issued(ek);
	if (ek != M.ek) memcpy(M.ek, ek, KEM_EK_LEN);
	memcpy(M.nonce, nonce, 32);
	M.bound = continues;
	M.pending = 1;
}

/* What the start of an exchange answers, from the draws it will make: the key's random bytes, which must be there
 * and not zero, then the signature's. */
static int model_kem_init_result(void)
{
	if (rng_next(0) != 0) return AEGIS_ERR_RNG;
	if (rng_next(1) == 1) return C.platkey ? AEGIS_ERR_SIGN : AEGIS_ERR_SIGN_RNG;
	return AEGIS_OK;
}

/* and a quote: the platform's evidence, then one draw for the signature */
static int model_quote_result(void)
{
	if (ev_fail) return AEGIS_ERR_EVIDENCE;
	if (rng_next(0) == 1) return C.platkey ? AEGIS_ERR_SIGN : AEGIS_ERR_SIGN_RNG;
	return AEGIS_OK;
}

/* What a credential is answered with once its exchange is taken: the model's own reading of it. */
static int model_cred(const uint8_t *ct, const uint8_t *cred, size_t cl, uint64_t *lifetime)
{
	static uint8_t msg[20 + CRED_MAX];
	const uint8_t pre[2] = {0, 0};
	const uint8_t *nl = memchr(cred, '\n', cl);
	uint8_t h_ct[32], h_ek[32];
	size_t bl;

	*lifetime = 0;
	if (!nl) return AEGIS_ERR_CRED_SIGNATURE;
	bl = (size_t)(nl - cred);
	if (cl - bl - 1 != SIG_LEN || 20 + bl > C.work_len) return AEGIS_ERR_CRED_SIGNATURE;
	memcpy(msg, "aegis-credential-v1", 20);
	memcpy(msg + 20, cred, bl);
	if (aegis_mldsa_verify_internal(nl + 1, msg, 20 + bl, pre, 2, gw_pub, 0) != 0) return AEGIS_ERR_CRED_SIGNATURE;
	sha3_256(ct, KEM_CT_LEN, h_ct);
	sha3_256(M.ek, KEM_EK_LEN, h_ek);
	if (!contains(cred, bl, "kem_ct_sha3_256", h_ct)) return AEGIS_ERR_CRED_OTHER_EXCHANGE;
	if (!C.no_endpoint && !contains(cred, bl, "endpoint_pq_pk_sha256", dev_pk_sha256)) return AEGIS_ERR_CRED_OTHER_ENDPOINT;
	if (!contains(cred, bl, "kem_ek_sha3_256", h_ek)) return AEGIS_ERR_CRED_OTHER_KEY;
	if (M.bound && !contains(cred, bl, "transcript_sha3_256", M.t2)) return AEGIS_ERR_CRED_OTHER_TRANSCRIPT;
	*lifetime = model_lifetime(cred, bl);
	return *lifetime ? AEGIS_OK : AEGIS_ERR_CRED_VALIDITY;
}

/* What the end of an exchange answers; ct_ok: the ciphertext has its length. The first three leave the exchange
 * pending, anything after them ends it. */
static int model_finish(const uint8_t *ct, int ct_ok, const uint8_t *cred, size_t cl, uint64_t *lifetime)
{
	*lifetime = 0;
	if (!M.pending) return AEGIS_ERR_NO_EXCHANGE;
	if (fz_clock_fail) return AEGIS_ERR_CLOCK;
	if (!ct_ok || cl == 0 || cl > CRED_MAX) return AEGIS_ERR_BAD_REQUEST;
	M.pending = 0;
	return model_cred(ct, cred, cl, lifetime);
}

/* An accepted credential: the tag the gateway expects, and the session from here on. k is the gateway's own shared
 * secret, from its encapsulation. */
static void model_accept(const uint8_t k[32], const uint8_t *ct, const uint8_t *cred, size_t cl, uint64_t lifetime,
			 uint8_t tag[32])
{
	uint8_t h_ct[32], h_cred[32];

	sha3_256(ct, KEM_CT_LEN, h_ct);
	sha3_256(cred, cl, h_cred);
	if (M.bound) {
		uint8_t t3[32];

		sha3v(t3, 4, "aegis-transcript-v2/kem-fin", (size_t)27, M.t2, (size_t)32, h_ct, (size_t)32, h_cred,
		      (size_t)32);
		sha3v(tag, 3, "aegis-confirm-v2", (size_t)16, k, (size_t)32, t3, (size_t)32);
		sha3v(M.session_key, 3, "aegis-session-v2", (size_t)16, k, (size_t)32, t3, (size_t)32);
	} else {
		sha3v(tag, 5, "aegis-confirm-v1", (size_t)16, k, (size_t)32, M.nonce, (size_t)32, h_ct, (size_t)32, h_cred,
		      (size_t)32);
		sha3v(M.session_key, 4, "aegis-session-v1", (size_t)16, k, (size_t)32, M.nonce, (size_t)32, h_ct,
		      (size_t)32);
	}
	memcpy(M.cred_hash, h_cred, 32);
	memcpy(seen.ct, ct, KEM_CT_LEN);
	memcpy(seen.cred, cred, cl);
	seen.cred_len = cl;
	seen.have = 1;
	M.session = 1;
	M.expired = 0;
	M.start = fz_now;
	M.limit = (lifetime + lifetime / 16) * C.hz;
	if (!C.hb_from_boot) M.hb = 0;
}

/* the heartbeat tag the gateway computes */
static void model_hb_tag(const uint8_t nonce[32], const uint8_t ctr[8], const void *status, size_t sl, uint8_t tag[32])
{
	struct aegis_kmac km;

	aegis_kmac256_init(&km, M.session_key, 32, (const uint8_t *)"aegis-hb-v2", 11);
	aegis_kmac256_update(&km, nonce, 32);
	aegis_kmac256_update(&km, ctr, 8);
	aegis_kmac256_update(&km, status, sl);
	aegis_kmac256_final(&km, tag, 32);
}

/* ---- the gateway's credential, as the input changes it ---- */
#define F_DROP_CT   0x01  /* leave kem_ct_sha3_256 out */
#define F_DROP_EK   0x02
#define F_DROP_PK   0x04
#define F_BAD_SIG   0x08  /* flip one signature bit */
#define F_BAD_CT    0x10  /* a ciphertext one byte short (lines), or with a byte changed (operations) */
#define F_NEWLINE   0x20  /* keep newlines in the added text */
#define F_STALE_EK  0x40  /* name an encapsulation key the device did not make */
#define F_SIGN_RAW  0x80  /* the added text alone is the whole body */

static struct {
	uint8_t ct[KEM_CT_LEN], k[32], flags;
	uint8_t cred[CRED_MAX + 512 + SIG_LEN + 1];
	size_t cl;
} G;

static void gateway_credential(uint8_t sel, const uint8_t *p, size_t n)
{
	static const unsigned lifetimes[4] = {3600, 1, 86400, 40};
	const unsigned variant = sel & 7u, life = lifetimes[(sel >> 3) & 3u];
	const unsigned long long issued_at = 1795000000ull;
	static uint8_t body[CRED_MAX + 512], msg[sizeof(CRED_LABEL) + CRED_MAX + 512], s[SIG_LEN];
	const uint8_t pre[2] = {0, 0};
	uint8_t flags = n ? p[0] : 0, coins[32] = {0}, h_ct[32], h_ek[32], stale[32], rnd[32] = {0};
	const uint8_t *extra = n > 33 ? p + 33 : p;
	size_t extra_n = n > 33 ? n - 33 : 0, bl = 0;
	/* the transcript's name in the credential: there exactly when the exchange continues a quote, unless bit 0 of
	 * payload byte 32 turns that round; bit 1 names another transcript */
	const unsigned tr = n > 32 ? p[32] & 3u : 0u;
	const int name_tr = !(flags & F_SIGN_RAW) && (M.bound ? !(tr & 1u) : (tr & 1u) != 0);

	G.flags = flags;
	if (n > 1) memcpy(coins, p + 1, n - 1 < 32 ? n - 1 : 32);
	if (aegis_mlkem_enc_derand(G.ct, G.k, M.ek, coins) != 0) DIE("encaps");
	sha3_256(G.ct, KEM_CT_LEN, h_ct);
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
		const unsigned long long from = variant == 5 ? issued_at * 10 : issued_at; /* 5: eleven digits, same lifetime */

		body[bl++] = '"';
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
	memcpy(G.cred, body, bl);
	G.cred[bl] = '\n';
	memcpy(G.cred + bl + 1, s, SIG_LEN);
	G.cl = bl + 1 + SIG_LEN;
	if (flags & F_BAD_SIG) G.cred[bl + 1 + (n ? p[n - 1] : 0u) * 13u % SIG_LEN] ^= 0x01;
}

/* ---- the device: a start, and its state against the model's ---- */

/* The protocol state as aegis_prover_init leaves it (the key stays: making it again would only cost time). */
static void device_reset(void)
{
	P->kem_pending = 0; P->session_ready = 0; P->hb_counter = 0; P->kem_counter = 0;
	P->kem_bound = 0;
#if !defined(FZ_QUOTE_OUTLIVES_RESET)
	P->quote_ready = 0; /* RAM: a quote does not outlive a reset. The control build keeps it, to show the model sees it */
#endif
	P->session_expired = 0; P->session_start = P->session_limit = 0;
	memset(P->session_key, 0, sizeof(P->session_key));
	memset(P->cred_hash, 0, sizeof(P->cred_hash));
	memset(P->kem_dk, 0, sizeof(P->kem_dk));
	memset(&M, 0, sizeof(M));
#if defined(FZ_STALE_RNG)
	rng_state = RNG_SEED; /* not a device's generator: the same bytes after every reset */
#endif
}

static void check_state(void)
{
	if (!!P->session_ready != M.session) DIE("the device has %s session, the model has %s", P->session_ready ? "a" : "no",
						 M.session ? "one" : "none");
	if (!P->session_ready && !!P->session_expired != M.expired) DIE("expired: device %d, model %d", P->session_expired, M.expired);
	if (!!P->kem_pending != M.pending) DIE("exchange pending: device %d, model %d", P->kem_pending, M.pending);
	if (!!P->quote_ready != M.quote) DIE("quote kept: device %d, model %d", P->quote_ready, M.quote);
	if (P->kem_pending && !!P->kem_bound != M.bound) DIE("exchange continues a quote: device %d, model %d", P->kem_bound, M.bound);
	if (P->session_ready && memcmp(P->session_key, M.session_key, 32)) DIE("session key");
}

/* ================================== the line front ================================== */

/* one request, as a transport makes it; returns the reply (the caller frees it) */
static char *call(const uint8_t *req, size_t n)
{
	char *line = malloc(n + 1), *out = malloc(AEGIS_REPLY_MAX);
	int r;

	memcpy(line, req, n);
	line[n] = 0;
	model_sweep();
	r = aegis_prover_handle_line(P, line, out, AEGIS_REPLY_MAX);
#if defined(FZ_TRACE)
	fz_trace_line(req, n, out, r);
#endif
	free(line);
	if (r < 0 || (size_t)r >= AEGIS_REPLY_MAX) DIE("reply length %d", r);
	if (strlen(out) != (size_t)r) DIE("reply does not end at its length (%zu, %d)", strlen(out), r);
	for (int i = 0; i < r; i++) {
		if (out[i] < 0x20 || out[i] > 0x7e) DIE("byte 0x%02x in reply", (unsigned char)out[i]);
	}
	return out;
}

static void l_raw(const uint8_t *p, size_t n)
{
	char *req, *t[5], *rep, *f[8];
	int tn = 0;
	uint8_t nonce[32];

	if (n == 0 || n > AEGIS_LINE_MAX) return; /* a transport refuses these before the protocol code */
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
		static uint8_t ev[EV_MAX];
		unsigned len = 0;
		int answered = !strncmp(rep, "PQTOKEN ", 8);

		if (answered && (fields(rep, f, 8) != 6 || sscanf(f[1], "%u", &len) != 1 || len > EV_MAX ||
				 unhexs(f[2], strlen(f[2]), ev, len)))
			DIE("malformed PQTOKEN");
		model_quote(answered, nonce, ev, len);
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

static void l_kem_init(const uint8_t *p, size_t n)
{
	static uint8_t sig[SIG_LEN];
	uint8_t nonce[32] = {0};
	char line[10 + 64 + 1], *f[8], *rep;
	const int want = model_kem_init_result();
	int continues;

	memcpy(nonce, p, n < 32 ? n : 32);
	memcpy(line, "PQKEMINIT ", 10);
	hexs(nonce, 32, line + 10);
	rep = call((const uint8_t *)line, strlen(line));
	continues = model_continues(nonce);
	M.pending = 0; /* refused or not: no older exchange is left pending, not even half of one */
	if (want != AEGIS_OK) {
		if (strcmp(rep, line_of(want))) DIE("PQKEMINIT: %.40s, the model says %s", rep, line_of(want));
		free(rep);
		return;
	}
	if (fields(rep, f, 8) != 6 || strcmp(f[0], "PQKEMEK") || strcmp(f[5], "END") ||
	    unhexs(f[2], strlen(f[2]), M.ek, KEM_EK_LEN) || unhexs(f[4], strlen(f[4]), sig, SIG_LEN))
		DIE("PQKEMINIT reply");
	model_kem_key(continues, nonce, M.ek, sig);
	free(rep);
}

/* PQKEMFIN with this ciphertext (ctl bytes of it) and credential; k: the gateway's shared secret, or NULL for a
 * request that must not be accepted whatever it holds (a recorded one) */
static void l_finish(const uint8_t *ct, size_t ctl, const uint8_t *cred, size_t cl, const uint8_t *k)
{
	static char line[2 * (KEM_CT_LEN + CRED_MAX + 512 + SIG_LEN + 1) + 32];
	uint64_t lifetime;
	char *o, *rep;
	int want;

	o = line + sprintf(line, "PQKEMFIN ");
	o = hexs(ct, ctl, o);
	*o++ = ' ';
	o = hexs(cred, cl, o);
	if ((size_t)(o - line) > AEGIS_LINE_MAX) return; /* a transport would refuse it before the protocol code */
	rep = call((const uint8_t *)line, (size_t)(o - line));
	want = model_finish(ct, ctl == KEM_CT_LEN, cred, cl, &lifetime);
	if (want != AEGIS_OK) {
		if (strcmp(rep, line_of(want))) DIE("PQKEMFIN: %.60s, the model says %s", rep, line_of(want));
	} else {
		uint8_t got[32], tag[32];
		char *f[4];

		if (k == NULL) DIE("a recorded PQKEMFIN was accepted again: the old session is back");
		if (strncmp(rep, "PQKEMOK ", 8)) DIE("credential refused, but the model says valid: %.60s", rep);
		if (fields(rep, f, 4) != 3 || unhexs(f[1], strlen(f[1]), got, 32) || strcmp(f[2], "END")) DIE("PQKEMOK");
		model_accept(k, ct, cred, cl, lifetime, tag);
		if (memcmp(tag, got, 32)) DIE("confirmation tag%s", M.bound ? " of the transcript" : "");
	}
	free(rep);
}

static void l_kem_fin(uint8_t sel, const uint8_t *p, size_t n)
{
	gateway_credential(sel, p, n);
	l_finish(G.ct, (G.flags & F_BAD_CT) ? KEM_CT_LEN - 1 : KEM_CT_LEN, G.cred, G.cl, G.k);
}

static void l_hb(const uint8_t *p, size_t n)
{
	uint8_t nonce[32] = {0}, ctr[8], tag[32], got[32], st[320];
	char line[5 + 64 + 1], *rep, *f[8], want[320];
	size_t sl;

	memcpy(nonce, p, n < 32 ? n : 32);
	memcpy(line, "PQHB ", 5);
	hexs(nonce, 32, line + 5);
	rep = call((const uint8_t *)line, strlen(line));
	/* the status under the MAC: the platform's text, then the seconds the session has left */
	sl = (size_t)snprintf(want, sizeof(want), "%s;ttl=%llu", status_text, model_ttl());
	if (!M.session) {
		if (strcmp(rep, line_of(model_no_session()))) DIE("PQHB without a session: %.40s", rep);
	} else if (strlen(status_text) >= AEGIS_STATUS_MAX) {
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
		model_hb_tag(nonce, ctr, want, sl, tag);
		if (memcmp(tag, got, 32)) DIE("heartbeat tag");
	}
	free(rep);
}

/* what the evidence of an answered quote must hold */
static void check_evidence(const uint8_t ch[32], const uint8_t *ev, size_t len)
{
	if (C.token) {
		if (len != FZ_TOKEN_LEN || memcmp(ev, "FZTOKEN", 7) || memcmp(ev + 8, ch, 32)) DIE("the platform's token was changed");
	} else {
		if (!memmem(ev, len, ch, 32)) DIE("challenge not in the claims");
		if (!memmem(ev, len, PROFILE, sizeof(PROFILE) - 1)) DIE("profile not in the claims");
		if (!memmem(ev, len, dev_pk_sha256, 32)) DIE("the key's hash not in the claims");
	}
}

static void l_chal(const uint8_t *p, size_t n)
{
	static uint8_t ev[EV_MAX], sig[SIG_LEN];
	uint8_t ch[32] = {0};
	char line[7 + 64 + 1], *rep, *f[8];
	const int want = model_quote_result();
	unsigned len;

	memcpy(ch, p, n < 32 ? n : 32);
	memcpy(line, "PQCHAL ", 7);
	hexs(ch, 32, line + 7);
	rep = call((const uint8_t *)line, strlen(line));
	if (want != AEGIS_OK) {
		if (strcmp(rep, line_of(want))) DIE("PQCHAL: %.40s, the model says %s", rep, line_of(want));
		model_quote(0, ch, NULL, 0);
	} else {
		if (fields(rep, f, 8) != 6 || strcmp(f[0], "PQTOKEN") || sscanf(f[1], "%u", &len) != 1 ||
		    len > EV_MAX || unhexs(f[2], strlen(f[2]), ev, len) || unhexs(f[4], strlen(f[4]), sig, SIG_LEN) ||
		    strcmp(f[5], "END"))
			DIE("PQTOKEN reply");
		model_quote(1, ch, ev, len);
		if (dev_verify(QUOTE_LABEL, ev, len, sig) != 0) DIE("quote not signed by the device key");
		check_evidence(ch, ev, len);
	}
	free(rep);
}

static void l_session(void)
{
	uint8_t id[32], got[32], h[32];
	char *rep, *f[5];

	rep = call((const uint8_t *)"PQSESSION", 9);
	if (!M.session) {
		if (strcmp(rep, line_of(model_no_session()))) DIE("PQSESSION without a session: %.40s", rep);
	} else {
		if (fields(rep, f, 5) != 4 || unhexs(f[1], strlen(f[1]), got, 32) || unhexs(f[2], strlen(f[2]), h, 32))
			DIE("PQSESSION reply");
		sha3v(id, 2, "aegis-session-id-v1", (size_t)19, M.session_key, (size_t)32);
		if (memcmp(id, got, 32) || memcmp(h, M.cred_hash, 32)) DIE("session id or credential hash");
	}
	free(rep);
}

static void set_rng(const uint8_t *p, size_t n, int zeros)
{
	rng_skip = n ? p[0] & 3 : 0;
	rng_fail = n > 1 ? p[1] & 3 : 1;
	rng_zero = zeros && n > 1 && (p[1] & 4);
}

static void line_op(uint8_t op, uint8_t sel, const uint8_t *p, size_t n)
{
	switch (op) {
	case 0: l_raw(p, n); break;
	case 1: l_kem_init(p, n); break;
	case 2: l_kem_fin(sel, p, n); break;
	case 3: l_hb(p, n); break;
	case 4: l_chal(p, n); break;
	case 5:
		if (C.magic && sel) {
			if (seen.have) l_finish(seen.ct, KEM_CT_LEN, seen.cred, seen.cred_len, NULL);
		} else {
			l_session();
		}
		break;
	case 6: {
		uint64_t d = 0;

		for (size_t j = 0; j < 4 && j < n; j++) d |= (uint64_t)p[j] << (8 * j);
		if (sel == 1) fz_now += d * C.hz;
		else if (sel == 2) fz_clock_fail = n ? p[0] & 1 : 1;
		else if (sel == 3) fz_now -= d * C.hz < fz_now ? d * C.hz : fz_now;
		else if (C.magic && sel == 4) device_reset();
		else if (C.magic && sel == 5) fz_now += d;
		else if (C.magic && sel == 6) ev_fail = n ? p[0] & 3 : 1;
		else set_rng(p, n, C.magic);
		break;
	}
	case 7: {
		/* a device's status is never empty ("requests=..."), so neither is this one */
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

/* ================================== the binary front ================================== */

static const uint8_t SENTINEL[1];

#if defined(FZ_TRACE)
#define TRACE_OP(name, rc, a, an, b, bn) fz_trace_op(name, rc, (rc) == AEGIS_OK ? (const void *)(a) : NULL, (rc) == AEGIS_OK ? (an) : 0, \
						     (rc) == AEGIS_OK ? (const void *)(b) : NULL, (rc) == AEGIS_OK ? (bn) : 0)
#else
#define TRACE_OP(name, rc, a, an, b, bn) ((void)0)
#endif

static int untouched(const uint8_t *p, size_t n, uint8_t fill)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] != fill) return 0;
	return 1;
}

static void b_poll(void)
{
	model_sweep();
	aegis_prover_poll(P);
	TRACE_OP("poll", 0, NULL, 0, NULL, 0);
}

static void b_pubkey(void)
{
	const uint8_t *k = aegis_prover_public_key(P);

	if (k == NULL || memcmp(k, dev_pk, PK_LEN)) DIE("aegis_prover_public_key");
	TRACE_OP("public_key", 0, k, PK_LEN, NULL, 0);
}

static void b_quote(const uint8_t ch[32])
{
	const uint8_t *ev = SENTINEL, *sig = SENTINEL;
	const int want = model_quote_result();
	size_t len = 0x5a5a;
	uint8_t *c = malloc(32);
	int rc;

	memcpy(c, ch, 32);
	model_sweep();
	rc = aegis_prover_quote(P, c, &ev, &len, &sig);
	TRACE_OP("quote", rc, ev, len, sig, SIG_LEN);
	if (rc != want) DIE("aegis_prover_quote: %d, the model says %d", rc, want);
	if (rc != AEGIS_OK) {
		if (ev != SENTINEL || sig != SENTINEL || len != 0x5a5a) DIE("a refused quote wrote its outputs");
		model_quote(0, ch, NULL, 0);
	} else {
		if (len == 0 || len > C.work_len - AEGIS_WORK_QUOTE_HEAD) DIE("evidence of %zu bytes", len);
		model_quote(1, ch, ev, len);
		if (dev_verify(QUOTE_LABEL, ev, len, sig) != 0) DIE("quote not signed by the device key");
		check_evidence(ch, ev, len);
	}
	free(c);
}

static void b_kem_init(const uint8_t nonce[32])
{
	const uint8_t *ek = SENTINEL, *sig = SENTINEL;
	const int want = model_kem_init_result();
	uint8_t *c = malloc(32);
	int rc, continues;

	memcpy(c, nonce, 32);
	model_sweep();
	rc = aegis_prover_kem_init(P, c, &ek, &sig);
	TRACE_OP("kem_init", rc, ek, KEM_EK_LEN, sig, SIG_LEN);
	continues = model_continues(nonce);
	M.pending = 0;
	if (rc != want) DIE("aegis_prover_kem_init: %d, the model says %d", rc, want);
	if (rc != AEGIS_OK) {
		if (ek != SENTINEL || sig != SENTINEL) DIE("a refused exchange wrote its outputs");
	} else {
		model_kem_key(continues, nonce, ek, sig);
	}
	free(c);
}

/* aegis_prover_kem_finish with exactly these bytes; k as for l_finish; raw: not a credential of the gateway's */
static void b_finish(const uint8_t *ct, const uint8_t *cred, size_t cl, const uint8_t *k, int raw)
{
	uint8_t *c = malloc(KEM_CT_LEN), *d = malloc(cl ? cl : 1), tag[32], want_tag[32];
	uint64_t lifetime;
	int pre, rc, want;

	memcpy(c, ct, KEM_CT_LEN);
	if (cl) memcpy(d, cred, cl);
	memset(tag, 0xee, sizeof(tag));
	model_sweep();
	pre = aegis_prover_kem_pending(P);
	rc = aegis_prover_kem_finish(P, c, d, cl, tag);
	TRACE_OP("kem_finish", rc, tag, 32, NULL, 0);
	want = model_finish(ct, 1, cred, cl, &lifetime);
	if ((want == AEGIS_ERR_NO_EXCHANGE || want == AEGIS_ERR_CLOCK) ? pre != want : pre != AEGIS_OK)
		DIE("aegis_prover_kem_pending: %d before an operation that answers %d", pre, want);
	if (rc != want) DIE("aegis_prover_kem_finish: %d, the model says %d", rc, want);
	if (rc != AEGIS_OK) {
		if (!untouched(tag, 32, 0xee)) DIE("a refused credential wrote the tag");
	} else {
		if (raw) DIE("a raw message was accepted as a credential");
		if (k == NULL) DIE("a recorded credential was accepted again: the old session is back");
		model_accept(k, ct, cred, cl, lifetime, want_tag);
		if (memcmp(tag, want_tag, 32)) DIE("confirmation tag%s", M.bound ? " of the transcript" : "");
	}
	free(c);
	free(d);
}

static void b_kem_fin(uint8_t sel, const uint8_t *p, size_t n)
{
	gateway_credential(sel, p, n);
	if (G.flags & F_BAD_CT) G.ct[(n ? p[n - 1] : 0u) * 7u % KEM_CT_LEN] ^= 0x01;
	b_finish(G.ct, G.cred, G.cl, G.k, 0);
}

static void b_session(void)
{
	uint8_t out[AEGIS_SESSION_LEN], id[32];
	uint32_t ttl = 0xdeadbeef;
	int pre, rc;

	memset(out, 0xee, sizeof(out));
	model_sweep();
	pre = aegis_prover_session_state(P, &ttl);
	rc = aegis_prover_session(P, out);
	TRACE_OP("session", rc, out, sizeof(out), NULL, 0);
	if (pre != rc) DIE("aegis_prover_session_state: %d, then aegis_prover_session: %d", pre, rc);
	if (!M.session) {
		if (rc != model_no_session()) DIE("aegis_prover_session without a session: %d", rc);
		if (!untouched(out, sizeof(out), 0xee) || ttl != 0xdeadbeef) DIE("a refused session query wrote its outputs");
	} else {
		sha3v(id, 2, "aegis-session-id-v1", (size_t)19, M.session_key, (size_t)32);
		if (rc != AEGIS_OK || memcmp(out, id, 32) || memcmp(out + 32, M.cred_hash, 32)) DIE("session id or credential hash");
		if (ttl != model_ttl()) DIE("seconds left: %u, the model says %llu", ttl, model_ttl());
	}
}

/* aegis_prover_heartbeat with dl bytes of status in a buffer of exactly cap bytes */
static void b_hb(const uint8_t nonce[32], const uint8_t *data, size_t dl, size_t cap, uint32_t flags)
{
	const size_t held = dl < cap ? dl : cap;
	char *st = malloc(cap ? cap : 1), ttl[32];
	uint8_t out[AEGIS_HB_LEN], ctr[8], tag[32], *c = malloc(32);
	size_t len = dl, tl;
	int rc, want;

	memcpy(c, nonce, 32);
	memset(st, 0xee, cap ? cap : 1);
	memcpy(st, data, held);
	memset(out, 0xee, sizeof(out));
	model_sweep();
	tl = (size_t)snprintf(ttl, sizeof(ttl), ";ttl=%llu", model_ttl());
	if (!M.session) want = model_no_session();
	else if (dl > cap || (!(flags & AEGIS_HB_RAW) && cap - dl < tl)) want = AEGIS_ERR_BUFFER;
	else want = AEGIS_OK;
	rc = aegis_prover_heartbeat(P, c, st, &len, cap, flags, out);
	TRACE_OP("heartbeat", rc, out, sizeof(out), st, len);
	if (rc != want) DIE("aegis_prover_heartbeat: %d, the model says %d", rc, want);
	if (rc != AEGIS_OK) {
		if (len != dl || memcmp(st, data, held) || !untouched((const uint8_t *)st + held, cap - held, 0xee) ||
		    !untouched(out, sizeof(out), 0xee))
			DIE("a refused heartbeat wrote its outputs");
	} else {
		const size_t sl = (flags & AEGIS_HB_RAW) ? dl : dl + tl;

		if (len != sl || memcmp(st, data, dl) || memcmp(st + dl, ttl, sl - dl)) DIE("heartbeat status");
		if (!untouched((const uint8_t *)st + sl, cap - sl, 0xee)) DIE("heartbeat wrote past the status");
		M.hb++;
		for (int i = 0; i < 8; i++) ctr[i] = (uint8_t)(M.hb >> (8 * i));
		if (memcmp(out, ctr, 8)) DIE("heartbeat counter");
		model_hb_tag(nonce, ctr, st, sl, tag);
		if (memcmp(tag, out + 8, 32)) DIE("heartbeat tag");
	}
	free(st);
	free(c);
}

static void b_hb_op(uint8_t sel, const uint8_t *p, size_t n)
{
	uint8_t nonce[32] = {0};
	const uint8_t *data = n > 32 ? p + 32 : p;
	const size_t dl = n > 32 ? n - 32 : 0;
	const unsigned pick = sel & 15u;
	const uint32_t flags = (pick == 1 || (sel & 16u)) ? AEGIS_HB_RAW : 0;
	char ttl[32];
	size_t cap;

	memcpy(nonce, p, n < 32 ? n : 32);
	model_sweep(); /* the buffer that is "exactly enough" needs the seconds left */
	if (pick == 0) cap = dl + AEGIS_HB_TTL_MAX;
	else if (pick == 1) cap = dl;
	else if (pick == 2) cap = dl + (flags ? 0 : (size_t)snprintf(ttl, sizeof(ttl), ";ttl=%llu", model_ttl()));
	else cap = 5u * pick;
	b_hb(nonce, data, dl, cap, flags);
}

/* a raw message of the STM32 family's transport, as far as it reaches the core */
static void b_raw(const uint8_t *p, size_t n)
{
	const int type = n ? p[0] % 8 : 0;
	size_t l0 = u16(p, n, 1) % 8192, l1 = u16(p, n, 3) % 8192, o0 = u16(p, n, 5) % 8192, o1 = u16(p, n, 7) % 8192;
	const uint8_t *d = n > 9 ? p + 9 : p;
	const size_t dn = n > 9 ? n - 9 : 0;

	if (l0 > dn) l0 = dn;
	if (l1 > dn - l0) l1 = dn - l0;
	if (type == 1) {
		b_pubkey();
	} else if (type == 2 && l0 == 32 && o0 >= 0x250 && o1 >= SIG_LEN) {
		b_quote(d);
	} else if (type == 3 && l0 == 32 && o0 >= KEM_EK_LEN && o1 >= SIG_LEN) {
		b_kem_init(d);
	} else if (type == 4 && l0 == KEM_CT_LEN) {
		b_finish(d, d + l0, l1, NULL, 1);
	} else if (type == 5) {
		b_session();
	} else if (type == 6 && l0 == 32) {
		/* no second output: the status is MACed as given, in a buffer of its own size, or of the first output's
		 * size if that is too small for a heartbeat */
		if (o1 == 0) b_hb(d, d + 32, l1, o0 < AEGIS_HB_LEN ? o0 : l1, AEGIS_HB_RAW);
		else b_hb(d, d + 32, l1, o1, 0);
	} else {
		b_poll(); /* refused by the transport: the clock is read, nothing else */
	}
}

static void binary_op(uint8_t op, uint8_t sel, const uint8_t *p, size_t n)
{
	uint8_t v32[32] = {0};

	memcpy(v32, p, n < 32 ? n : 32);
	switch (op) {
	case 0: b_raw(p, n); break;
	case 1: b_kem_init(v32); break;
	case 2: b_kem_fin(sel, p, n); break;
	case 3: b_hb_op(sel, p, n); break;
	case 4: b_quote(v32); break;
	case 5:
		if (!sel) b_session();
		else if (seen.have) b_finish(seen.ct, seen.cred, seen.cred_len, NULL, 0);
		break;
	case 6: {
		const uint32_t v = (uint32_t)(u16(p, n, 0) | u16(p, n, 2) << 16);

		if (sel == 1) {
			clk_advance((uint64_t)(v % 17000000u) * C.hz);
		} else if (sel == 2) {
			clk_advance(v);
		} else if (sel == 3) {
			clk_back(v);
		} else if (sel == 4) {
			/* the STM32 harness's faults of the clock's hardware, as they reach the core */
			const unsigned what = (n ? p[0] : 0u) % 12u;

			if (what == 11) fz_now += 1ull << 33; /* a wrap flag: a wrap */
			else if (what != 9) fz_clock_fail = 1;  /* 9, the register clock: the port switches it on again */
		} else if (sel == 5) {
			/* a reset; the clock starts if the hardware lets it (that harness's model: no flag that stops it,
			 * and an RTC clock that is the LSI or not chosen yet), at the counter the payload gives */
			const unsigned flags = n ? p[0] & 0x1Fu : 0, rtcsel = (n > 1 ? p[1] : 2u) & 3u;

			device_reset();
			fz_clock_fail = (flags & 0x0Fu) != 0 || (rtcsel != 0 && rtcsel != 2);
			fz_now = 0xFFFFFFFFu - (uint32_t)(u16(p, n, 2) | u16(p, n, 4) << 16);
		} else if (sel == 6) {
			ev_fail = n ? p[0] & 3 : 1;
		} else if (sel == 7) {
			fz_clock_fail = n ? p[0] & 1 : 1;
		} else {
			set_rng(p, n, 1);
		}
		break;
	}
	case 7: b_pubkey(); break;
	}
}

/* ================================== libFuzzer ================================== */

/* Once, before any input: what sdk/include/aegis_sdk.h says of a context that was not started, of a start with a
 * configuration it must refuse, and of arguments that are not there. */
static void contract_checks(const uint8_t seed[32], const uint8_t root[32])
{
	static struct aegis_prover q;
	static uint8_t w[AEGIS_WORK_MIN];
	struct aegis_platform pl = hosts[0].platform, bad;
	struct aegis_config cfg = {&pl, gw_pub, seed, root, w, sizeof(w)}, c;
	const uint8_t *a = SENTINEL, *b = SENTINEL;
	uint8_t out[AEGIS_SESSION_LEN], ch[32] = {0};
	char line[16], rep[AEGIS_REPLY_LEN(KEM_EK_LEN)], st[32];
	size_t n = 0;
	uint32_t ttl;

#define REFUSED(expr, want) do { if ((expr) != (want)) DIE("contract: %s is not %s", #expr, #want); } while (0)
#define LINE(text, cap, want) do { strcpy(line, text); \
		if (aegis_prover_handle_line(&q, line, rep, cap) != (int)strlen(want) || strcmp(rep, want)) \
			DIE("contract: \"%s\" with room for %u is answered %s", text, (unsigned)(cap), rep); } while (0)
	/* not started: nothing answers */
	REFUSED(aegis_prover_public_key(&q) != NULL, 0);
	REFUSED(aegis_prover_quote(&q, ch, &a, &n, &b), AEGIS_ERR_IDENTITY);
	REFUSED(aegis_prover_kem_init(&q, ch, &a, &b), AEGIS_ERR_IDENTITY);
	REFUSED(aegis_prover_kem_pending(&q), AEGIS_ERR_IDENTITY);
	REFUSED(aegis_prover_kem_finish(&q, w, w, 1, out), AEGIS_ERR_IDENTITY);
	REFUSED(aegis_prover_session_state(&q, &ttl), AEGIS_ERR_IDENTITY);
	REFUSED(aegis_prover_session(&q, out), AEGIS_ERR_IDENTITY);
	REFUSED(aegis_prover_heartbeat(&q, ch, st, &n, sizeof(st), 0, out), AEGIS_ERR_IDENTITY);
	aegis_prover_poll(&q);
	LINE("PQKEY", sizeof(rep), "ERR internal");
	/* a caller built against another layout or version, and configurations with something missing */
	REFUSED(aegis_prover_init(NULL, sizeof(q), AEGIS_SDK_API_VERSION, &cfg), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_init(&q, sizeof(q), AEGIS_SDK_API_VERSION, NULL), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_init(&q, sizeof(q) - 1, AEGIS_SDK_API_VERSION, &cfg), AEGIS_ERR_VERSION);
	REFUSED(aegis_prover_init(&q, sizeof(q), AEGIS_SDK_API_VERSION + 1u, &cfg), AEGIS_ERR_VERSION);
#define BAD_CFG(change) do { c = cfg; bad = pl; c.platform = &bad; change; \
		REFUSED(AEGIS_PROVER_INIT(&q, &c), AEGIS_ERR_ARGUMENT); REFUSED(aegis_prover_public_key(&q) != NULL, 0); } while (0)
	BAD_CFG(c.platform = NULL);
	BAD_CFG(bad.random = NULL);
	BAD_CFG(bad.clock = NULL);
	BAD_CFG(bad.clock_hz = 0);
	BAD_CFG(bad.measurements = NULL);                 /* no evidence of either kind */
	BAD_CFG(bad.evidence = fz_evidence);              /* both kinds */
	BAD_CFG(bad.profile = NULL);
	BAD_CFG(bad.version = NULL);
	BAD_CFG(bad.identity_sign = hosts[2].platform.identity_sign);             /* half an identity */
	BAD_CFG(bad.identity_public_key = hosts[2].platform.identity_public_key);
	BAD_CFG(bad.identity_sign = hosts[2].platform.identity_sign;
		bad.identity_public_key = hosts[2].platform.identity_public_key);  /* a platform key and a seed */
	BAD_CFG(c.identity_seed = NULL);                  /* neither */
	BAD_CFG(c.verifier_pk = NULL);
	BAD_CFG(c.exchange_root = NULL);
	BAD_CFG(c.work = NULL);
	BAD_CFG(c.work_len = AEGIS_WORK_MIN - 1u);
	/* started: arguments that are not there, and reply buffers that are too small */
	REFUSED(AEGIS_PROVER_INIT(&q, &cfg), AEGIS_OK);
	REFUSED(memcmp(aegis_prover_public_key(&q), aegis_prover_public_key(&hosts[0].prover), PK_LEN), 0);
	REFUSED(aegis_prover_public_key(NULL) != NULL, 0);
	REFUSED(aegis_prover_quote(&q, NULL, &a, &n, &b), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_quote(&q, ch, NULL, &n, &b), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_kem_init(&q, ch, &a, NULL), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_kem_finish(&q, NULL, w, 1, out), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_kem_finish(&q, w, NULL, 1, out), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_kem_finish(&q, w, w, 1, NULL), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_session(&q, NULL), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_heartbeat(&q, ch, NULL, &n, 0, 0, out), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_heartbeat(&q, ch, st, NULL, sizeof(st), 0, out), AEGIS_ERR_ARGUMENT);
	REFUSED(aegis_prover_session_state(&q, NULL), AEGIS_ERR_NO_SESSION);
	REFUSED(a != SENTINEL || b != SENTINEL, 0);
	strcpy(line, "PQKEY");
	REFUSED(aegis_prover_handle_line(&q, line, rep, 31), -1);
	REFUSED(aegis_prover_handle_line(NULL, line, rep, sizeof(rep)), -1);
	REFUSED(aegis_prover_handle_line(&q, NULL, rep, sizeof(rep)), -1);
	REFUSED(aegis_prover_handle_line(&q, line, NULL, sizeof(rep)), -1);
	LINE(" \t\r\n", 32, "ERR empty");
	LINE("a b c d e", 32, "ERR bad-request");
	LINE("PQKEY", sizeof(rep) - 1, "ERR internal");
	LINE("PQSESSION", sizeof(rep), "ERR pq no-session");
	LINE("PQKEY x", sizeof(rep), "ERR unknown");
#undef REFUSED
#undef LINE
#undef BAD_CFG
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
	aegis_host_test_random = fz_random;
	aegis_host_test_clock = fz_clock;
	for (unsigned i = 0; i < 8; i++) {
		struct aegis_host *h = &hosts[i];
		const size_t wl = (i & 4u) ? AEGIS_WORK_MIN : sizeof(h->work);

		aegis_host_prepare(h, PROFILE, "rw612-tfm", "0.1.0");
		h->status = status_text;
		if (i & 1u) {
			h->platform.measurements = NULL;
			h->platform.evidence = fz_evidence;
		} else {
			h->platform.measurements = fz_measurements;
		}
		if (aegis_host_start(h, dseed, root, gw_pub, (i & 2u) != 0) != AEGIS_OK) abort();
		/* the work buffer at its exact size on the heap, so that the sanitizer sees a write past it */
		h->prover.work = malloc(wl);
		h->prover.work_len = wl;
		if (memcmp(aegis_prover_public_key(&h->prover), aegis_prover_public_key(&hosts[0].prover), PK_LEN)) abort();
	}
	dev_pk = aegis_prover_public_key(&hosts[0].prover);
	aegis_sha256(dev_pk, PK_LEN, dev_pk_sha256);
	contract_checks(dseed, root);
	return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct aegis_host *h;
	uint8_t cfg = 0;
	size_t i = 0;
	int ops = 0;

	memset(&C, 0, sizeof(C));
	if (size >= 5 && !memcmp(data, MAGIC, 4)) {
		C.magic = 1;
		cfg = data[4];
		i = 5;
	}
	C.binary = cfg & 1u;
	C.hz = (cfg & 2u) ? 250u : 1u;
	C.hb_from_boot = (cfg & 4u) != 0;
	C.no_endpoint = (cfg & 8u) != 0;
	C.token = (cfg & 16u) != 0;
	C.platkey = (cfg & 32u) != 0;
	h = &hosts[(cfg >> 4) & 7u];
	P = &h->prover;
	C.work_len = P->work_len;
	h->platform.clock_hz = C.hz;
	h->platform.compat = (C.hb_from_boot ? AEGIS_COMPAT_HB_COUNTER_FROM_BOOT : 0u) |
			     (C.no_endpoint ? AEGIS_COMPAT_CRED_WITHOUT_ENDPOINT : 0u);

	/* a fresh device state for every input (the key stays) */
	device_reset();
	seen.have = 0;
	seen.eks = 0;
	fz_now = C.binary ? 0xFFFFu : 1000u;
	fz_clock_fail = 0;
	rng_state = RNG_SEED;
	rng_skip = rng_fail = 0;
	rng_zero = 0;
	ev_fail = 0;
	strcpy(status_text, "requests=1;stack=na;clk=ref;fw=rw612-tfm-0.2.2");

	while (i + 3 <= size && ops++ < 24) {
		uint8_t op = data[i] & 7, sel = data[i] >> 3;
		size_t n = (size_t)data[i + 1] | (size_t)data[i + 2] << 8;
		const uint8_t *p = data + i + 3;

		if (n > size - i - 3) n = size - i - 3;
		i += 3 + n;
		if (C.binary) binary_op(op, sel, p, n);
		else line_op(op, sel, p, n);
		check_state(); /* both as of the last request: only a request reads the clock */
	}
	return 0;
}

#if defined(FZ_STANDALONE)
/* without libFuzzer: the inputs named on the command line, one after the other */
int main(int argc, char **argv)
{
	static uint8_t buf[65536];

	LLVMFuzzerInitialize(&argc, &argv);
	for (int i = 1; i < argc; i++) {
		FILE *f = fopen(argv[i], "rb");
		size_t n;

		if (!f) { perror(argv[i]); return 2; }
		n = fread(buf, 1, sizeof(buf), f);
		fclose(f);
		LLVMFuzzerTestOneInput(buf, n);
	}
	printf("%d inputs, no finding\n", argc - 1);
	return 0;
}
#endif
