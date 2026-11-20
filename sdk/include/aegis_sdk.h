/* SPDX-License-Identifier: Apache-2.0
 *
 * Aegis Prover SDK: the public interface of the protocol core (sdk/src/aegis_proto.c) and of the platform layer a
 * device maker writes for it. sdk/README.md is the integrator's guide; this file is the reference.
 *
 * The core is the device's side of the Aegis attestation protocol: an ML-DSA-65 quote, an ML-KEM-768 session bound
 * to that quote by one signed transcript, a credential from the verifier, KMAC256 heartbeats, and the session's end
 * on the device's own clock. It is plain C11 (<stddef.h>, <stdint.h>, and memcpy, memcmp, strlen and strcmp of
 * <string.h>), allocates nothing, and keeps all its state in a context and one work buffer that the caller provides. It reaches
 * the device through the functions of struct aegis_platform, and the network not at all: the integrator carries
 * messages to and from it, either as text lines (aegis_prover_handle_line) or as binary operations (aegis_prover_*).
 *
 * Everything declared here runs in the device's secure world (a TF-M secure partition, a trusted application, or
 * the whole firmware on a chip without one): the context holds the secret keys.
 */
#ifndef AEGIS_SDK_H
#define AEGIS_SDK_H
#include <stddef.h>
#include <stdint.h>

/* Changes when a function, a structure or a contract of this file changes incompatibly. aegis_prover_init() refuses
 * a caller built against another version, or against another layout of struct aegis_prover. */
#define AEGIS_SDK_API_VERSION 1u

/* ---- sizes --------------------------------------------------------------------------------------------------- */
#define AEGIS_PK_LEN        1952u /* ML-DSA-65 public key (FIPS 204) */
#define AEGIS_SK_LEN        4032u /* ML-DSA-65 secret key */
#define AEGIS_SIG_LEN       3309u /* ML-DSA-65 signature */
#define AEGIS_SEED_LEN      32u   /* ML-DSA-65 key generation seed; also the length of the exchange root */
#define AEGIS_KEM_EK_LEN    1184u /* ML-KEM-768 encapsulation key (FIPS 203) */
#define AEGIS_KEM_DK_LEN    2400u /* ML-KEM-768 decapsulation key */
#define AEGIS_KEM_CT_LEN    1088u /* ML-KEM-768 ciphertext */
#define AEGIS_CHALLENGE_LEN 32u   /* the verifier's challenge, and its nonces */
#define AEGIS_DIGEST_LEN    32u
#define AEGIS_TAG_LEN       32u   /* the confirmation tag of a finished exchange */
#define AEGIS_HB_LEN        40u   /* a heartbeat: counter (8 bytes, little-endian) || KMAC256 tag (32) */
#define AEGIS_SESSION_LEN   64u   /* session id (32) || SHA3-256 of the credential (32) */
/* A credential is "<canonical JSON body>\n<ML-DSA-65 signature>"; longer ones are refused. */
#define AEGIS_CRED_MAX      6144u
#define AEGIS_CRED_BODY_MAX (AEGIS_CRED_MAX - 1u - AEGIS_SIG_LEN)

/* The work buffer (struct aegis_config). The core builds in it whatever is signed or verified: a label, a zero byte
 * and the message. Its size sets two limits:
 *   evidence (the claims, or the platform's token)   work_len - AEGIS_WORK_QUOTE_HEAD bytes
 *   credential body                                  work_len - AEGIS_WORK_CRED_HEAD bytes
 * and it is never less than AEGIS_WORK_MIN, the message under a KEM key's signature. AEGIS_WORK_LEN() gives the size
 * for a wanted evidence limit; with it every credential the protocol allows fits. A port that must save RAM can give
 * AEGIS_WORK_MIN: credentials are then limited to bodies of 1214 bytes (the gateway's are about 600). */
#define AEGIS_WORK_QUOTE_HEAD 24u /* "aegis-endpoint-quote-v1" and its terminator */
#define AEGIS_WORK_CRED_HEAD  20u /* "aegis-credential-v1" and its terminator */
#define AEGIS_WORK_MIN        (18u + AEGIS_CHALLENGE_LEN + AEGIS_KEM_EK_LEN)
#define AEGIS_WORK_CRED       (AEGIS_WORK_CRED_HEAD + AEGIS_CRED_BODY_MAX)
#define AEGIS_WORK_LEN(evidence_max) \
	(AEGIS_WORK_QUOTE_HEAD + (evidence_max) > AEGIS_WORK_CRED ? AEGIS_WORK_QUOTE_HEAD + (evidence_max) : AEGIS_WORK_CRED)

/* The line transport (aegis_prover_handle_line). The longest request is PQKEMFIN: a ciphertext and a credential in
 * hex. The longest reply is PQTOKEN: evidence and a signature in hex. AEGIS_REPLY_MAX fits evidence of up to 1440
 * bytes; AEGIS_REPLY_LEN() gives the size for another limit. */
#define AEGIS_LINE_MAX 14600u
#define AEGIS_REPLY_LEN(evidence_max) (2u * ((evidence_max) + AEGIS_SIG_LEN) + 64u)
#define AEGIS_REPLY_MAX 9600u
#define AEGIS_STATUS_MAX 96u /* the platform's heartbeat status text in the line transport, with its terminator */
/* ";ttl=<seconds>" as the core appends it to a heartbeat's status: at most this many bytes */
#define AEGIS_HB_TTL_MAX 15u

/* A session ends on the device's own clock (docs/endpoint-expiry.md). The credential's lifetime is its signed
 * "expires" minus "issued", at most AEGIS_CRED_LIFETIME_MAX seconds; the session lives that long plus a margin of one
 * sixteenth. The margin covers a clock up to 6 % fast (the least exact one in use is the STM32's RC oscillator, good
 * to a few per cent), so a device does not end a session before the verifier's own expiry. */
#define AEGIS_CRED_LIFETIME_MAX 86400u
#define AEGIS_SESSION_LIMIT(lifetime) ((uint64_t)(lifetime) + (lifetime) / 16u)

/* ---- results -------------------------------------------------------------------------------------------------- */
/* What an operation returns. The line transport turns each into the reply given on the right; a binary transport
 * maps them to its own codes (endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c maps them to PSA statuses).
 * Any result but AEGIS_OK means that nothing was written to the operation's outputs. */
enum aegis_result {
	AEGIS_OK = 0,
	AEGIS_ERR_ARGUMENT,              /* a NULL or out-of-range argument of the caller's: a programming error */
	AEGIS_ERR_VERSION,               /* aegis_prover_init: built against another API version or layout */
	AEGIS_ERR_IDENTITY,              /* aegis_prover_init: no identity key (key generation or the platform failed) */
	AEGIS_ERR_BAD_REQUEST,           /* "ERR bad-request"            a length the protocol does not allow */
	AEGIS_ERR_EVIDENCE,              /* "ERR evidence"               the platform gave no evidence, or it does not fit */
	AEGIS_ERR_RNG,                   /* "ERR rng"                    no fresh randomness for the exchange's key */
	AEGIS_ERR_SIGN_RNG,              /* "ERR sign"                   no fresh randomness for a signature */
	AEGIS_ERR_SIGN,                  /* "ERR sign"                   the signature could not be made */
	AEGIS_ERR_KEM,                   /* "ERR kem"                    ML-KEM key generation or decapsulation failed */
	AEGIS_ERR_NO_EXCHANGE,           /* "ERR cred no-exchange"       no exchange is pending */
	AEGIS_ERR_CLOCK,                 /* "ERR clock"                  the clock cannot be trusted: no session starts */
	AEGIS_ERR_CRED_SIGNATURE,        /* "ERR cred signature"         not signed by the pinned verifier key */
	AEGIS_ERR_CRED_OTHER_EXCHANGE,   /* "ERR cred other-exchange"    does not name this ciphertext */
	AEGIS_ERR_CRED_OTHER_ENDPOINT,   /* "ERR cred other-endpoint"    does not name this device's key */
	AEGIS_ERR_CRED_OTHER_KEY,        /* "ERR cred other-key"         does not name this exchange's ML-KEM key */
	AEGIS_ERR_CRED_OTHER_TRANSCRIPT, /* "ERR cred other-transcript"  does not name this transcript */
	AEGIS_ERR_CRED_VALIDITY,         /* "ERR cred validity"          carries no lifetime of 1 to 86400 seconds */
	AEGIS_ERR_NO_SESSION,            /* "ERR pq no-session"          no session since the start */
	AEGIS_ERR_EXPIRED,               /* "ERR pq expired"             the last session was ended by the clock */
	AEGIS_ERR_STATUS,                /* "ERR status"                 the platform gave no status text */
	AEGIS_ERR_BUFFER                 /* "ERR internal"               an output buffer of the caller's is too small */
};

/* ---- the platform layer --------------------------------------------------------------------------------------- */

/* One measured software component (PSA claim names): its type label, its SHA-256 (or other 32-byte) digest and a
 * description for the verifier's journal. The verifier's policy compares label and value with reference values. */
struct aegis_measurement {
	const char *label; /* for example "SPE", "NSPE", "APP"; must stay valid while the list is in use */
	uint8_t value[AEGIS_DIGEST_LEN];
	char desc[64];     /* a terminated text */
};

/* Compatibility with images in the field. A new port sets none of them. */
/* The heartbeat counter counts from the start of the device, not from the start of each session (the STM32H573
 * partition up to SPE 3183f74a). The verifier only needs it to rise within a session. */
#define AEGIS_COMPAT_HB_COUNTER_FROM_BOOT   0x01u
/* A credential need not name this device's key in "endpoint_pq_pk_sha256" (the same partition). It must still name
 * this exchange's ML-KEM key, which no other device has. */
#define AEGIS_COMPAT_CRED_WITHOUT_ENDPOINT  0x02u

/* What the device gives the core. Every function gets `user` back as its first argument and returns 0 for success;
 * any other value makes the core refuse the request that needed it (it never continues with a default). The
 * structure must stay valid and unchanged for as long as the context is used: make it const.
 *
 * Required: random, clock and clock_hz, and one of measurements and evidence. */
struct aegis_platform {
	void *user;

	/* Randomness. n bytes (32 at a time) from the chip's random number generator or a DRBG seeded from it. They go
	 * into every exchange's ML-KEM key and, hedged, into every signature. A failure refuses the request; so do 32
	 * zero bytes for an exchange's key (a generator that reports success and writes nothing). The generator must
	 * not restart with the same output after a reset: the exchange keys then repeat, and a recorded exchange can be
	 * replayed (tests/host/test_reset_replay_check.py shows it). */
	int (*random)(void *user, uint8_t *out, size_t n);

	/* Time. A counter that only advances, at clock_hz counts a second (1 or more), from any origin, and that
	 * nothing outside the secure world can set, slow or stop. It is read at every request. A failure, or a reading
	 * below the one at a session's start, ends the session and lets none start: return nonzero whenever the counter
	 * can no longer be trusted (a changed clock source, a wrap that may have been missed). */
	int (*clock)(void *user, uint64_t *now);
	uint32_t clock_hz;

	/* Evidence, variant 1: the measurements, as taken by code the measured code cannot change (the boot stage
	 * before it, or the secure world before the non-secure image runs). *list points to *count entries that stay
	 * valid until the next call. The core puts them into the Aegis claims (CBOR, PSA claim numbers) with `profile`
	 * and `version` and signs them. Leave NULL when `evidence` is set. */
	int (*measurements)(void *user, const struct aegis_measurement **list, size_t *count);
	const char *profile; /* the claims' profile name: tells the verifier what kind of device and key this is */
	const char *version; /* the measured components' version text */

	/* Evidence, variant 2 (instead of 1): the platform's own token for this challenge, at most cap bytes, its
	 * length in *len (for example TF-M's PSA initial attestation token, which carries the boot measurements under
	 * the platform's key). The core signs it as it is. This is also where an EAT / COSE encoder goes. */
	int (*evidence)(void *user, const uint8_t challenge[AEGIS_CHALLENGE_LEN], uint8_t *out, size_t cap, size_t *len);

	/* Identity key held by the platform (a secure element, a key store, an accelerator). Set both or neither. With
	 * both set the core never sees the secret key: struct aegis_config.identity_seed is then NULL.
	 * identity_sign signs msg with pure ML-DSA-65 (FIPS 204 ML-DSA.Sign, empty context string), hedged. */
	int (*identity_public_key)(void *user, uint8_t pk[AEGIS_PK_LEN]);
	int (*identity_sign)(void *user, const uint8_t *msg, size_t msg_len, uint8_t sig[AEGIS_SIG_LEN]);

	/* Optional, for the line transport's PQHB: the device's status text (key=value;key=value, printable, no
	 * "ttl=" key) into buf, terminated; returns its length, or a negative value. It must be shorter than cap. The
	 * verifier shows the text and can match it; it is under the heartbeat's MAC. Without it the status is empty. */
	int (*status)(void *user, char *buf, size_t cap);

	uint32_t compat; /* AEGIS_COMPAT_*, normally 0 */
};

/* ---- the context ---------------------------------------------------------------------------------------------- */

/* The prover's whole state. The caller provides the storage (static, in secure RAM that does not keep its content
 * across a reset) and never reads or writes a member: the layout is here only so that its size is known. Nothing in
 * it is persistent and nothing may be made so: a session and the quote an exchange continues must not outlive a
 * reset. */
struct aegis_prover {
	const struct aegis_platform *plat;
	const uint8_t *verifier_pk;
	uint8_t *work;
	size_t work_len;
	uint8_t pk[AEGIS_PK_LEN];
	uint8_t sk[AEGIS_SK_LEN];             /* unused when the platform holds the identity key */
	uint8_t pk_sha256[AEGIS_DIGEST_LEN];
	uint8_t prov_root[AEGIS_SEED_LEN];
	uint8_t sig[AEGIS_SIG_LEN];
	uint8_t kem_ek[AEGIS_KEM_EK_LEN], kem_dk[AEGIS_KEM_DK_LEN], kem_nonce[AEGIS_CHALLENGE_LEN];
	uint8_t quote_ch[AEGIS_CHALLENGE_LEN], quote_t1[AEGIS_DIGEST_LEN]; /* the last quote signed since the start */
	uint8_t kem_t2[AEGIS_DIGEST_LEN];     /* T2 of the pending exchange, when it continues a quote */
	uint8_t session_key[32], cred_hash[AEGIS_DIGEST_LEN];
	uint64_t session_start, session_limit; /* the clock at the accepted credential; the counts the session may live */
	uint64_t now;                          /* the clock as last read */
	uint64_t hb_counter;
	uint32_t kem_counter;
	uint8_t ready, clock_ok, quote_ready, kem_pending, kem_bound, session_ready, session_expired;
};

struct aegis_config {
	const struct aegis_platform *platform;
	/* The verifier's (gateway's) ML-DSA-65 public key, AEGIS_PK_LEN bytes, pinned in the image. Not copied: it must
	 * stay valid and unchanged (keep it in ROM). Only credentials signed with it start a session. */
	const uint8_t *verifier_pk;
	/* The identity key's seed, AEGIS_SEED_LEN bytes, device-unique and derived from a hardware secret that only the
	 * secure world can use. The core makes the ML-DSA-65 key pair from it (the same pair at every start) and does
	 * not keep it: wipe your copy when aegis_prover_init() returns. NULL when the platform holds the key. */
	const uint8_t *identity_seed;
	/* A second device-unique secret, AEGIS_SEED_LEN bytes, used only in the derivation of the exchanges' ML-KEM
	 * keys (with fresh randomness, the nonce and a counter). Copied into the context; wipe your copy. */
	const uint8_t *exchange_root;
	/* The work buffer: at least AEGIS_WORK_MIN bytes, see AEGIS_WORK_LEN(). Used only by the core. */
	uint8_t *work;
	size_t work_len;
};

/* ---- the core -------------------------------------------------------------------------------------------------
 * One context serves one request at a time (no locking inside). Every function below except aegis_prover_init and
 * aegis_prover_public_key first reads the clock and ends a session that has outlived its credential.
 * Output pointers (*evidence, *sig, *ek) point into the context or the work buffer and are valid until the next call
 * with the same context. */

/* At every start of the device, before the first request: checks the configuration, wipes the context, makes or
 * fetches the identity key. prover_size and api_version are the caller's sizeof(struct aegis_prover) and
 * AEGIS_SDK_API_VERSION: use AEGIS_PROVER_INIT(). Until it has returned AEGIS_OK every other function refuses. */
int aegis_prover_init(struct aegis_prover *p, size_t prover_size, uint32_t api_version, const struct aegis_config *cfg);
#define AEGIS_PROVER_INIT(p, cfg) aegis_prover_init((p), sizeof(struct aegis_prover), AEGIS_SDK_API_VERSION, (cfg))

/* The identity public key (AEGIS_PK_LEN bytes), or NULL before a successful init. */
const uint8_t *aegis_prover_public_key(const struct aegis_prover *p);

/* Read the clock and end an overdue session, nothing else. A transport may call it for requests it refuses itself,
 * and a device may call it from a timer, so that the session key is wiped when the session ends and not only at the
 * next request. */
void aegis_prover_poll(struct aegis_prover *p);

/* Quote: evidence for this challenge and its ML-DSA-65 signature over "aegis-endpoint-quote-v1\0" || evidence.
 * It becomes the one quote an exchange can continue, in place of any earlier one. */
int aegis_prover_quote(struct aegis_prover *p, const uint8_t challenge[AEGIS_CHALLENGE_LEN], const uint8_t **evidence,
		       size_t *evidence_len, const uint8_t **sig);

/* Start an exchange: a fresh ML-KEM-768 key and the identity key's signature for it. A nonce equal to the challenge
 * of the last quote continues that quote (once): the signature is then over the transcript. Replaces a pending
 * exchange; an established session stays until an exchange completes. */
int aegis_prover_kem_init(struct aegis_prover *p, const uint8_t nonce[AEGIS_CHALLENGE_LEN], const uint8_t **ek,
			  const uint8_t **sig);

/* May an exchange be finished now? AEGIS_OK, AEGIS_ERR_NO_EXCHANGE or AEGIS_ERR_CLOCK: what aegis_prover_kem_finish
 * would answer first. For a transport that wants to refuse before it reads a large message. */
int aegis_prover_kem_pending(struct aegis_prover *p);

/* Finish the exchange: check the verifier's credential (cred_len bytes, 1 to AEGIS_CRED_MAX), decapsulate, start the
 * session, give the confirmation tag. ct and cred are only read. A refused credential ends the exchange and leaves
 * an established session alone; AEGIS_ERR_NO_EXCHANGE, AEGIS_ERR_CLOCK and AEGIS_ERR_BAD_REQUEST leave both. */
int aegis_prover_kem_finish(struct aegis_prover *p, const uint8_t ct[AEGIS_KEM_CT_LEN], const uint8_t *cred,
			    size_t cred_len, uint8_t tag[AEGIS_TAG_LEN]);

/* Is there a session? AEGIS_OK (and, if ttl_s is not NULL, the seconds it has left, rounded up),
 * AEGIS_ERR_NO_SESSION or AEGIS_ERR_EXPIRED. */
int aegis_prover_session_state(struct aegis_prover *p, uint32_t *ttl_s);

/* The session's public name: SHA3-256("aegis-session-id-v1" || session key) || SHA3-256(credential). */
int aegis_prover_session(struct aegis_prover *p, uint8_t out[AEGIS_SESSION_LEN]);

/* Heartbeat: a counter and KMAC256(session key, nonce || counter || status, 256, "aegis-hb-v2").
 * status holds *status_len bytes of the device's status text in a buffer of status_cap bytes. The core appends
 * ";ttl=<seconds the session has left>" (up to AEGIS_HB_TTL_MAX bytes; AEGIS_ERR_BUFFER if they do not fit), updates
 * *status_len, and the MAC covers the whole text: send it with the heartbeat. The text before it must not hold a
 * "ttl=" key that an untrusted party chose. With AEGIS_HB_RAW the status is MACed as given, for a transport with
 * no way to return it (the verifier then does not learn the time left). */
#define AEGIS_HB_RAW 0x01u
int aegis_prover_heartbeat(struct aegis_prover *p, const uint8_t nonce[AEGIS_CHALLENGE_LEN], char *status,
			   size_t *status_len, size_t status_cap, uint32_t flags, uint8_t out[AEGIS_HB_LEN]);

/* The line transport: one request line (terminated text, changed in place) in, one reply (terminated, without a line
 * end) out; returns the reply's length, or -1 if cap cannot hold any reply (give AEGIS_REPLY_MAX).
 *   PQKEY                    -> PQKEY <len> <hex> END
 *   PQCHAL <challenge>       -> PQTOKEN <len> <evidence> <len> <sig> END
 *   PQKEMINIT <nonce>        -> PQKEMEK <len> <ek> <len> <sig> END
 *   PQKEMFIN <ct> <cred>     -> PQKEMOK <tag> END
 *   PQHB <nonce>             -> PQHB <status> <counter> <tag> END
 *   PQSESSION                -> PQSESSION <session id> <credential hash> END
 * and "ERR <reason>" (enum aegis_result; also "ERR empty", "ERR unknown"). Binary fields are in hex. A transport
 * that reads a line longer than AEGIS_LINE_MAX answers "ERR too-long" itself. */
int aegis_prover_handle_line(struct aegis_prover *p, char *line, char *out, size_t cap);

/* Overwrite n bytes with zeros in a way the compiler does not remove: for a port's copies of seeds and keys. */
void aegis_wipe(void *p, size_t n);
#endif
