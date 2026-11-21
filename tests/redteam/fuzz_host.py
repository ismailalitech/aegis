#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Red-team checks on the PC (no hardware). Each check states the property it tries to break.

  1. token parser: mutated / truncated / random PSA tokens are never accepted and raise nothing but
     psa_token.TokenError (no crash, no other exception);
  2. aegisd quote service: malformed requests (garbage, wrong JSON, huge length prefix, bad nonce)
     never stop the service; a valid quote still verifies afterwards;
  3. fleet verifier vs a hostile endpoint: random reply lines, a classic-token downgrade for a
     post-quantum endpoint, a replayed KEM key from an earlier nonce: never admitted / provisioned;
     validly signed tokens (ES256 and ML-DSA-65) carrying random CBOR claims: attest() never raises;
  4. one transcript (policy "transcript": "v2", docs/architecture.md): a hostile endpoint that holds validly signed
     pieces which are not the transcript of the quote the verifier appraised (a KEM key signed the old way, signed
     over another challenge, another token, another key or another step, under the other label, or a random line)
     is never given a credential: provision() stops before it sends one, with ValueError and nothing else.
  5. endorsed enrolment (policy "endorsement": "required", docs/enrolment.md): a record file that is not exactly what
     a trusted endorser signed for this device, family and key (mutated bytes, edited claims with the old signature
     or a new one by a key the policy does not list, the endorser's own signature under another label or for another
     device, family, key or an expiry in the past, another key pinned, the endorser's own record for this device and
     key that is not the one the entry pins with endorsement_sha256, random JSON) never makes a key trusted:
     device_key() raises endorsement.Refused and nothing else, attest() refuses without contacting the endpoint.
  6. standard evidence (policy "evidence_format": "eat-cose-v1", docs/evidence-format.md): EAT, EAR and the
     endorsement as COSE_Sign1 objects signed with ML-DSA-65. Bytes that are not exactly a signed object (mutated,
     truncated, extended, random) are never accepted by the decoders (common/cose.py, common/eat.py,
     common/endorsement.py), which raise their Refused and nothing else. An object whose signature is valid but
     whose header is not the profile's (another algorithm, a header outside the signature, an unknown or critical
     parameter, another kid or typ, a second encoding), or whose claims are not the profile's or not this cycle's
     (a claim removed, replaced or added, another measurement, random CBOR), is never admitted, and attest() never
     raises. A COSE record that is not the one the entry pins never makes a key trusted. The standalone checker
     (tools/verify_evidence.py; skipped without pycose, cbor2 and ML-DSA in cryptography) never reports any of
     these as verified, and never verifies evidence the verifier's own decoder refuses.
  7. audit log and signed policy (policy "audit_log": true; policy-signing keys; docs/audit-and-policy.md). A log
     that is not exactly what the verifier wrote (bytes mutated, cut off anywhere, a batch removed, repeated, moved,
     taken from another log of the same key, an entry edited under the old signature or under another key's, an item
     put between batches) is never accepted by a reader that holds the last batch record as its anchor: the
     verifier's reader (common/audit.py) raises audit.Refused and nothing else, the standalone checker
     (tools/verify_audit.py) never verifies it, and without the anchor the two readers still agree on every one of
     them. A policy file that is not a policy signer's statement of a version this verifier has not gone past
     (mutated, signed by another key, the signer's signature under another typ or header, over claims that are not
     a policy's, an older version, another policy under an accepted version) is never loaded: fleet.load_policy
     raises PolicyRefused and nothing else, and the checker never verifies it. Whatever a verdict holds (random
     CBOR in every field), the audit trail never raises, and the log it wrote verifies under both readers, which
     read the same entries from it.
  8. Aegis 1.2. A pack's manifest.cose that is not the verifier's statement of exactly this pack (mutated, another
     key, the verifier's key under another typ or header, another endpoint, time, manifest or result, a claim
     added, removed or replaced) is never accepted: common/evidence_pack.py raises its Refused or cose.Refused and
     nothing else, and the checker (tools/verify_evidence.py) agrees on every one. A result whose new claims
     (aegis.audit-log/-batch/-head, aegis.warnings, aegis.disabled, aegis.min-trust) hold anything is read by
     eat.read_ear only if each is of its form, and the checker agrees. A policy entry whose "disabled" and
     "min_trust" hold anything: attest() never raises, contacts the endpoint only where it may admit it (not where
     the floor can never be met by the entry's profile), admits exactly where the floor is met, and the result made of the verdict reads back and says "disabled".

  fuzz_host.py [iterations]     prints a JSON summary, exit 0 only if no property broke
"""
import json
import os
import random
import socket
import struct
import sys
import tempfile
import threading
import time

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..")
for p in ("common", "host", "gateway/aegisd", "gateway/sysserv", "tests/host"):
    sys.path.insert(0, os.path.abspath(os.path.join(ROOT, p)))

import cbor  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import mlkem  # noqa: E402
import psa_token  # noqa: E402
import transcript  # noqa: E402
import test_fleet as tf  # noqa: E402
import test_identity_quote as tq  # noqa: E402
import aegis_verify as av  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

N = int(sys.argv[1]) if len(sys.argv) > 1 else 3000
R = random.Random(1234)
broken = []


def mutate(b):
    b = bytearray(b)
    kind = R.randrange(5)
    if kind == 0 and b:
        b[R.randrange(len(b))] ^= 1 << R.randrange(8)
    elif kind == 1 and b:
        del b[R.randrange(len(b)):]
    elif kind == 2:
        i = R.randrange(len(b) + 1)
        b[i:i] = bytes(R.randrange(256) for _ in range(R.randrange(1, 9)))
    elif kind == 3 and b:
        i = R.randrange(len(b))
        b[i] = R.choice([0x00, 0xFF, 0x1B, 0x5B, 0x9F, 0xBF, 0xD8, 0x7F])
    else:
        b = bytearray(R.randrange(256) for _ in range(R.randrange(0, 600)))
    return bytes(b)


# ---- 1. token parser -----------------------------------------------------------------------
key = ec.generate_private_key(ec.SECP256R1())
pub = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
good = tf.make_token(key, b"\x11" * 32)
assert psa_token.verify(good, pub, psa_token.verify_with_cryptography)["challenge"] == b"\x11" * 32
signed_parts = psa_token.parse(good)[:3]
accepted = other_exc = 0
for _ in range(N):
    t = mutate(good)
    try:
        psa_token.verify(t, pub, psa_token.verify_with_cryptography)
        if psa_token.envelope(t) != signed_parts:  # signed content changed, yet accepted
            accepted += 1
    except psa_token.TokenError:  # every decoding failure is reported as a TokenError (verified first)
        pass
    except Exception as e:  # anything else is a robustness bug
        other_exc += 1
        if len(broken) < 5:
            broken.append("token parser raised %r" % e)
token_result = {"mutations": N, "accepted": accepted, "unexpected_exceptions": other_exc}
if accepted:
    broken.append("a mutated token was accepted")

# ---- 2. aegisd quote service ---------------------------------------------------------------
gw = tq.Gateway(tq.FakeHardware())
store = tempfile.mkdtemp()
_, enrolled = av.enroll("127.0.0.1", gw.port, store=store)


def raw_send(data, read=True):
    try:
        with socket.create_connection(("127.0.0.1", gw.port), timeout=2) as s:
            s.sendall(data)
            s.shutdown(socket.SHUT_WR)  # end of request: the server sees EOF at once
            if read:
                s.settimeout(2)
                return s.recv(4096)
    except OSError:
        return None


# slow client: opens a connection, sends half a frame and keeps it open; quotes must still work
slow = socket.create_connection(("127.0.0.1", gw.port), timeout=5)
slow.sendall(struct.pack(">I", 1000) + b"{")
t0 = time.monotonic()
resp_s, nonce_s, el_s = av.fresh_quote("127.0.0.1", gw.port)
slow_ok, _ = av.check_quote(enrolled, resp_s, nonce_s, el_s)
slow_s = round(time.monotonic() - t0, 3)
slow.close()


bad_requests = [b"", b"\x00", b"\xff\xff\xff\xff", struct.pack(">I", 1 << 30) + b"{}",
                struct.pack(">I", 5) + b"notjs", struct.pack(">I", 2) + b"[]",
                struct.pack(">I", 15) + b'{"type":"what"}',
                struct.pack(">I", 30) + b'{"type":"quote","nonce":"zz"}',
                struct.pack(">I", 36) + b'{"type":"quote","nonce":12345678}',
                struct.pack(">I", 4) + b"null"]
for _ in range(min(N, 300)):
    bad_requests.append(struct.pack(">I", R.randrange(0, 2000)) + bytes(R.randrange(256) for _ in range(R.randrange(0, 200))))
for b in bad_requests:
    raw_send(b)
resp, nonce, el = av.fresh_quote("127.0.0.1", gw.port)
ok_after, reasons = av.check_quote(enrolled, resp, nonce, el)
service_result = {"malformed_requests": len(bad_requests), "valid_quote_after": ok_after,
                  "quote_while_slow_client_open_s": slow_s, "quote_while_slow_client_ok": slow_ok}
if not slow_ok or slow_s > 2:
    broken.append("a slow client blocked the quote service (%.1f s)" % slow_s)
if not ok_after:
    broken.append("aegisd stopped answering correctly after malformed input: %s" % reasons)

# ---- 3. hostile endpoint -------------------------------------------------------------------


class Hostile(threading.Thread):
    """Answers every request with the next line from `replies` (bytes)."""

    def __init__(self, replies):
        super().__init__(daemon=True)
        self.replies = list(replies)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        self.start()

    def run(self):
        while self.replies:
            c, _ = self.srv.accept()
            try:
                c.recv(65536)
                c.sendall(self.replies.pop(0))
            finally:
                c.close()


pq_pk, pq_sk = tf.PQ_KEYS[0]
pqf = os.path.join(store, "pq.pub")
open(pqf, "w").write(pq_pk.hex())
pemf = os.path.join(store, "iak.pem")
open(pemf, "wb").write(pub)
allowed = [{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
           {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}]
admitted_by_garbage = 0
for _ in range(min(N, 400)):
    line = bytes(R.randrange(32, 127) for _ in range(R.randrange(0, 300)))
    if R.random() < 0.3:
        line = R.choice([b"PQTOKEN ", b"TOKEN ", b"PQTOKEN 1 00 1 00 END", b"TOKEN 999999 00 END"]) + line
    h = Hostile([line + b"\r\n"])
    for kind in ("psa", "aegis-pq"):
        conf = {"name": "x", "kind": kind, "host": "127.0.0.1", "port": h.port, "iak_pub_pem": pemf,
                "pq_pub_file": pqf, "allowed": allowed}
        if kind == "aegis-pq":
            h = Hostile([line + b"\r\n"])
            conf["port"] = h.port
        v = fleet.attest(conf, psa_token.verify_with_cryptography, store, timeout=1)
        admitted_by_garbage += v["admitted"]

# downgrade: a post-quantum endpoint answering with a perfectly valid classic token only
classic = tf.make_token(key, b"\x00" * 32)
h = Hostile([b"TOKEN %d %s END\r\n" % (len(classic), classic.hex().encode())])
v = fleet.attest({"name": "down", "kind": "aegis-pq", "host": "127.0.0.1", "port": h.port, "pq_pub_file": pqf,
                  "iak_pub_pem": pemf, "allowed": allowed}, psa_token.verify_with_cryptography, store, timeout=2)
downgrade_refused = not v["admitted"]

# KEM replay: a validly signed ek from an earlier nonce must not be accepted for a new nonce
old_nonce = b"\x42" * 32
ek, _dk = mlkem.keypair()
old_sig = mldsa.sign(pq_sk, b"aegis-kem-init-v1", old_nonce + ek)
h = Hostile([b"PQKEMEK %d %s %d %s END\r\n" % (len(ek), ek.hex().encode(), len(old_sig), old_sig.hex().encode())])
try:
    fleet.provision({"name": "replay", "host": "127.0.0.1", "port": h.port, "pq_pub_file": pqf}, store,
                    mldsa.keypair()[1], "gid", {}, timeout=2)
    kem_replay_refused = False
except ValueError:
    kem_replay_refused = True

# signed hostile claims: the signature is valid (ES256 for "psa", ML-DSA-65 for the PQ kinds), the claims are random
# CBOR of any shape. attest() must return a verdict, never raise, never admit.


def rand_cbor(depth=0):
    r = R.randrange(9 if depth < 4 else 5)
    if r == 0:
        return R.randrange(-2 ** 40, 2 ** 40)
    if r == 1:
        return bytes(R.randrange(256) for _ in range(R.choice([0, 1, 32, R.randrange(70)])))
    if r == 2:
        return "".join(chr(R.randrange(32, 127)) for _ in range(R.randrange(12)))
    if r == 3:
        return R.choice([True, False, None])
    if r == 4:
        return R.choice(["SPE", "NSPE", "BOOT", fleet.TEE_PROFILE, fleet.TEE_DEVHUK_PROFILE])
    if r in (5, 6):
        return [rand_cbor(depth + 1) for _ in range(R.randrange(4))]
    if r == 7:
        return cbor.Tag(R.randrange(30), rand_cbor(depth + 1))
    return {R.choice([R.randrange(-5, 12), -75006, 2399, -75008, 10, 265, 256, "k"]): rand_cbor(depth + 1)
            for _ in range(R.randrange(5))}


def rand_claims():
    claims = {R.choice([-75008, 10]): R.choice([b"\x00" * 32, rand_cbor()])}
    for k in R.sample([265, -75000, 256, -75009, 2399, -75006, 1, "x"], R.randrange(1, 6)):
        if k in (2399, -75006) and R.random() < 0.6:
            claims[k] = [{R.choice([1, 2, 4, 5, 6, 9]): rand_cbor(2) for _ in range(R.randrange(4))}
                         for _ in range(R.randrange(3))]
        else:
            claims[k] = rand_cbor(1)
    return claims


from test_gateway_hardening import es256_token  # noqa: E402
signed_attests = signed_raised = signed_admitted = 0
tee_pf = os.path.join(store, "tee.pub")
open(tee_pf, "w").write(pq_pk.hex())
for _ in range(min(N, 300)):
    claims = rand_claims()
    payload = cbor.dumps(claims)
    for kind in ("psa", "aegis-tee"):
        if kind == "psa":
            tok = es256_token(key, payload)
            line = b"TOKEN %d %s END\r\n" % (len(tok), tok.hex().encode())
            conf = {"name": "s", "kind": "psa", "iak_pub_pem": pemf}
        else:
            sig = mldsa.sign(pq_sk, fleet.PQ_LABEL, payload)
            line = b"PQTOKEN %d %s %d %s END\r\n" % (len(payload), payload.hex().encode(), len(sig), sig.hex().encode())
            conf = {"name": "s", "kind": "aegis-tee", "pq_pub_file": tee_pf, "profile": fleet.TEE_DEVHUK_PROFILE,
                    "allow_dev_profile": True}
        h = Hostile([line])
        conf.update({"host": "127.0.0.1", "port": h.port, "allowed": allowed})
        signed_attests += 1
        try:
            v = fleet.attest(conf, psa_token.verify_with_cryptography, store, timeout=2)
            signed_admitted += v["admitted"]
        except Exception as e:  # noqa: BLE001
            signed_raised += 1
            if len(broken) < 8:
                broken.append("attest() raised on signed hostile claims (%s): %r" % (kind, e))
if signed_admitted:
    broken.append("signed random claims were admitted")

endpoint_result = {"random_replies": min(N, 400) * 2, "admitted_by_garbage": admitted_by_garbage,
                   "classic_token_downgrade_refused": downgrade_refused, "kem_key_replay_refused": kem_replay_refused,
                   "signed_hostile_claims": signed_attests, "signed_hostile_raised": signed_raised,
                   "signed_hostile_admitted": signed_admitted}
if admitted_by_garbage:
    broken.append("a garbage reply was admitted")
if not downgrade_refused:
    broken.append("downgrade to a classic-only token was admitted")
if not kem_replay_refused:
    broken.append("a replayed KEM key was accepted")

# ---- 4. one transcript: signed pieces that are not the transcript of the appraised quote ----


def flip(b):
    b = bytearray(b)
    b[R.randrange(len(b))] ^= 1 << R.randrange(8)
    return bytes(b)


def other_transcript_piece(kind, challenge, tok_hash):
    """A PQKEMEK reply whose signature is valid under the endpoint's key, for something else than
    T2 = H(kem-init || H(quote || challenge || token hash) || ek) under the label aegis-kem-init-v2."""
    ek, _ = mlkem.keypair()
    ek2, _ = mlkem.keypair()
    t1 = transcript.quote(challenge, tok_hash)
    t2 = transcript.kem_init(t1, ek)
    label, msg, sent = transcript.KEM_INIT_LABEL, t2, ek
    if kind == "first-version":            # what a firmware from before the transcript signs
        label, msg = fleet.KEM_INIT_LABEL, challenge + ek
    elif kind == "other-challenge":
        msg = transcript.kem_init(transcript.quote(flip(challenge), tok_hash), ek)
    elif kind == "other-token":            # the quote of another firmware, or of another boot
        msg = transcript.kem_init(transcript.quote(challenge, flip(tok_hash)), ek)
    elif kind == "other-key":              # signed for one KEM key, sent with another
        sent = ek2
    elif kind == "first-version-label":    # the transcript under the old label
        label = fleet.KEM_INIT_LABEL
    elif kind == "transcript-label":       # the old message under the transcript's label
        msg = challenge + ek
    elif kind == "quote-label":            # a quote signature is not a KEM key signature
        label = fleet.PQ_LABEL
    elif kind == "earlier-step":           # T1 in the place of T2
        msg = t1
    elif kind == "later-step":
        msg = transcript.kem_fin(t2, b"ct", b"cred")
    sig = mldsa.sign(pq_sk, label, msg)
    if kind == "damaged-signature":
        sig = flip(sig)
    return b"PQKEMEK %d %s %d %s END\r\n" % (len(sent), sent.hex().encode(), len(sig), sig.hex().encode())


KINDS = ("first-version", "other-challenge", "other-token", "other-key", "first-version-label", "transcript-label",
         "quote-label", "earlier-step", "later-step", "damaged-signature", "random-line")
gw_sk_t = mldsa.keypair()[1]
transcript_tried = transcript_accepted = transcript_raised = 0
for i in range(min(N, 220)):
    kind = KINDS[i % len(KINDS)]
    challenge, tok_hash = os.urandom(32), os.urandom(32)
    if kind == "random-line":
        line = R.choice([b"PQKEMEK ", b"PQKEMEK 1184 ", b"PQKEMOK ", b""]) + \
            bytes(R.randrange(32, 127) for _ in range(R.randrange(0, 300))) + b"\r\n"
    else:
        line = other_transcript_piece(kind, challenge, tok_hash)
    h = Hostile([line, b"PQKEMOK " + b"00" * 32 + b" END\r\n"])
    transcript_tried += 1
    try:
        fleet.provision({"name": "t", "host": "127.0.0.1", "port": h.port, "pq_pub_file": pqf, "transcript": "v2"},
                        store, gw_sk_t, "gid", {}, timeout=2,
                        quote={"challenge": challenge.hex(), "token_sha3_256": tok_hash.hex()})
        transcript_accepted += 1
        broken.append("transcript v2: a %s piece was given a credential" % kind)
    except ValueError:
        if len(h.replies) != 1:            # the second reply was asked for: a PQKEMFIN went out
            transcript_accepted += 1
            broken.append("transcript v2: a credential was sent for a %s piece" % kind)
    except Exception as e:  # noqa: BLE001
        transcript_raised += 1
        if len(broken) < 8:
            broken.append("provision() raised %r on a %s piece" % (e, kind))
transcript_result = {"pieces_that_are_not_the_transcript": transcript_tried, "kinds": len(KINDS),
                     "given_a_credential": transcript_accepted, "raised_other_than_ValueError": transcript_raised}

# ---- 5. endorsed enrolment: record files that are not a trusted endorser's statement about this key ----
import endorsement  # noqa: E402
import wire  # noqa: E402

end_dir = tempfile.mkdtemp()
e_pk, e_sk = mldsa.keypair()            # the endorser the policy trusts
r_pk, r_sk = mldsa.keypair()            # one it does not
with open(os.path.join(end_dir, "endorser.pub"), "w") as f:
    f.write(e_pk.hex())
with open(os.path.join(end_dir, "dev.pub"), "w") as f:
    f.write(pq_pk.hex())
trusted_list = [{"name": "bench", "pk_file": "endorser.pub", "pk_sha256": endorsement.pk_sha256(e_pk)}]
end_ep = {"name": "dev", "kind": "aegis-pq", "pq_pub_file": "dev.pub", "endorsement": "required",
          "endorsement_file": "dev.json", "iak_pub_pem": pemf, "allowed": allowed, "host": "127.0.0.1"}
good_body = {"v": 1, "type": "endorsement", "device": "dev", "kind": "aegis-pq", "device_pk_alg": "ML-DSA-65",
             "device_pk_sha256": endorsement.pk_sha256(pq_pk),
             "measurements": [{"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER},
                              {"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER}],
             "evidence": {"challenge": "11" * 32, "token_sha3_256": "22" * 32}, "device_state": "development",
             "endorser": "bench", "endorser_pk_sha256": endorsement.pk_sha256(e_pk), "issued": int(time.time()) - 10}
good_rec = endorsement.sign(good_body, e_sk, pq_pk)
good_bytes = endorsement.dumps(good_rec)
end_ep["endorsement_sha256"] = endorsement.record_sha256(good_rec)     # as enroll-endorsed pins it
rec_file = os.path.join(end_dir, "dev.json")


def rand_json(depth=0):
    r = R.randrange(8 if depth < 4 else 5)
    if r == 0:
        return R.randrange(-2 ** 40, 2 ** 40)
    if r == 1:
        return "".join(R.choice("0123456789abcdef") for _ in range(R.choice([0, 2, 64, R.randrange(80)])))
    if r == 2:
        return R.choice([True, False, None, 1.5, "dev", "aegis-pq", "endorsement", endorsement.FORMAT])
    if r in (3, 4):
        return R.choice([good_body["device_pk_sha256"], good_body["endorser_pk_sha256"], good_rec["sig"], 1, "x"])
    if r == 5:
        return [rand_json(depth + 1) for _ in range(R.randrange(4))]
    return {R.choice(sorted(endorsement._BODY_KEYS | endorsement._RECORD_KEYS)): rand_json(depth + 1)
            for _ in range(R.randrange(6))}


def hostile_record(kind):
    """(file bytes, the key file's content) for one record that must not make the pinned key trusted, except where
    the bytes still decode to exactly what the endorser signed (a mutation in white space, say)."""
    body, key, sk, label = json.loads(json.dumps(good_body)), pq_pk, None, endorsement.LABEL
    if kind == "bytes":
        return mutate(good_bytes), key
    if kind == "random-json":
        return json.dumps(rand_json()).encode(), key
    if kind == "another-key-pinned":            # the record is the endorser's; the key file is someone else's
        return good_bytes, R.choice([r_pk, tf.PQ_KEYS[1][0], mutate(pq_pk)])
    if kind in ("edited", "edited-resigned", "rogue"):   # claims changed: old signature, or a key the policy lacks
        k = R.choice(sorted(body))
        if R.random() < 0.7:
            body[k] = R.choice([rand_json(2), "x", 0])
        else:
            del body[k]
        if body == good_body:
            body["notes"] = "edited"
        if kind != "edited":
            sk = r_sk
        if kind == "rogue":                      # ... that says so itself
            body["endorser_pk_sha256"] = endorsement.pk_sha256(r_pk)
    elif kind == "other-label":                  # the endorser's key, signing these bytes as something else
        sk, label = e_sk, R.choice([fleet.CRED_LABEL, fleet.PQ_LABEL, wire.LABEL_IDENTITY, wire.LABEL_QUOTE,
                                    endorsement.ENDORSER_LABEL, transcript.KEM_INIT_LABEL, b"aegis-endorsement-v2"])
    elif kind == "superseded":                   # the trusted endorser's record for this device and key, not the pinned one
        sk = e_sk
        body["issued"] -= R.randrange(0, 10 ** 6)
    elif kind == "endorsed-for-something-else":  # a genuine record of the trusted endorser: not for this entry
        sk = e_sk
        which = R.randrange(5)
        if which == 0:
            body["device"] = R.choice(["dev2", "Dev", "dev ", "de"])
        elif which == 1:
            body["kind"] = R.choice(["aegis-device", "aegis-linux", "aegis-tee"])
        elif which == 2:
            body["profile"] = fleet.DEVICE_TFM_PROFILE
        elif which == 3:
            body["device_pk_sha256"] = endorsement.pk_sha256(R.choice([r_pk, tf.PQ_KEYS[1][0]]))
        else:
            body["expires"] = body["issued"] + R.randrange(1, 10)
    rec = dict(good_rec, body=body)
    if sk is not None:
        try:
            rec["sig"] = mldsa.sign(sk, label, wire.canonical(body)).hex()
        except (TypeError, ValueError):
            pass
    return json.dumps(rec).encode(), key


END_KINDS = ("bytes", "bytes", "bytes", "edited", "edited-resigned", "rogue", "other-label",
             "endorsed-for-something-else", "another-key-pinned", "random-json", "superseded")
end_tried = end_trusted = end_raised = end_same = end_admitted = end_contacted = 0
with open(rec_file, "wb") as f:
    f.write(good_bytes)
_, e0 = fleet.device_key(end_ep, end_dir, trusted_list)
want = dict(good_body, endorser_name="bench", record_sha256=endorsement.record_sha256(good_rec))
if e0 != want:
    broken.append("endorsement: the good record was not accepted as signed")
for i in range(N):
    kind = END_KINDS[i % len(END_KINDS)]
    data, key = hostile_record(kind)
    with open(rec_file, "wb") as f:
        f.write(data)
    with open(os.path.join(end_dir, "dev.pub"), "w") as f:
        f.write(key.hex())
    end_tried += 1
    try:
        pk_used, e = fleet.device_key(end_ep, end_dir, trusted_list)
        if pk_used == pq_pk and e == want:
            end_same += 1                       # the bytes still say exactly what the endorser signed, for this key
        else:
            end_trusted += 1
            if len(broken) < 12:
                broken.append("endorsement: a %s record made a key trusted" % kind)
    except endorsement.Refused:
        pass
    except ValueError:
        if kind != "another-key-pinned":        # a key file that is not hex at all is refused as such
            end_raised += 1
            broken.append("endorsement: device_key() raised a plain ValueError on a %s record" % kind)
    except Exception as e:  # noqa: BLE001
        end_raised += 1
        if len(broken) < 12:
            broken.append("endorsement: device_key() raised %r on a %s record" % (e, kind))
    if i % 10 == 0 and kind != "bytes":         # the loop's own view: refused, and the endpoint never asked
        h = Hostile([b"PQTOKEN 1 00 1 00 END\r\n"])
        try:
            v = fleet.attest(dict(end_ep, port=h.port), psa_token.verify_with_cryptography, end_dir, 1, trusted_list)
            end_admitted += v["admitted"]
            end_contacted += len(h.replies) != 1
        except Exception as e:  # noqa: BLE001
            end_raised += 1
            broken.append("endorsement: attest() raised %r on a %s record" % (e, kind))
endorsement_result = {"records_that_are_not_the_endorsement": end_tried, "kinds": len(set(END_KINDS)),
                      "made_a_key_trusted": end_trusted, "still_exactly_the_signed_record": end_same,
                      "raised_other_than_Refused": end_raised, "admitted": end_admitted,
                      "endpoint_contacted": end_contacted}
if end_admitted or end_contacted:
    broken.append("endorsement: an endpoint without a valid endorsement was admitted or contacted")

# ---- 6. standard evidence: EAT, EAR and the endorsement in COSE_Sign1 with ML-DSA-65 ----
import hashlib  # noqa: E402

import cose  # noqa: E402
import eat  # noqa: E402

sys.path.insert(0, os.path.abspath(os.path.join(ROOT, "tools")))
try:
    import verify_evidence as checker       # third-party libraries only; a second reading of the document
except Exception:  # noqa: BLE001
    checker = None

std_dir = tempfile.mkdtemp()
with open(os.path.join(std_dir, "dev.pub"), "w") as f:
    f.write(pq_pk.hex())
v_pk, v_sk = mldsa.keypair()            # the verifier that signs results
STD_MEAS = [("SPE", tf.GOOD_S), ("NSPE", tf.GOOD_NS)]
std_ep = {"name": "dev", "kind": "aegis-tee", "host": "127.0.0.1", "pq_pub_file": "dev.pub",
          "profile": fleet.TEE_PROFILE, "evidence_format": "eat-cose-v1",
          "allowed": [{"type": n, "measurement_value": d} for n, d in STD_MEAS]}


def std_claims(ch):
    return {10: ch, 256: b"\x01" + hashlib.sha256(pq_pk).digest(), 265: eat.EVIDENCE_PROFILE, 275: 1,
            -82400: fleet.TEE_PROFILE, 273: [eat.measured_component(n, bytes.fromhex(d)) for n, d in STD_MEAS]}


def std_sign(sk, protected, payload, unprotected=None, tag=18):
    sig = mldsa.sign_raw(sk, cbor.dumps(["Signature1", protected, b"", payload]))
    body = [protected, unprotected or {}, payload, sig]
    return cbor.dumps(cbor.Tag(tag, body) if tag is not None else body)


def hostile_header(pk, sk, payload, typ=cose.TYP_EAT_CWT):
    """A valid signature over a header that is not the profile's, or around it."""
    hdr = {1: -49, 4: cose.key_thumbprint(pk), 16: typ}
    kw = {}
    which = R.randrange(11)
    if which == 0:
        hdr[1] = R.choice([-48, -50, -7, -8, -35, -257, 0, "ML-DSA-65", None])
    elif which == 1:
        del hdr[R.choice([1, 4, 16])]
    elif which == 2:
        hdr[R.choice([2, 3, 5, 6, 15, 33, -1, "x"])] = rand_cbor(2)
    elif which == 3:
        hdr[4] = R.choice([cose.key_thumbprint(r_pk), hdr[4][:16], hdr[4] + b"\x00", hdr[4].hex(), b""])
    elif which == 4:
        hdr[16] = R.choice(["application/cwt", "application/eat+cwt ", 61, "", "application/eat+jwt"])
    elif which == 5:
        kw["unprotected"] = {R.choice([1, 4, 16, 33, "x"]): rand_cbor(2)}
    elif which == 6:
        kw["tag"] = R.choice([None, 16, 17, 61, 98, 0])
    elif which == 7:
        return std_sign(sk, cbor.dumps(dict(reversed(sorted(hdr.items())))), payload)    # another order of the map
    elif which == 8:
        good = std_sign(sk, cbor.dumps(hdr, sort=True), payload)
        return good[:2] + b"\x59\x00\x3c" + good[4:]                                  # a longer head, the same items
    elif which == 9:
        return std_sign(sk, cbor.dumps(hdr, sort=True), payload) + bytes(R.randrange(256) for _ in range(R.randrange(1, 4)))
    else:
        return std_sign(r_sk, cbor.dumps(hdr, sort=True), payload)                     # this kid, another key's signature
    return std_sign(sk, cbor.dumps(hdr, sort=True), payload, **kw)


def hostile_claims(c):
    """Claims that are not the profile's, or not what the policy allows, from good ones. None: the edit changed
    nothing."""
    before = cbor.dumps(c, sort=True)
    which = R.randrange(8)
    if which == 0:
        del c[R.choice(list(c))]
    elif which == 1:
        c[R.choice(list(c))] = rand_cbor(1)
    elif which == 2:
        k = R.choice([R.randrange(-90000, 3000), "x", 266, 1, 2, 4, 6, 8, -82401, -82408, 1000])
        if k == 263:
            return None                         # dbgstat is a claim of the profile
        c[k] = rand_cbor(1)
    elif which == 3:
        n, d = R.choice(STD_MEAS)
        other = bytearray(bytes.fromhex(d))
        other[R.randrange(32)] ^= 1 << R.randrange(8)
        c[273] = [eat.measured_component(n, bytes(other))] + [m for m in c[273] if cbor.loads(m[1])[1][0] != n]
    elif which == 4:
        c[273] = c[273] + [eat.measured_component(R.choice(["EXTRA", "SPE", "BL2"]), bytes(R.randrange(256) for _ in range(32)))]
    elif which == 5:
        c[273] = R.choice([[], c[273][:1] * 2, [[294, c[273][0][1]]], [[295, cbor.dumps(rand_cbor(1))]],
                           [[295, cbor.dumps({2: [1, bytes(32)], 1: ["SPE"]})]], [c[273][0] + [1]], c[273][0]])
    elif which == 6:
        c[10] = bytes(R.randrange(256) for _ in range(R.choice([32, 32, 31, 33, 0])))
    else:
        return cbor.dumps(rand_cbor())
    after = cbor.dumps(c, sort=True)
    return None if after == before else after


class Responder(threading.Thread):
    """Answers one PQEAT with what make(challenge) returns."""

    def __init__(self, make):
        super().__init__(daemon=True)
        self.make = make
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(2)
        self.port = self.srv.getsockname()[1]
        self.start()

    def run(self):
        c, _ = self.srv.accept()
        try:
            line = c.recv(4096).split()
            ev = self.make(bytes.fromhex(line[1].decode()))
            c.sendall(b"PQEAT %d %s END\r\n" % (len(ev), ev.hex().encode()))
        finally:
            c.close()
            self.srv.close()


std = {"decoder_objects": 0, "decoder_accepted": 0, "decoder_raised": 0, "attests": 0, "admitted": 0, "raised": 0,
       "control_admitted": 0, "records": 0, "record_trusted": 0, "record_raised": 0,
       "checker": "tools/verify_evidence.py" if checker else "skipped (needs pycose, cbor2, ML-DSA in cryptography)",
       "checker_objects": 0, "checker_verified": 0, "checker_verified_what_the_verifier_refuses": 0}


def std_broken(text):
    if len(broken) < 20:
        broken.append("standard evidence: " + text)


def checker_says(fn, data, pk):
    """True if the standalone checker reports the object as verified (its main() prints every exception as 'not
    verified')."""
    if checker is None:
        return None
    std["checker_objects"] += 1
    try:
        fn(data, pk)
    except Exception:  # noqa: BLE001
        return False
    std["checker_verified"] += 1
    return True


# the control: the good objects are accepted by everything, so the refusals below are not refusals of everything
good_ch = bytes(R.randrange(256) for _ in range(32))
good_ev = cose.sign1(pq_sk, pq_pk, cbor.dumps(std_claims(good_ch), sort=True))
good_ear = cose.sign1(v_sk, v_pk, eat.ear_payload(
    {"endpoint": "dev", "kind": "aegis-tee", "admitted": True, "reasons": [], "trust": "trustzone", "enrolment": "endorsed",
     "device_pk_sha256": hashlib.sha256(pq_pk).hexdigest(),
     "endorsement": {"endorser_name": "bench", "record_sha256": "00" * 32, "device_pk_sha256": "11" * 32,
                     "device_state": "development", "issued": 5}},
    {"stage": "appraised", "signature": True, "components_ok": True, "format": "eat-cose-v1", "nonce": good_ch,
     "ueid": b"\x01" + hashlib.sha256(pq_pk).digest(), "platform": fleet.TEE_PROFILE,
     "components": [{"measurement_type": n, "measurement_value": d} for n, d in STD_MEAS]},
    eat.policy_id(b"{}"), 1000, 2000))
good_cose = endorsement.sign_cose(good_body, e_sk, e_pk, pq_pk)
if eat.read_evidence(cose.verify1(good_ev, pq_pk).payload, pq_pk)["nonce"] != good_ch \
        or eat.read_ear(good_ear, v_pk)["status"] != "affirming" or endorsement.loads(good_cose)["body"] != good_body:
    std_broken("a good object was not read as signed")
if checker and not (checker_says(checker.check_evidence, good_ev, pq_pk) and checker_says(checker.check_result, good_ear, v_pk)
                    and checker_says(checker.check_endorsement, good_cose, e_pk)):
    std_broken("the standalone checker does not verify a good object")
std["checker_objects"] = std["checker_verified"] = 0
for _ in range(3):
    h = Responder(lambda ch: cose.sign1(pq_sk, pq_pk, cbor.dumps(std_claims(ch), sort=True)))
    std["control_admitted"] += fleet.attest(dict(std_ep, port=h.port), None, std_dir, 2)["admitted"]
if std["control_admitted"] != 3:
    std_broken("the control (good evidence) was not admitted")

# 6a. bytes that are not exactly the signed object
for i in range(N):
    what, good, pk = (("evidence", good_ev, pq_pk), ("result", good_ear, v_pk), ("endorsement", good_cose, e_pk))[i % 3]
    data = mutate(good)
    if data == good:
        continue
    std["decoder_objects"] += 1
    try:
        if what == "evidence":
            eat.read_evidence(cose.verify1(data, pk).payload, pk)
        elif what == "result":
            eat.read_ear(data, pk)
        else:
            endorsement.check(endorsement.loads(data), endorsement.trusted(trusted_list, end_dir), "dev", "aegis-pq",
                              None, pq_pk, time.time())
        std["decoder_accepted"] += 1
        std_broken("a mutated %s was accepted" % what)
    except (cose.Refused, eat.Refused, endorsement.Refused):
        pass
    except Exception as e:  # noqa: BLE001
        std["decoder_raised"] += 1
        std_broken("the %s decoder raised %r" % (what, e))
    fn = checker and {"evidence": checker.check_evidence, "result": checker.check_result,
                      "endorsement": checker.check_endorsement}[what]
    if checker_says(fn, data, pk):
        std_broken("the standalone checker verified a mutated %s" % what)

# 6b. valid signatures over a header or claims that are not the profile's or not this cycle's: the verifier's loop
for i in range(min(N, 600)):
    made = {}

    def make(ch, i=i, made=made):
        if i % 2:
            data = hostile_header(pq_pk, pq_sk, cbor.dumps(std_claims(ch), sort=True))
        else:
            payload = None
            while payload is None:
                payload = hostile_claims(std_claims(ch))
            data = cose.sign1(pq_sk, pq_pk, payload)
        made["data"] = data
        return data
    h = Responder(make)
    std["attests"] += 1
    try:
        v = fleet.attest(dict(std_ep, port=h.port), None, std_dir, 2)
        if v["admitted"]:
            std["admitted"] += 1
            std_broken("hostile %s admitted: %s..." % ("header" if i % 2 else "claims", made.get("data", b"").hex()[:160]))
    except Exception as e:  # noqa: BLE001
        std["raised"] += 1
        std_broken("attest() raised %r" % (e,))
    data = made.get("data")
    if data is not None and checker_says(checker and checker.check_evidence, data, pq_pk):
        # the checker has no policy and no challenge; it must still not verify what the verifier's decoder refuses
        try:
            eat.read_evidence(cose.verify1(data, pq_pk).payload, pq_pk)
        except (cose.Refused, eat.Refused) as e:
            std["checker_verified_what_the_verifier_refuses"] += 1
            std_broken("the standalone checker verified evidence the verifier refuses (%s): %s..." % (e, data.hex()[:160]))

# 6c. a COSE record that is not the pinned one: other bytes, the trusted endorser's signature over other claims, an
# untrusted endorser's over these
cose_ep = dict(end_ep, endorsement_sha256=hashlib.sha256(good_cose).hexdigest())
with open(os.path.join(end_dir, "dev.pub"), "w") as f:
    f.write(pq_pk.hex())
with open(rec_file, "wb") as f:
    f.write(good_cose)
if fleet.device_key(cose_ep, end_dir, trusted_list)[1]["record_sha256"] != cose_ep["endorsement_sha256"]:
    std_broken("the good COSE record was not accepted")
good_claims = cbor.loads(cose.parse(good_cose).payload)
for i in range(min(N, 900)):
    kind = i % 3
    if kind == 0:
        data = mutate(good_cose)
    else:
        c = dict(good_claims)
        which = R.randrange(4)
        if which == 0:
            del c[R.choice(list(c))]
        elif which == 1:
            c[R.choice(list(c))] = rand_cbor(1)
        elif which == 2:
            c[R.choice([R.randrange(-90000, 3000), "x", 263, 266, 275, 1000])] = rand_cbor(1)
        signer = (e_sk, e_pk) if kind == 1 else (r_sk, r_pk)
        data = hostile_header(signer[1], signer[0], cbor.dumps(c, sort=True)) if R.random() < 0.3 else \
            cose.sign1(signer[0], signer[1], cbor.dumps(c, sort=True))
    if data == good_cose:
        continue
    with open(rec_file, "wb") as f:
        f.write(data)
    std["records"] += 1
    try:
        fleet.device_key(cose_ep, end_dir, trusted_list)
        std["record_trusted"] += 1
        std_broken("a COSE record that is not the pinned one made a key trusted")
    except endorsement.Refused:
        pass
    except Exception as e:  # noqa: BLE001
        std["record_raised"] += 1
        std_broken("device_key() raised %r on a COSE record" % (e,))
    if kind == 0 and checker_says(checker and checker.check_endorsement, data, e_pk):
        std_broken("the standalone checker verified a mutated endorsement")
    if kind == 2 and checker_says(checker and checker.check_endorsement, data, e_pk):
        std_broken("the standalone checker verified an endorsement signed by another key")

# ---- 7. the audit log and the signed policy ----
import contextlib  # noqa: E402
import io  # noqa: E402

import audit  # noqa: E402
import signed_policy  # noqa: E402

try:
    import verify_audit as audit_checker    # third-party libraries only; a second reading of the document
except Exception:  # noqa: BLE001
    audit_checker = None

ap = {"checker": audit_checker is not None, "logs": 0, "accepted_with_the_anchor": 0, "raised_other_than_Refused": 0,
      "a_shorter_log_without_the_anchor": 0,
      "checker_verified_with_the_anchor": 0, "readers_disagree": 0, "policies": 0, "policy_loaded": 0,
      "policy_raised_other_than_PolicyRefused": 0, "checker_verified_policy": 0, "hostile_verdicts": 0,
      "trail_raised": 0, "trail_entries": 0}


def ap_broken(text):
    if len(broken) < 20:
        broken.append("audit and policy: " + text)


def make_log(pk, sk, batches, t0=1_800_000_000):
    """A log of that many batches in a new directory; returns its records."""
    d = os.path.join(tempfile.mkdtemp(), "audit")
    lg = audit.Log(d, pk, lambda: sk)
    for i in range(batches):
        for j in range(R.randrange(1, 4)):
            lg.add(R.choice(["admit", "refuse", "issue", "revoke"]), "dev%d" % j,
                   {"kind": "aegis-device", "measurements": {"SPE": bytes(32)}, "reasons": ["r%d" % i]}, t0 + i)
        lg.flush(t0 + i)
    out = []
    for _, path in audit.segments(d):
        with open(path, "rb") as f:
            out += [raw for _, raw in audit.split(f.read())]
    return out


def readers(data, anchor):
    """(accepted by the verifier's reader, verified by the checker) for one log file's bytes; None for the checker
    without its libraries. anchor: a batch record both must find in the log, or None."""
    with open(os.path.join(ap_dir, "audit-000001.cbor"), "wb") as f:
        f.write(data)
    try:
        audit.verify(ap_dir, [v_pk], anchors=[anchor] if anchor else [])
        ours = True
    except audit.Refused:
        ours = False
    except Exception as e:  # noqa: BLE001
        ours = False
        ap["raised_other_than_Refused"] += 1
        ap_broken("audit.verify raised %r" % (e,))
    theirs = None
    if audit_checker is not None:
        try:
            audit_checker.check_log([ap_dir], [v_pk], [ap_anchor] if anchor else [])
            theirs = True
        except Exception:  # noqa: BLE001 - its main() prints every exception as "not verified"
            theirs = False
    return ours, theirs


ap_dir = os.path.join(tempfile.mkdtemp(), "audit")
os.makedirs(ap_dir)
good_log = make_log(v_pk, v_sk, 6)
other_log = make_log(v_pk, v_sk, 6)         # another log of the same key
ap_anchor = os.path.join(tempfile.mkdtemp(), "anchor.cbor")
with open(ap_anchor, "wb") as f:
    f.write(good_log[-1])
good_blob = b"".join(good_log)
if readers(good_blob, good_log[-1]) not in ((True, True), (True, None)):
    ap_broken("the control (the log as written, with its anchor) was not accepted")


def hostile_log():
    """The bytes of a log that is not the one the verifier wrote."""
    recs = list(good_log)
    i = R.randrange(len(recs))
    which = R.randrange(10)
    if which == 0:
        return mutate(good_blob)
    if which == 1:
        return good_blob[:R.randrange(len(good_blob))]                  # cut off anywhere, between batches too
    if which == 2:
        del recs[i]
    elif which == 3:
        j = R.randrange(len(recs))
        recs[i], recs[j] = recs[j], recs[i]
    elif which == 4:
        recs.insert(R.randrange(len(recs) + 1), recs[i])
    elif which == 5:
        recs[i] = other_log[i]                                          # the same number, another log
    elif which == 6:
        recs.insert(R.randrange(len(recs) + 1), cbor.dumps(rand_cbor(1)))
    else:
        c = cbor.loads(cose.parse(recs[i]).payload)
        edit = R.randrange(5)
        if edit == 0 and c[7]:
            c[7][R.randrange(len(c[7]))][2] = R.choice(["admit", "refuse", "revoke"])
        elif edit == 1:
            c[R.choice([3, 5, 6])] += R.choice([-1, 1])
        elif edit == 2:
            c[R.choice(list(c))] = rand_cbor(1)
        elif edit == 3:
            c[7] = c[7] + [{1: c[5], 2: "admit", 3: "evil"}]
        else:
            del c[R.choice(list(c))]
        payload = cbor.dumps(c, sort=True)
        if which == 7:      # the verifier's signature of the batch as it was
            tag = cbor.loads(recs[i])
            recs[i] = cose.assemble(tag.value[0], payload, tag.value[3])
        elif which == 8:    # a key that is not the verifier's
            recs[i] = cose.sign1(r_sk, r_pk, payload, typ=audit.TYP)
        else:               # the verifier's key under a header that is not a batch's
            recs[i] = hostile_header(v_pk, v_sk, cose.parse(recs[i]).payload, typ=audit.TYP)
    return b"".join(recs)


for _ in range(min(N, 1500)):
    data = hostile_log()
    if data == good_blob:
        continue
    ap["logs"] += 1
    ours, theirs = readers(data, good_log[-1])
    if ours:
        ap["accepted_with_the_anchor"] += 1
        ap_broken("a log that is not the one written was accepted with its anchor: %s..." % data.hex()[:120])
    if theirs:
        ap["checker_verified_with_the_anchor"] += 1
        ap_broken("the standalone checker verified a log that is not the one written")
    ours, theirs = readers(data, None)      # without the anchor a log cut off between batches is a log, for both
    ap["a_shorter_log_without_the_anchor"] += ours
    if theirs is not None and ours != theirs:
        ap["readers_disagree"] += 1
        ap_broken("the two readers disagree on a log (verifier %s, checker %s): %s..." % (ours, theirs, data.hex()[:120]))

# 7b. policy files
pol_state, pol_dir = tempfile.mkdtemp(), tempfile.mkdtemp()
o_pk, o_sk = mldsa.keypair()                # the operator's policy-signing key
with open(os.path.join(pol_state, signed_policy.SIGNERS_FILE), "wb") as f:
    f.write(signed_policy.signers_file([("ops", o_pk)]))
POLICY_JSON = json.dumps({"endpoints": [{"name": "dev", "kind": "aegis-pq", "host": "192.0.2.1", "port": 7444,
                                         "pq_pub_file": "dev.pub", "allowed": []}]}).encode()
OTHER_JSON = POLICY_JSON.replace(b"192.0.2.1", b"192.0.2.9")
pol_file = os.path.join(pol_dir, "fleet.cose")
ACCEPTED = 6                                # the version this verifier has accepted
good_policy = signed_policy.sign(o_sk, o_pk, POLICY_JSON, ACCEPTED, "ops")
with open(pol_file, "wb") as f:
    f.write(good_policy)
if fleet.load_policy(pol_file, pol_state, remember=True)[1] != POLICY_JSON or (
        audit_checker and audit_checker.check_policy(good_policy, [o_pk], None, ACCEPTED)["version"] != ACCEPTED):
    ap_broken("the control (a signed policy) was not loaded")
good_pclaims = cbor.loads(cose.parse(good_policy, signed_policy.MAX_SIGNED).payload)
WRONG = {1: lambda: rand_cbor(1), 2: lambda: R.choice([0, -1, "7", None, True, [7], 1 << 60]),
         3: lambda: R.choice(["now", -5, None, 1 << 41]),
         4: lambda: R.choice([b"", b"{", b"[]", b"{}", "text", 5, json.dumps(rand_json()).encode(), POLICY_JSON[:-1],
                              b'{"endpoints": [], "endpoints": []}', bytes(R.randrange(256) for _ in range(40))]),
         5: lambda: R.choice([5, "", "x" * 65, None, b"ops"]), 6: lambda: R.choice(["", 7, "y" * 65, None])}


def hostile_policy():
    """A policy file that this verifier must not run from."""
    which = R.randrange(8)
    if which == 0:
        return mutate(good_policy)
    if which == 1:          # somebody else's key; the verifier's own identity
        sk, pk = R.choice([(r_sk, r_pk), (v_sk, v_pk)])
        return signed_policy.sign(sk, pk, POLICY_JSON, ACCEPTED + 1, "ops")
    if which == 2:          # an older version, or another policy under the accepted one
        version = R.randrange(1, ACCEPTED + 1)
        return signed_policy.sign(o_sk, o_pk, OTHER_JSON if version == ACCEPTED or R.random() < 0.5 else POLICY_JSON,
                                  version, "ops")
    c = {**good_pclaims, 2: ACCEPTED + 1}
    if which == 3:          # the signer's signature under another typ
        return cose.sign1(o_sk, o_pk, cbor.dumps(c, sort=True), typ=R.choice([cose.TYP_EAT_CWT, audit.TYP, "", "x"]))
    if which == 4:          # ... or a header that is not the profile's
        return hostile_header(o_pk, o_sk, cbor.dumps(c, sort=True), typ=signed_policy.TYP)
    if which == 5:
        k = R.choice(list(WRONG))
        c[k] = WRONG[k]()
        if c[k] is None and k != 6:
            del c[k]
        elif k == 1 and c[k] == signed_policy.FORMAT:
            c[k] = 1
    elif which == 6:
        c[R.choice([0, 7, 8, -1, "x", 265])] = rand_cbor(1)
    else:                   # the claims in another order of the map
        return cose.sign1(o_sk, o_pk, cbor.dumps(dict(reversed(list(c.items())))), typ=signed_policy.TYP)
    return cose.sign1(o_sk, o_pk, cbor.dumps(c, sort=True), typ=signed_policy.TYP)


for _ in range(min(N, 1500)):
    data = hostile_policy()
    if data == good_policy:
        continue
    ap["policies"] += 1
    with open(pol_file, "wb") as f:
        f.write(data)
    try:
        fleet.load_policy(pol_file, pol_state, remember=True)
        ap["policy_loaded"] += 1
        ap_broken("a policy file that is not an accepted signed policy was loaded: %s..." % data.hex()[:160])
    except fleet.PolicyRefused:
        pass
    except Exception as e:  # noqa: BLE001
        ap["policy_raised_other_than_PolicyRefused"] += 1
        ap_broken("load_policy raised %r" % (e,))
    if audit_checker is not None:
        try:
            audit_checker.check_policy(data, [o_pk], None, ACCEPTED + 1 if data[:1] == b"\xd2" else None)
            # the checker knows no counter: told the version this verifier has reached, it must refuse what the
            # verifier refuses, unless that is a new version the verifier would also take
            try:
                signed_policy.check_version(signed_policy.open_signed(
                    data, signed_policy.load_signers(os.path.join(pol_state, signed_policy.SIGNERS_FILE))["keys"]),
                    signed_policy.last_version(pol_state))
            except ValueError:
                ap["checker_verified_policy"] += 1
                ap_broken("the standalone checker verified a policy the verifier refuses: %s..." % data.hex()[:160])
        except Exception:  # noqa: BLE001
            pass
if signed_policy.last_version(pol_state)["version"] != ACCEPTED:
    ap_broken("a hostile policy moved the verifier's version counter")

# 7c. the audit trail fed verdicts that hold anything
trail_state = tempfile.mkdtemp()
with open(os.path.join(trail_state, "identity.json"), "w") as f:
    json.dump({"body": {"v": 1, "type": "identity", "pk": v_pk.hex()}}, f)
with open(os.path.join(trail_state, "identity.sk"), "wb") as f:
    f.write(v_sk)
trail = fleet.AuditTrail(trail_state, fleet.AUDIT_SETTINGS, promise=False, start={"cmd": "fuzz"})
VERDICT_KEYS = ("endpoint", "kind", "time", "admitted", "reasons", "measurements", "device_pk_sha256", "enrolment",
                "trust", "endorsement", "quote", "attestation_result", "warning", "credential", "enforcement",
                "session_binding")
with contextlib.redirect_stderr(io.StringIO()):
    for i in range(min(N, 800)):
        v = {k: rand_cbor() for k in R.sample(VERDICT_KEYS, R.randrange(len(VERDICT_KEYS) + 1))}
        if R.random() < 0.5:
            v["endpoint"] = R.choice(["dev", "dev2", "x" * 200, "../../etc/passwd", "\ud800"])
        ap["hostile_verdicts"] += 1
        try:
            trail.decision(v, {k: rand_cbor() for k in R.sample(["stage", "format"], R.randrange(3))})
            if i % 7 == 0:
                trail.session_change({"name": rand_cbor()}, R.choice([None, {"id": rand_cbor(), "expires": rand_cbor()}]),
                                     rand_cbor())
                trail.policy({"sha256": rand_cbor(), "signed": rand_cbor()}, R.choice([None, rand_cbor(), {"endpoints": rand_cbor()}]))
                trail.policy_refused(rand_cbor())
            if i % 40 == 39 and not trail.flush(final=True):
                ap_broken("the trail wrote nothing for hostile verdicts")
        except Exception as e:  # noqa: BLE001
            ap["trail_raised"] += 1
            ap_broken("the audit trail raised %r on a hostile verdict" % (e,))
    trail.flush(final=True)
try:
    rep = audit.verify(os.path.join(trail_state, "audit"), [v_pk], with_entries=True)
    ap["trail_entries"] = len(rep["entries"])
    if ap["trail_entries"] < ap["hostile_verdicts"] // 4:
        ap_broken("the trail lost entries (%d of %d verdicts)" % (ap["trail_entries"], ap["hostile_verdicts"]))
    if audit_checker is not None:
        theirs = audit_checker.check_log([os.path.join(trail_state, "audit")], [v_pk], with_entries=True)
        if theirs["entries"] != json.loads(json.dumps(fleet._jsonable(rep["entries"]))):
            ap_broken("the two readers read different entries from the log of hostile verdicts")
except Exception as e:  # noqa: BLE001
    ap_broken("the log written from hostile verdicts does not verify: %r" % (e,))

# ---- 8. Aegis 1.2: the signed pack statement, the result's new claims, "disabled" and "min_trust" ----
import evidence_pack  # noqa: E402

v12 = {"pack_statements": 0, "pack_accepted_other": 0, "pack_raised": 0, "pack_readers_disagree": 0,
       "results": 0, "result_raised": 0, "result_misread": 0, "result_readers_disagree": 0,
       "entries": 0, "entry_wrong": 0, "entry_raised": 0, "entry_result_unreadable": 0,
       "checker": checker is not None}


def v12_broken(text):
    if len(broken) < 20:
        broken.append("aegis 1.2: " + text)


# 8a. manifest.cose: bytes that are not the verifier's statement of this pack
pack_dir = tempfile.mkdtemp()
PACK_MAN = {"format": "aegis-evidence-pack-v1", "endpoint": "dev", "exported": 1_800_000_000,
            "signed_manifest": "manifest.cose"}
pack_man_bytes = (json.dumps(PACK_MAN, indent=1) + "\n").encode()
good_pack = evidence_pack.sign(v_sk, v_pk, "dev", PACK_MAN["exported"], pack_man_bytes, good_ear)
good_pack_payload = cose.parse(good_pack).payload


def pack_readers(data):
    """(the verifier's reader accepts, the checker accepts or None) for manifest.cose bytes in the pack above."""
    try:
        evidence_pack.read(data, v_pk, pack_man_bytes, good_ear)
        ours = True
    except (evidence_pack.Refused, cose.Refused):
        ours = False
    except Exception as e:  # noqa: BLE001
        ours = False
        v12["pack_raised"] += 1
        v12_broken("evidence_pack.read raised %r" % (e,))
    theirs = None
    if checker is not None:
        with open(os.path.join(pack_dir, "manifest.cose"), "wb") as f:
            f.write(data)
        try:
            theirs = checker.check_pack_signature(pack_dir, PACK_MAN, pack_man_bytes, good_ear, v_pk, True)["signed"]
        except Exception:  # noqa: BLE001
            theirs = False
    return ours, theirs


if pack_readers(good_pack) not in ((True, True), (True, None)):
    v12_broken("the control (a good pack statement) was not accepted")


def hostile_pack():
    which = R.randrange(7)
    if which == 0:
        return mutate(good_pack)
    c = cbor.loads(good_pack_payload)
    if which == 1:          # the verifier's key under another typ: a result, a batch, a policy
        return cose.sign1(v_sk, v_pk, good_pack_payload, typ=R.choice([cose.TYP_EAT_CWT, audit.TYP, signed_policy.TYP]))
    if which == 2:          # another key
        return cose.sign1(r_sk, r_pk, good_pack_payload, typ=evidence_pack.TYP)
    if which == 3:
        return hostile_header(v_pk, v_sk, good_pack_payload, typ=evidence_pack.TYP)
    if which == 4:          # another pack, another time, another manifest or result: properly signed
        k = R.choice([2, 3, 4, 5])
        c[k] = {2: lambda: R.choice(["other", "dev ", "", "x" * 65]), 3: lambda: c[3] + R.choice([-1, 1, 3600]),
                4: lambda: hashlib.sha256(pack_man_bytes + b" ").digest(),
                5: lambda: hashlib.sha256(good_ev).digest()}[k]()
    elif which == 5:
        k = R.choice(list(c) + [0, 6, -1, "x"])
        c[k] = rand_cbor(1)
    else:
        del c[R.choice(list(c))]
    return cose.sign1(v_sk, v_pk, cbor.dumps(c, sort=True), typ=evidence_pack.TYP)


for _ in range(min(N, 900)):
    data = hostile_pack()
    if data == good_pack:
        continue
    v12["pack_statements"] += 1
    ours, theirs = pack_readers(data)
    same = False
    try:
        same = cose.verify1(data, v_pk, typ=evidence_pack.TYP).payload == good_pack_payload
    except Exception:  # noqa: BLE001
        pass
    if ours and not same:
        v12["pack_accepted_other"] += 1
        v12_broken("a pack statement that is not this pack's was accepted: %s..." % data.hex()[:120])
    if theirs is not None and theirs != ours:
        v12["pack_readers_disagree"] += 1
        v12_broken("the two readers disagree on a pack statement (verifier %s, checker %s): %s..." % (
            ours, theirs, data.hex()[:120]))

# 8b. attestation results whose Aegis 1.2 claims hold anything, signed by the verifier
good_ear_claims = cbor.loads(cose.parse(good_ear).payload)
NEW_CLAIMS = {"aegis.audit-log": lambda: R.choice([bytes(16), bytes(15), "00" * 16]),
              "aegis.audit-batch": lambda: R.choice([1, 7, 0, -1, 1 << 53, True, "1"]),
              "aegis.audit-head": lambda: R.choice([bytes(32), bytes(33), None]),
              "aegis.warnings": lambda: R.choice([["w"], ["w"] * 8, ["w"] * 9, [], [""], ["x" * 301], "w", [1]]),
              "aegis.disabled": lambda: R.choice([True, False, 1, None]),
              "aegis.min-trust": lambda: R.choice(["trustzone", "", "x" * 65, 3, None]),
              "aegis.pack-signed": lambda: R.choice([True, False, 1, None, "true"])}
for _ in range(min(N, 600)):
    c = cbor.loads(cbor.dumps(good_ear_claims))
    ver = next(iter(c[266].values()))[1006]
    for k in R.sample(list(NEW_CLAIMS), R.randrange(1, len(NEW_CLAIMS) + 1)):
        ver[k] = NEW_CLAIMS[k]() if R.random() < 0.8 else rand_cbor(1)
    data = cose.sign1(v_sk, v_pk, cbor.dumps(c, sort=True))
    v12["results"] += 1
    try:
        r = eat.read_ear(data, v_pk)
        ours = True
        h = r["audit_head"]
        if not ((h is None or (len(h["log"]) == 16 and type(h["batch"]) is int and h["batch"] >= 1
                               and len(h["sha256"]) == 32))
                and (r["warnings"] is None or (1 <= len(r["warnings"]) <= 8 and all(
                    isinstance(w, str) and 1 <= len(w) <= 300 for w in r["warnings"])))
                and (not r["disabled"] or not r["admitted"])
                and (r["min_trust"] is None or (isinstance(r["min_trust"], str) and 1 <= len(r["min_trust"]) <= 64))
                and r["pack_signed"] == (ver.get("aegis.pack-signed") is True)):
            v12["result_misread"] += 1
            v12_broken("read_ear accepted a 1.2 claim not of its form: %r" % (ver,))
    except (eat.Refused, cose.Refused):
        ours = False
    except Exception as e:  # noqa: BLE001
        ours = False
        v12["result_raised"] += 1
        v12_broken("read_ear raised %r" % (e,))
    if checker is not None:
        try:
            checker.check_result(data, v_pk)
            theirs = True
        except Exception:  # noqa: BLE001 - its main() prints every exception as "not verified"
            theirs = False
        if theirs != ours:
            v12["result_readers_disagree"] += 1
            v12_broken("the two readers disagree on a result's 1.2 claims (verifier %s, checker %s): %r" % (
                ours, theirs, ver))

# 8c. policy entries whose "disabled" and "min_trust" hold anything: attest() never raises, contacts the endpoint
# only for an entry it may admit, admits only where the floor is met, and the result it makes reads back
DEV_HUK = fleet.TEE_DEVHUK_PROFILE
for i in range(min(N, 400)):
    devhuk = i % 2 == 1                     # trust "development-shared-key"; the other: "trustzone"
    ep = dict(std_ep, profile=DEV_HUK if devhuk else fleet.TEE_PROFILE)
    if devhuk:
        ep["allow_dev_profile"] = True
    for key, values in (("disabled", [True, False, None, 0, 1, "true", [], {}]),
                        ("min_trust", list(fleet.TRUST_ORDER) + [None, "", "TrustZone", 1, ["trustzone"]])):
        if R.random() < 0.6:
            ep[key] = R.choice(values) if R.random() < 0.85 else rand_cbor(1)
    valid = ("disabled" not in ep or isinstance(ep["disabled"], bool)) and (
        "min_trust" not in ep or (isinstance(ep["min_trust"], str) and ep["min_trust"] in fleet.TRUST_ORDER))
    label = "development-shared-key" if devhuk else "trustzone"
    # a floor the entry's profile can never meet is a policy error: the entry is not asked either
    met = "min_trust" not in ep or (valid and fleet.TRUST_ORDER.index(label) <= fleet.TRUST_ORDER.index(ep["min_trust"]))
    contact = valid and ep.get("disabled") is not True and met
    want = contact
    platform = DEV_HUK if devhuk else fleet.TEE_PROFILE

    def make(ch, platform=platform):
        c = std_claims(ch)
        c[-82400] = platform
        return cose.sign1(pq_sk, pq_pk, cbor.dumps(c, sort=True))
    if contact:
        ep["port"] = Responder(make).port
    else:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            ep["port"] = s.getsockname()[1]  # nobody listens: a contact would show as "no attestation"
    v12["entries"] += 1
    facts = {}
    try:
        v = fleet.attest(ep, None, std_dir, 2, facts=facts)
        if v["admitted"] != want or (not contact and any(r.startswith("no attestation") for r in v["reasons"])) \
                or (ep.get("disabled") is True and v["reasons"][0] != "disabled by policy"):
            v12["entry_wrong"] += 1
            v12_broken("entry %r: admitted %s (want %s), reasons %r" % (
                {k: ep.get(k) for k in ("disabled", "min_trust", "profile")}, v["admitted"], want, v["reasons"]))
        try:
            r = eat.read_ear(cose.sign1(v_sk, v_pk, eat.ear_payload(v, facts, eat.policy_id(b"{}"), 1000)), v_pk)
            if r["disabled"] != (ep.get("disabled") is True) or (ep.get("disabled") is True and r["status"] != "incomplete"):
                v12["entry_wrong"] += 1
                v12_broken("the result of a disabled entry does not say so: %r" % (r,))
        except Exception as e:  # noqa: BLE001
            v12["entry_result_unreadable"] += 1
            v12_broken("the result of entry %r does not read back: %r" % (ep, e))
    except Exception as e:  # noqa: BLE001
        v12["entry_raised"] += 1
        v12_broken("attest() raised %r on entry %r" % (e, ep))

print(json.dumps({"token_parser": token_result, "aegisd_service": service_result,
                  "hostile_endpoint": endpoint_result, "one_transcript": transcript_result,
                  "endorsed_enrolment": endorsement_result, "standard_evidence": std, "audit_and_policy": ap,
                  "aegis_1_2": v12, "broken": broken},
                 indent=1))
sys.exit(1 if broken else 0)
