#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Red-team checks on the PC (no hardware). Each check states the property it tries to break.

  1. token parser: mutated / truncated / random PSA tokens are never accepted and raise nothing but
     psa_token.TokenError (no crash, no other exception);
  2. aegisd quote service: malformed requests (garbage, wrong JSON, huge length prefix, bad nonce)
     never stop the service; a valid quote still verifies afterwards;
  3. fleet verifier vs a hostile endpoint: random reply lines, a classic-token downgrade for a
     post-quantum endpoint, a replayed KEM key from an earlier nonce: never admitted / provisioned;
     validly signed tokens (ES256 and ML-DSA-65) carrying random CBOR claims: attest() never raises.

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

print(json.dumps({"token_parser": token_result, "aegisd_service": service_result,
                  "hostile_endpoint": endpoint_result, "broken": broken}, indent=1))
sys.exit(1 if broken else 0)
