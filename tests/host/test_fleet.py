# SPDX-License-Identifier: Apache-2.0
"""Host tests of the fleet verifier with simulated endpoints (no hardware).

Each fake endpoint signs PSA-style tokens with its own P-256 key, so every
admission and quarantine path is exercised: good node, tampered firmware,
replayed token, wrong key, garbage reply, silent node, no TCP service.
"""
import json
import os
import socket
import sys
import tempfile
import threading
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
for p in ("common", "gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(ROOT, p)))

from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: E402

import cbor  # noqa: E402
import mldsa  # noqa: E402
import kmac  # noqa: E402
import mlkem  # noqa: E402
import hashlib  # noqa: E402
import fleet  # noqa: E402
import psa_token  # noqa: E402

PQ_KEYS = [mldsa.keypair(), mldsa.keypair()]
GOOD_S = "11" * 32
GOOD_NS = "22" * 32
SIGNER = "33" * 32


def make_token(key, challenge, ns_meas=GOOD_NS):
    claims = {
        -75008: challenge,
        -75009: b"\x01" + b"\x44" * 32,
        -75006: [
            {1: "SPE", 2: bytes.fromhex(GOOD_S), 4: "2.3.0", 5: bytes.fromhex(SIGNER), 6: "SHA256"},
            {1: "NSPE", 2: bytes.fromhex(ns_meas), 4: "0.0.0", 5: bytes.fromhex(SIGNER), 6: "SHA256"},
        ],
    }
    protected = cbor.dumps({1: -7})
    payload = cbor.dumps(claims)
    tbs = cbor.dumps(["Signature1", protected, b"", payload])
    r, s = decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
    sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    return cbor.dumps(cbor.Tag(18, [protected, {}, payload, sig]))


class FakeEndpoint:
    """mode: good | tampered | replay | wrongkey | garbage | silent"""

    def __init__(self, key, mode="good"):
        self.key, self.mode, self.old = key, mode, None
        self.other = ec.generate_private_key(ec.SECP256R1())
        self.pq_pk, self.pq_sk = PQ_KEYS[0]
        self.pq_other_sk = PQ_KEYS[1][1]
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.srv.accept()
            try:
                buf = b""
                while b"\n" not in buf:
                    chunk = c.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                line = buf.split(b"\n")[0].decode()
                if line.startswith("PQ"):
                    self.pq(c, line)
                    continue
                ch = bytes.fromhex(line.split()[1])
                if self.mode == "silent":
                    threading.Event().wait(3)
                    continue
                if self.mode == "garbage":
                    c.sendall(b"HELLO\r\n")
                    continue
                if self.mode == "replay":
                    if self.old is None:
                        self.old = make_token(self.key, b"\x00" * 32)
                    tok = self.old
                elif self.mode == "tampered":
                    tok = make_token(self.key, ch, ns_meas="99" * 32)
                elif self.mode == "wrongkey":
                    tok = make_token(self.other, ch)
                else:
                    tok = make_token(self.key, ch)
                c.sendall(b"TOKEN %d %s END\r\n" % (len(tok), tok.hex().encode()))
            finally:
                c.close()


    def pq(self, c, line):
        sha3 = lambda *p: hashlib.sha3_256(b"".join(p)).digest()  # noqa: E731
        if line.startswith("PQKEMINIT "):
            self.nonce = bytes.fromhex(line.split()[1])
            self.ek, self.dk = mlkem.keypair()
            sk = self.pq_other_sk if self.mode == "kem-mitm" else self.pq_sk
            sig = mldsa.sign(sk, b"aegis-kem-init-v1", self.nonce + self.ek)
            c.sendall(b"PQKEMEK %d %s %d %s END\r\n" % (len(self.ek), self.ek.hex().encode(), len(sig), sig.hex().encode()))
            return
        if line.startswith("PQKEMFIN "):
            _, cth, credh = line.split()
            ct, cred = bytes.fromhex(cth), bytes.fromhex(credh)
            k = mlkem.decaps(ct, self.dk)
            if self.mode == "kem-badtag":
                k = bytes(32)
            tag = sha3(b"aegis-confirm-v1", k, self.nonce, sha3(ct), sha3(cred))
            self.session = sha3(b"aegis-session-v1", k, self.nonce, sha3(ct))
            self.cred = cred
            self.expired = False
            c.sendall(b"PQKEMOK %s END\r\n" % tag.hex().encode())
            return
        if line.startswith("PQHB "):
            if getattr(self, "expired", False):   # the endpoint ended the session on its own clock
                c.sendall(b"ERR pq expired\r\n")
                return
            nonce = bytes.fromhex(line.split()[1])
            self.hb = getattr(self, "hb", 0) + 1
            ctr = self.hb.to_bytes(8, "little")
            status = getattr(self, "hb_status", b"uptime_s=1;link=1;fw=test")
            if getattr(self, "hb_mac", "kmac256") == "kmac256":   # every current endpoint image
                tag = kmac.kmac256(self.session, nonce + ctr + status, 32, b"aegis-hb-v2")
            else:
                tag = sha3(b"aegis-hb-v1", self.session, nonce, ctr, status)
            c.sendall(b"PQHB %s %s %s END\r\n" % (status.hex().encode(), ctr.hex().encode(), tag.hex().encode()))
            return
        if line == "PQSESSION":
            sid = sha3(b"aegis-session-id-v1", self.session)
            c.sendall(b"PQSESSION %s %s END\r\n" % (sid.hex().encode(), sha3(self.cred).hex().encode()))
            return
        if line == "PQKEY":
            c.sendall(b"PQKEY %d %s END\r\n" % (len(self.pq_pk), self.pq_pk.hex().encode()))
            return
        ch = bytes.fromhex(line.split()[1])
        tok = make_token(self.key, ch, ns_meas="99" * 32 if self.mode == "pq-tampered" else GOOD_NS)
        sk = self.pq_other_sk if self.mode == "pq-wrongkey" else self.pq_sk
        sig = mldsa.sign(sk, b"aegis-endpoint-quote-v1", tok)
        c.sendall(b"PQTOKEN %d %s %d %s END\r\n" % (len(tok), tok.hex().encode(), len(sig), sig.hex().encode()))


class Fleet(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.dir = tempfile.mkdtemp()
        cls.pem = os.path.join(cls.dir, "iak.pub.pem")
        with open(cls.pem, "wb") as f:
            f.write(cls.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
        cls.allowed = [{"type": "SPE", "measurement_value": GOOD_S, "signer_id": SIGNER},
                       {"type": "NSPE", "measurement_value": GOOD_NS, "signer_id": SIGNER}]

    def run_ep(self, mode, verifier=psa_token.verify_with_cryptography, timeout=1.0):
        ep = FakeEndpoint(self.key, mode)
        conf = {"name": mode, "host": "127.0.0.1", "port": ep.port, "iak_pub_pem": self.pem,
                "allowed": self.allowed}
        return fleet.attest(conf, verifier, self.dir, timeout=timeout)

    def test_good_node_admitted(self):
        v = self.run_ep("good")
        self.assertTrue(v["admitted"], v["reasons"])

    def test_good_node_admitted_with_openssl_tool(self):
        v = self.run_ep("good", verifier=psa_token.verify_with_openssl_cli)
        self.assertTrue(v["admitted"], v["reasons"])

    def test_tampered_firmware_quarantined(self):
        v = self.run_ep("tampered")
        self.assertFalse(v["admitted"])
        self.assertTrue(any("NSPE not allowed" in r for r in v["reasons"]), v["reasons"])

    def test_replayed_token_quarantined(self):
        v = self.run_ep("replay")
        self.assertFalse(v["admitted"])
        self.assertIn("challenge mismatch (replayed or stale token)", v["reasons"])

    def test_wrong_key_quarantined(self):
        v = self.run_ep("wrongkey")
        self.assertFalse(v["admitted"])
        self.assertIn("token signature invalid", v["reasons"])

    def test_garbage_reply_quarantined(self):
        v = self.run_ep("garbage")
        self.assertFalse(v["admitted"])
        self.assertTrue(v["reasons"][0].startswith("no attestation"))

    def test_silent_node_quarantined(self):
        v = self.run_ep("silent", timeout=0.5)
        self.assertFalse(v["admitted"])
        self.assertTrue(v["reasons"][0].startswith("no attestation"))

    def test_no_service_quarantined(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        conf = {"name": "none", "host": "127.0.0.1", "port": port, "iak_pub_pem": self.pem, "allowed": self.allowed}
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=0.5)
        self.assertFalse(v["admitted"])

    def run_pq(self, mode):
        ep = FakeEndpoint(self.key, mode)
        pqf = os.path.join(self.dir, "pq.pub")
        with open(pqf, "w") as f:
            f.write(PQ_KEYS[0][0].hex())
        conf = {"name": mode, "kind": "aegis-pq", "host": "127.0.0.1", "port": ep.port,
                "pq_pub_file": pqf, "allowed": self.allowed}
        return ep, fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=2)

    def test_pq_good_admitted(self):
        ep, v = self.run_pq("pq-good")
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(fleet.request_pq_key("127.0.0.1", ep.port), PQ_KEYS[0][0])

    def test_pq_wrong_key_quarantined(self):
        _, v = self.run_pq("pq-wrongkey")
        self.assertFalse(v["admitted"])
        self.assertIn("ML-DSA-65 quote signature invalid", v["reasons"])

    def test_pq_tampered_firmware_quarantined(self):
        _, v = self.run_pq("pq-tampered")
        self.assertFalse(v["admitted"])
        self.assertTrue(any("NSPE not allowed" in r for r in v["reasons"]), v["reasons"])

    def provision_ep(self, mode):
        ep = FakeEndpoint(self.key, mode)
        pqf = os.path.join(self.dir, "pq.pub")
        with open(pqf, "w") as f:
            f.write(PQ_KEYS[0][0].hex())
        conf = {"name": mode, "kind": "aegis-pq", "host": "127.0.0.1", "port": ep.port, "pq_pub_file": pqf,
                "allowed": self.allowed, "provision": True}
        gw_pk, gw_sk = mldsa.keypair()
        return ep, conf, gw_pk, gw_sk

    def test_kem_provisioning_agrees_on_session(self):
        ep, conf, gw_pk, gw_sk = self.provision_ep("kem-good")
        r = fleet.provision(conf, self.dir, gw_sk, "gid", {"NSPE": GOOD_NS}, timeout=5)
        sid, ch = fleet.query_session(conf)
        self.assertEqual(sid, r["session_id"])
        self.assertEqual(ch, r["credential_sha3_256"])
        body, sig = r["credential"].split(b"\n", 1)
        self.assertTrue(mldsa.verify(gw_pk, b"aegis-credential-v1", body, sig))
        # the lifetime as the endpoints read it from the signed text (docs/endpoint-expiry.md): "issued" and "expires"
        # once each, plain digits ended by ',' or '}', at most a day apart
        import re
        issued, expires = (re.findall(rb'"%s":(\d{1,10})[,}]' % k, body) for k in (b"issued", b"expires"))
        self.assertEqual((len(issued), len(expires)), (1, 1))
        self.assertEqual((body.count(b'"issued":'), body.count(b'"expires":')), (1, 1))
        self.assertEqual(int(expires[0]) - int(issued[0]), fleet.CRED_LIFETIME_S)
        self.assertTrue(300 < fleet.CRED_LIFETIME_S <= 86400)

    def test_credential_lifetime_option(self):
        """--credential-lifetime (the soak's setting, docs/soak-and-watchdogs.md): outside 600 s to a day refused before
        anything runs; inside it the credentials carry it."""
        import contextlib
        import io
        for bad in ("599", "86401", "0", "-5", "x"):
            with self.assertRaises(SystemExit), contextlib.redirect_stderr(io.StringIO()):
                fleet.main(["check", os.path.join(self.dir, "none.json"), "--credential-lifetime", bad])
        self.assertEqual(fleet.CRED_LIFETIME_S, 3600)
        try:
            with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
                try:
                    fleet.main(["check", os.path.join(self.dir, "none.json"), "--credential-lifetime", "600"])
                except (OSError, ValueError, SystemExit):
                    pass            # no policy there: only the setting is looked at
            self.assertEqual(fleet.CRED_LIFETIME_S, 600)
            self.assertGreaterEqual(fleet.CRED_LIFETIME_MIN_S, 2 * fleet.RENEWAL_WINDOW_S)
            _, conf, _, gw_sk = self.provision_ep("kem-short")
            r = fleet.provision(conf, self.dir, gw_sk, "gid", {"NSPE": GOOD_NS}, timeout=5)
            body = json.loads(r["credential"].split(b"\n", 1)[0])
            self.assertEqual(body["expires"] - body["issued"], 600)
        finally:
            fleet.CRED_LIFETIME_S = 3600

    def test_kem_key_signed_by_other_key_refused(self):
        _, conf, _, gw_sk = self.provision_ep("kem-mitm")
        with self.assertRaises(ValueError):
            fleet.provision(conf, self.dir, gw_sk, "gid", {}, timeout=5)

    def test_kem_wrong_confirmation_refused(self):
        _, conf, _, gw_sk = self.provision_ep("kem-badtag")
        with self.assertRaises(ValueError):
            fleet.provision(conf, self.dir, gw_sk, "gid", {}, timeout=5)

    def admitted(self, conf):
        """An admitted verdict as attest() makes it: by the pinned key (a stored session is kept only for that key)."""
        with open(os.path.join(self.dir, conf["pq_pub_file"])) as f:
            pk = bytes.fromhex(f.read().strip())
        return {"admitted": True, "measurements": {}, "device_pk_sha256": hashlib.sha256(pk).hexdigest()}

    def test_credential_issued_then_revoked(self):
        import wire
        ep, conf, gw_pk, gw_sk = self.provision_ep("kem-good")
        state = tempfile.mkdtemp()
        body = {"v": 1, "type": "identity", "pk": gw_pk.hex()}
        with open(os.path.join(state, "identity.json"), "w") as f:
            json.dump({"body": body}, f)
        with open(os.path.join(state, "identity.sk"), "wb") as f:
            f.write(gw_sk)
        st = fleet.credential_step(conf, self.admitted(conf), self.dir, state=state)
        self.assertTrue(st.startswith("issued"), st)
        self.assertTrue(fleet.credential_step(conf, self.admitted(conf), self.dir, state=state).startswith("valid, heartbeat 1"))
        self.assertTrue(fleet.credential_step(conf, self.admitted(conf), self.dir, state=state).startswith("valid, heartbeat 2"))
        self.assertEqual(fleet.credential_step(conf, {"admitted": False}, self.dir, state=state), "revoked")
        self.assertFalse(os.path.exists(os.path.join(state, "credentials", "kem-good.session")))

    def test_session_ended_by_the_endpoint_is_provisioned_again(self):
        """An endpoint that has ended the session on its own clock answers "ERR pq expired"; the gateway provisions
        again in the same cycle, as for any failed heartbeat."""
        ep, conf, gw_pk, gw_sk = self.provision_ep("kem-good")
        state = tempfile.mkdtemp()
        with open(os.path.join(state, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "identity", "pk": gw_pk.hex()}}, f)
        with open(os.path.join(state, "identity.sk"), "wb") as f:
            f.write(gw_sk)
        first = fleet.credential_step(conf, self.admitted(conf), self.dir, state=state)
        self.assertTrue(first.startswith("issued session "), first)
        self.assertTrue(fleet.credential_step(conf, self.admitted(conf), self.dir, state=state).startswith("valid, heartbeat 1"))
        ep.expired = True
        again = fleet.credential_step(conf, self.admitted(conf), self.dir, state=state)
        self.assertTrue(again.startswith("issued session "), again)
        self.assertNotEqual(again, first)
        self.assertTrue(fleet.credential_step(conf, self.admitted(conf), self.dir, state=state).startswith("valid, heartbeat "))

    def test_heartbeat_kmac256(self):
        ep, conf, _, gw_sk = self.provision_ep("kem-good")
        r = fleet.provision(conf, self.dir, gw_sk, "gid", {}, timeout=5)
        ep.hb_mac = "kmac256"
        conf["heartbeat_mac"] = "kmac256"
        status, ctr = fleet.heartbeat(conf, r["session_key"], timeout=5)
        self.assertEqual(ctr, 1)
        self.assertTrue(status.startswith(b"uptime_s="))

    def test_heartbeat_status_with_secure_stack(self):
        # the STM32 partition appends ";sstack=<used>/<size>" under its MAC: opaque text to the gateway, longest case
        # 128 bytes from the non-secure side plus 19
        ep, conf, _, gw_sk = self.provision_ep("kem-good")
        r = fleet.provision(conf, self.dir, gw_sk, "gid", {}, timeout=5)
        ep.hb_mac = conf["heartbeat_mac"] = "kmac256"
        for st in (b"uptime_s=62;link=1;fw=0.6.0;sstack=19344/26624", b"uptime_s=62;link=1;fw=0.6.0;sstack=na",
                   b"x" * 128 + b";sstack=26624/26624"):
            ep.hb_status = st
            status, _ = fleet.heartbeat(conf, r["session_key"], timeout=5)
            self.assertEqual(status, st)

    def test_heartbeat_mac_mismatch_refused(self):
        ep, conf, _, gw_sk = self.provision_ep("kem-good")
        r = fleet.provision(conf, self.dir, gw_sk, "gid", {}, timeout=5)
        ep.hb_mac = "kmac256"          # endpoint on KMAC, gateway policy pinned to the first version
        conf["heartbeat_mac"] = "sha3-256"
        with self.assertRaises(ValueError):
            fleet.heartbeat(conf, r["session_key"], timeout=5)

    def test_heartbeat_default_is_kmac256(self):
        """An entry without "heartbeat_mac" expects KMAC256, what every endpoint image now computes."""
        self.assertEqual(fleet.heartbeat_tag(None, b"k" * 32, b"n" * 32, bytes(8), b"s"),
                         fleet.heartbeat_tag("kmac256", b"k" * 32, b"n" * 32, bytes(8), b"s"))
        ep, conf, _, gw_sk = self.provision_ep("kem-good")
        r = fleet.provision(conf, self.dir, gw_sk, "gid", {}, timeout=5)
        self.assertNotIn("heartbeat_mac", conf)
        self.assertEqual(fleet.heartbeat(conf, r["session_key"], timeout=5)[1], 1)

    def test_heartbeat_sha3_only_endpoint_still_works_when_named(self):
        """A SHA-3-only image (STM32 built with AEGIS_HB_KMAC=0) keeps working with "heartbeat_mac": "sha3-256", and
        is refused by the new default."""
        ep, conf, _, gw_sk = self.provision_ep("kem-good")
        r = fleet.provision(conf, self.dir, gw_sk, "gid", {}, timeout=5)
        ep.hb_mac = "sha3-256"
        with self.assertRaises(ValueError):
            fleet.heartbeat(conf, r["session_key"], timeout=5)
        conf["heartbeat_mac"] = "sha3-256"
        self.assertEqual(fleet.heartbeat(conf, r["session_key"], timeout=5)[1], 2)

    def test_heartbeat_unknown_mac_refused(self):
        with self.assertRaises(ValueError):
            fleet.heartbeat_tag("hmac-md5", bytes(32), bytes(32), bytes(8), b"")

    def test_cbor_roundtrip(self):
        x = {1: [b"ab", "cd", -5, 2 ** 40, True, None], -75008: cbor.Tag(18, b"x")}
        y = cbor.loads(cbor.dumps(x))
        self.assertEqual(y[1], x[1])
        self.assertEqual(y[-75008].tag, 18)


if __name__ == "__main__":
    unittest.main()
