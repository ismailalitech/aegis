"""Host tests of the fleet verifier with simulated endpoints (no hardware).

Each fake endpoint signs PSA-style tokens with its own P-256 key, so every
admission and quarantine path is exercised: good node, tampered firmware,
replayed token, wrong key, garbage reply, silent node, no TCP service.
"""
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
import fleet  # noqa: E402
import psa_token  # noqa: E402

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
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.srv.accept()
            try:
                line = c.recv(256).split(b"\n")[0].decode()
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

    def test_cbor_roundtrip(self):
        x = {1: [b"ab", "cd", -5, 2 ** 40, True, None], -75008: cbor.Tag(18, b"x")}
        y = cbor.loads(cbor.dumps(x))
        self.assertEqual(y[1], x[1])
        self.assertEqual(y[-75008].tag, 18)


if __name__ == "__main__":
    unittest.main()
