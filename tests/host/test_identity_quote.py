"""End-to-end host tests of the gateway identity, quote service and verifier.

The gateway runs in a thread on localhost with a fake system controller, so
every acceptance and refusal path of the verifier is exercised without a board.
"""
import copy
import hashlib
import os
import sys
import tempfile
import threading
import unittest

ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
for p in ("common", "host", "gateway/aegisd", "gateway/sysserv"):
    sys.path.insert(0, os.path.abspath(os.path.join(ROOT, p)))

import aegisd  # noqa: E402
import aegis_verify as av  # noqa: E402
import mldsa  # noqa: E402
import wire  # noqa: E402


def fake_cert():
    body = bytes(range(256)) * 3
    n = len(body)
    return b"\x30\x82" + n.to_bytes(2, "big") + body + bytes(1024 - 4 - n)


class FakeHardware:
    def __init__(self):
        self.values = {
            "serial": bytes.fromhex("00112233445566778899aabbccddeeff"),
            "device_cert": fake_cert(),
            "design_info": b"D" * 36,
            "usercode": b"\x01\x02\x03\x04",
            "security": bytes(36),
            "digest": b"\x5a" * 576,
        }

    def read(self, name):
        return self.values[name]


class Gateway:
    def __init__(self, hw):
        self.dir = tempfile.mkdtemp()
        self.hw = hw
        aegisd.init_identity(self.dir, hw)
        ready = threading.Event()
        self.port = None

        def on_ready(port):
            self.port = port
            ready.set()

        self.t = threading.Thread(target=aegisd.serve, args=(self.dir, 0, hw),
                                  kwargs={"ready": on_ready}, daemon=True)
        self.t.start()
        ready.wait(5)


class IdentityAndQuote(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hw = FakeHardware()
        cls.gw = Gateway(cls.hw)
        cls.store = tempfile.mkdtemp()
        cls.path, cls.enrolled = av.enroll("127.0.0.1", cls.gw.port, store=cls.store)

    def quote(self):
        return av.fresh_quote("127.0.0.1", self.gw.port)

    def test_identity_self_signature(self):
        ok, why = av.check_identity(self.enrolled["identity"])
        self.assertTrue(ok, why)
        self.assertEqual(self.enrolled["identity"]["body"]["dsn"], self.hw.values["serial"].hex())
        self.assertEqual(self.enrolled["identity"]["body"]["device_cert_sha256"],
                         hashlib.sha256(self.hw.values["device_cert"][:4 + 768]).hexdigest())

    def test_fresh_quote_accepted(self):
        resp, nonce, el = self.quote()
        ok, reasons = av.check_quote(self.enrolled, resp, nonce, el)
        self.assertTrue(ok, reasons)
        self.assertEqual(len(bytes.fromhex(resp["sig"])), mldsa.SIG_LEN)

    def test_tampered_measurement_refused(self):
        resp, nonce, el = self.quote()
        bad = copy.deepcopy(resp)
        bad["body"]["measurements"]["usercode"] = "ffffffff"
        ok, reasons = av.check_quote(self.enrolled, bad, nonce, el)
        self.assertFalse(ok)
        self.assertIn("signature invalid", reasons)

    def test_flipped_signature_bit_refused(self):
        resp, nonce, el = self.quote()
        sig = bytearray(bytes.fromhex(resp["sig"]))
        sig[100] ^= 1
        bad = dict(resp, sig=bytes(sig).hex())
        self.assertFalse(av.check_quote(self.enrolled, bad, nonce, el)[0])

    def test_replayed_answer_refused(self):
        old, _, el = self.quote()
        _, new_nonce, _ = self.quote()
        ok, reasons = av.check_quote(self.enrolled, old, new_nonce, el)
        self.assertFalse(ok)
        self.assertTrue(any("nonce mismatch" in r for r in reasons))

    def test_slow_answer_refused(self):
        resp, nonce, _ = self.quote()
        ok, reasons = av.check_quote(self.enrolled, resp, nonce, av.MAX_SECONDS + 1)
        self.assertFalse(ok)

    def test_identity_signature_cannot_pass_as_quote(self):
        rec = self.enrolled["identity"]
        forged = {"body": dict(rec["body"], type="quote"), "sig": rec["sig"]}
        self.assertFalse(av.check_quote(self.enrolled, forged, "00" * 32, 0.1)[0])

    def test_measurement_change_detected_with_valid_signature(self):
        self.hw.values["digest"] = b"\xa5" * 576
        try:
            resp, nonce, el = self.quote()
        finally:
            self.hw.values["digest"] = b"\x5a" * 576
        ok, reasons = av.check_quote(self.enrolled, resp, nonce, el)
        self.assertFalse(ok)
        self.assertEqual(reasons, ["measurement changed: design_digests_sha256"])

    def test_other_gateway_key_refused(self):
        other = Gateway(FakeHardware())
        resp, nonce, el = av.fresh_quote("127.0.0.1", other.port)
        ok, reasons = av.check_quote(self.enrolled, resp, nonce, el)
        self.assertFalse(ok)
        self.assertIn("signature invalid", reasons)
        self.assertIn("identity differs from enrolment", reasons)

    def test_bad_nonce_length_rejected_by_gateway(self):
        resp = av.request("127.0.0.1", self.gw.port, {"type": "quote", "nonce": "00"})
        self.assertIn("error", resp)


if __name__ == "__main__":
    unittest.main()
