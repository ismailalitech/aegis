# SPDX-License-Identifier: Apache-2.0
"""The gateway's identity and quote service on an ordinary Linux host (aegisd --platform linux): no system
controller, the PC verifier unchanged. Also the two ML-DSA / ML-KEM backends against each other when both are
installed."""
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
import mlkem  # noqa: E402


def host(machine_id=b"0123456789abcdef0123456789abcdef\n"):
    d = tempfile.mkdtemp()
    mid, rel = os.path.join(d, "machine-id"), os.path.join(d, "os-release")
    with open(mid, "wb") as f:
        f.write(machine_id)
    with open(rel, "w") as f:
        f.write('NAME="Test Linux"\nVERSION_ID="1"\n')
    return aegisd.LinuxHostSource(mid, rel)


def start(hw):
    state = tempfile.mkdtemp()
    aegisd.init_identity(state, hw)
    ready, port = threading.Event(), []
    threading.Thread(target=aegisd.serve, args=(state, 0, hw),
                     kwargs={"ready": lambda p: (port.append(p), ready.set())}, daemon=True).start()
    ready.wait(5)
    return state, port[0]


class LinuxHost(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.hw = host()
        cls.state, cls.port = start(cls.hw)
        cls.store = tempfile.mkdtemp()
        cls.path, cls.enrolled = av.enroll("127.0.0.1", cls.port, store=cls.store)

    def test_identity_says_what_it_is(self):
        body = self.enrolled["identity"]["body"]
        self.assertEqual(body["platform"], "linux-host")
        self.assertIn("no TPM", body["key_storage"])
        self.assertNotIn("device_cert_sha256", body)
        self.assertEqual(len(body["dsn"]), 32)
        self.assertNotIn("0123456789abcdef", body["dsn"])          # the machine ID itself is not published

    def test_quote_accepted_and_names_the_platform(self):
        resp, nonce, elapsed = av.fresh_quote("127.0.0.1", self.port)
        ok, reasons = av.check_quote(self.enrolled, resp, nonce, elapsed)
        self.assertTrue(ok, reasons)
        m = resp["body"]["measurements"]
        self.assertEqual(m["platform"], "linux-host")
        for k in ("host_id_sha256", "aegisd_code_sha256", "os_release_sha256"):
            self.assertEqual(len(m[k]), 64, k)

    def test_replayed_quote_refused(self):
        resp, nonce, elapsed = av.fresh_quote("127.0.0.1", self.port)
        ok, reasons = av.check_quote(self.enrolled, resp, "00" * 32, elapsed)
        self.assertFalse(ok)
        self.assertTrue(any("nonce" in r for r in reasons), reasons)

    def test_changed_os_release_is_a_changed_measurement(self):
        with open(self.hw.os_release_path, "a") as f:
            f.write("TAMPERED=1\n")
        try:
            resp, nonce, elapsed = av.fresh_quote("127.0.0.1", self.port)
            ok, reasons = av.check_quote(self.enrolled, resp, nonce, elapsed)
            self.assertFalse(ok)
            self.assertIn("measurement changed: os_release_sha256", reasons)
        finally:
            with open(self.hw.os_release_path, "w") as f:
                f.write('NAME="Test Linux"\nVERSION_ID="1"\n')

    def test_another_host_has_another_identity(self):
        _, port2 = start(host(b"ffffffffffffffffffffffffffffffff\n"))
        resp, nonce, elapsed = av.fresh_quote("127.0.0.1", port2)
        ok, reasons = av.check_quote(self.enrolled, resp, nonce, elapsed)
        self.assertFalse(ok)
        self.assertIn("signature invalid", reasons)

    def test_empty_machine_id_refused(self):
        with self.assertRaises(ValueError):
            host(b"\n").host_id()

    def test_platform_choice(self):
        self.assertIsInstance(aegisd.pick_platform("linux"), aegisd.LinuxHostSource)
        with self.assertRaises(ValueError):
            aegisd.pick_platform("teapot")


class Backends(unittest.TestCase):
    def test_keys_name_their_backend_by_length(self):
        pk, sk = mldsa.keypair()
        ek, dk = mlkem.keypair()
        if mldsa.backend() == "openssl":
            self.assertEqual((len(sk), len(dk)), (mldsa.SEED_LEN, mlkem.SEED_LEN))
        else:
            self.assertEqual((len(sk), len(dk)), (mldsa.SK_LEN, mlkem.DK_LEN))
        self.assertEqual((len(pk), len(ek)), (mldsa.PK_LEN, mlkem.EK_LEN))

    def test_bad_inputs_are_refused_not_raised(self):
        pk, sk = mldsa.keypair()
        sig = mldsa.sign(sk, b"l", b"m")
        self.assertFalse(mldsa.verify(pk, b"l", b"m", sig[:-1]))
        self.assertFalse(mldsa.verify(pk, b"l", b"m", sig[:-1] + bytes([sig[-1] ^ 1])))
        self.assertFalse(mldsa.verify(pk[:-1], b"l", b"m", sig))
        self.assertFalse(mldsa.verify(b"\xff" * mldsa.PK_LEN, b"l", b"m", sig))
        with self.assertRaises(ValueError):
            mldsa.sign(sk + b"x", b"l", b"m")
        with self.assertRaises(ValueError):
            mlkem.encaps(b"\x00" * 10)
        with self.assertRaises(RuntimeError):
            mlkem.encaps(b"\xff" * mlkem.EK_LEN)                    # coefficients not reduced: FIPS 203 input check

    def test_unknown_backend_name(self):
        old = os.environ.get("AEGIS_PQ_BACKEND")
        os.environ["AEGIS_PQ_BACKEND"] = "rot13"
        try:
            with self.assertRaises(ValueError):
                mldsa.backend()
        finally:
            if old is None:
                del os.environ["AEGIS_PQ_BACKEND"]
            else:
                os.environ["AEGIS_PQ_BACKEND"] = old

    @unittest.skipUnless(mldsa.have("openssl") and mldsa.have("liboqs"), "needs both backends installed")
    def test_openssl_and_liboqs_agree(self):
        """A signature or ciphertext made by one library is accepted by the other, both ways."""
        for maker in ("openssl", "liboqs"):
            other = "liboqs" if maker == "openssl" else "openssl"
            os.environ["AEGIS_PQ_BACKEND"] = maker
            try:
                pk, sk = mldsa.keypair()
                sig = mldsa.sign(sk, b"aegis-quote-v1", b"cross-check")
                ek, dk = mlkem.keypair()
            finally:
                del os.environ["AEGIS_PQ_BACKEND"]
            self.assertTrue(mldsa.verify(pk, b"aegis-quote-v1", b"cross-check", sig, use=other), maker)
            self.assertFalse(mldsa.verify(pk, b"aegis-quote-v1", b"cross-chec", sig, use=other), maker)
            ct, ss = mlkem.encaps(ek, use=other)
            self.assertEqual(mlkem.decaps(ct, dk), ss, maker)


if __name__ == "__main__":
    unittest.main()
