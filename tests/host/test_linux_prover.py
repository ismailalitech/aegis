"""The aegis-linux prover (endpoints/zybo/aegis_linux_prover.py) against the gateway's own code (fleet.py), on the PC:
attestation with software trust, ML-KEM provisioning with the credential checks, KMAC256 heartbeats, the session query,
and the refusals (a changed boot file, a wrong pinned key, a credential from another key or for another exchange)."""
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, os.path.join(ROOT, "gateway", "aegisd"))
sys.path.insert(0, os.path.join(ROOT, "endpoints", "zybo"))
import fleet  # noqa: E402
import mldsa  # noqa: E402
import mlkem  # noqa: E402
import wire  # noqa: E402
import aegis_linux_prover as prover_mod  # noqa: E402


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


class LinuxProver(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.gw_pk, cls.gw_sk = mldsa.keypair()
        with open(os.path.join(cls.d, "gw.pub"), "w") as f:
            f.write(cls.gw_pk.hex())
        cls.bootf = os.path.join(cls.d, "boot.bin")
        with open(cls.bootf, "wb") as f:
            f.write(b"first stage boot loader")
        cls.port = free_port()
        args = prover_mod.argparse.Namespace(state=os.path.join(cls.d, "state"), gateway_pk=os.path.join(cls.d, "gw.pub"),
                                             measure=[("BOOT", [cls.bootf])], port=cls.port, heartbeat_mac="kmac256")
        cls.prover = prover_mod.Prover(args)
        threading.Thread(target=prover_mod.serve, args=(cls.prover, cls.port), daemon=True).start()
        import time
        for _ in range(50):
            try:
                socket.create_connection(("127.0.0.1", cls.port), timeout=0.2).close()
                break
            except OSError:
                time.sleep(0.05)
        with open(os.path.join(cls.d, "ep.pub"), "w") as f:
            f.write(cls.prover.pk.hex())

    def ep(self, **kw):
        def sha256_file(path):
            with open(path, "rb") as f:
                return hashlib.sha256(f.read()).hexdigest()
        good, prov = sha256_file(self.bootf), sha256_file(prover_mod.__file__)
        e = {"name": "zybo", "kind": "aegis-linux", "host": "127.0.0.1", "port": self.port, "pq_pub_file": "ep.pub",
             "heartbeat_mac": "kmac256",
             "allowed": [{"type": "BOOT", "measurement_value": good}, {"type": "PROVER", "measurement_value": prov}]}
        e.update(kw)
        return e

    def test_1_attest_software_trust(self):
        v = fleet.attest(self.ep(), None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "software")
        self.assertEqual(v["pq_signature"], "ML-DSA-65 valid")
        self.assertEqual(set(v["measurements"]), {"BOOT", "PROVER"})

    def test_2_changed_boot_file_quarantined(self):
        e = self.ep()
        e["allowed"][0]["measurement_value"] = "00" * 32
        v = fleet.attest(e, None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertTrue(any("BOOT" in r for r in v["reasons"]), v["reasons"])

    def test_3_wrong_pinned_key_refused(self):
        other_pk, _ = mldsa.keypair()
        with open(os.path.join(self.d, "other.pub"), "w") as f:
            f.write(other_pk.hex())
        v = fleet.attest(self.ep(pq_pub_file="other.pub"), None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertIn("ML-DSA-65 quote signature invalid", v["reasons"])

    def test_4_provision_heartbeat_session(self):
        r = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {"BOOT": "x"}, timeout=20)
        sid, ch = fleet.query_session(self.ep())
        self.assertEqual(sid, r["session_id"])
        self.assertEqual(ch, r["credential_sha3_256"])
        for n in (1, 2):
            status, ctr = fleet.heartbeat(self.ep(), r["session_key"], timeout=10)
            self.assertEqual(ctr, n)
            self.assertTrue(status.startswith(b"uptime_s="))
        with self.assertRaises(ValueError):       # the first heartbeat construction does not verify a KMAC device
            fleet.heartbeat(self.ep(heartbeat_mac="sha3-256"), r["session_key"], timeout=10)

    def kem_raw(self, sign_key, bind_ct=True):
        """Run the exchange by hand to send a credential the gateway code would never make."""
        nonce = os.urandom(32)
        p = fleet._exchange("127.0.0.1", self.port, "PQKEMINIT " + nonce.hex(), 10).split()
        ek = bytes.fromhex(p[2])
        ct, _ = mlkem.encaps(ek)
        body = {"v": 1, "type": "credential", "endpoint": "zybo",
                "endpoint_pq_pk_sha256": hashlib.sha256(self.prover.pk).hexdigest(),
                "kem_ct_sha3_256": fleet._sha3(ct if bind_ct else b"other").hex(),
                "kem_ek_sha3_256": fleet._sha3(ek).hex(), "expires": 4102444800}
        cred = wire.canonical(body) + b"\n" + mldsa.sign(sign_key, fleet.CRED_LABEL, wire.canonical(body))
        return fleet._exchange("127.0.0.1", self.port, "PQKEMFIN %s %s" % (ct.hex(), cred.hex()), 10)

    def test_5_forged_credentials_refused_and_session_kept(self):
        r = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {}, timeout=20)
        _, other_sk = mldsa.keypair()
        self.assertIn("ERR cred signature", self.kem_raw(other_sk))
        self.assertIn("ERR cred other-exchange", self.kem_raw(self.gw_sk, bind_ct=False))
        sid, _ = fleet.query_session(self.ep())
        self.assertEqual(sid, r["session_id"], "a refused exchange must not replace the session")

    def test_7_refused_init_leaves_nothing_pending(self):
        """A PQKEMINIT that fails at its signature cancels the pending exchange and keeps nothing half made; an error
        inside one request does not stop the server (found by fuzzing the device partitions, 2026-11-18)."""
        from unittest import mock
        nonce = os.urandom(32)
        p = fleet._exchange("127.0.0.1", self.port, "PQKEMINIT " + nonce.hex(), 10).split()
        ek1 = bytes.fromhex(p[2])
        with mock.patch.object(prover_mod.mldsa, "sign", side_effect=RuntimeError("no randomness")):
            self.assertEqual(fleet._exchange("127.0.0.1", self.port, "PQKEMINIT " + os.urandom(32).hex(), 10).strip(),
                             "ERR sign")
        ct, _ = mlkem.encaps(ek1)
        body = {"v": 1, "type": "credential", "endpoint": "zybo",
                "endpoint_pq_pk_sha256": hashlib.sha256(self.prover.pk).hexdigest(),
                "kem_ct_sha3_256": fleet._sha3(ct).hex(), "kem_ek_sha3_256": fleet._sha3(ek1).hex(),
                "expires": 4102444800}
        cred = wire.canonical(body) + b"\n" + mldsa.sign(self.gw_sk, fleet.CRED_LABEL, wire.canonical(body))
        self.assertIn("ERR cred no-exchange",
                      fleet._exchange("127.0.0.1", self.port, "PQKEMFIN %s %s" % (ct.hex(), cred.hex()), 10))
        with mock.patch.object(self.prover, "handle", side_effect=KeyError("boom")):
            self.assertEqual(fleet._exchange("127.0.0.1", self.port, "PQKEY", 10).strip(), "ERR internal")
        self.assertTrue(fleet._exchange("127.0.0.1", self.port, "PQKEY", 10).startswith("PQKEY "))

    def test_6_malformed_requests(self):
        for line in ("", "PQCHAL zz", "PQCHAL " + "00" * 31, "PQKEMFIN 00", "HELLO", "PQHB " + "00" * 32 + " extra"):
            reply = fleet._exchange("127.0.0.1", self.port, line, 10)
            self.assertTrue(reply.startswith("ERR"), (line, reply))


if __name__ == "__main__":
    unittest.main()
