"""The RW612 prover's protocol code (endpoints/rw612/prover/src/aegis_proto.c, the same C file as in the firmware),
built for the PC and run against the gateway's own code (fleet.py): attestation with device-key trust, ML-KEM
provisioning with the credential checks, KMAC256 heartbeats, the session query, and the refusals (a changed
image, a wrong pinned key, a credential from another key, for another exchange or for another endpoint).
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import hashlib
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, os.path.join(ROOT, "gateway", "aegisd"))
import fleet  # noqa: E402
import mldsa  # noqa: E402
import mlkem  # noqa: E402
import wire  # noqa: E402

TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
PROVER = os.path.join(ROOT, "endpoints", "rw612", "prover")
PART = os.path.join(ROOT, "endpoints", "stm32h573", "tfm-aegis-partition")


def build(out):
    cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-D_GNU_SOURCE",
           '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"',
           "-I", os.path.join(PROVER, "src"), "-I", PART, "-I", os.path.join(PART, "mldsa"), "-I", MLDSA,
           "-I", os.path.join(PART, "mlkem"), "-I", MLKEM,
           os.path.join(PROVER, "host", "host_main.c"), os.path.join(PROVER, "src", "aegis_proto.c"),
           os.path.join(PROVER, "src", "sha256.c"), os.path.join(PART, "aegis_kmac.c"),
           os.path.join(PART, "mlkem_unit.c"), os.path.join(MLDSA, "mldsa_native.c"), "-o", out]
    subprocess.run(cmd, check=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


@unittest.skipUnless(os.path.isdir(MLDSA) and os.path.isdir(MLKEM), "mldsa-native / mlkem-native not found")
class Rw612Proto(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.exe = os.path.join(cls.d, "aegis_rw612_host")
        build(cls.exe)
        cls.gw_pk, cls.gw_sk = mldsa.keypair()
        with open(os.path.join(cls.d, "gw.pub"), "w") as f:
            f.write(cls.gw_pk.hex())
        cls.image = os.path.join(cls.d, "zephyr.bin")
        with open(cls.image, "wb") as f:
            f.write(os.urandom(150001))   # not a multiple of 64: exercises the SHA-256 padding
        cls.seed, cls.root = os.urandom(32).hex(), os.urandom(32).hex()
        cls.procs = []
        cls.port, cls.fp = cls.start(cls.seed)
        with socket.create_connection(("127.0.0.1", cls.port), timeout=5) as s:
            s.sendall(b"PQKEY\n")
            reply = b""
            while not reply.endswith(b"\r\n"):
                reply += s.recv(65536)
        p = reply.split()
        cls.pk = bytes.fromhex(p[2].decode())
        with open(os.path.join(cls.d, "ep.pub"), "w") as f:
            f.write(cls.pk.hex())

    @classmethod
    def start(cls, seed):
        port = free_port()
        pr = subprocess.Popen([cls.exe, str(port), seed, cls.root, os.path.join(cls.d, "gw.pub"), cls.image],
                              stdout=subprocess.PIPE, text=True)
        cls.procs.append(pr)
        line = pr.stdout.readline().split()
        assert line[0] == "READY", line
        return port, line[1]

    @classmethod
    def tearDownClass(cls):
        for pr in cls.procs:
            pr.kill()
            pr.wait()

    def ep(self, **kw):
        with open(self.image, "rb") as f:
            good = hashlib.sha256(f.read()).hexdigest()
        e = {"name": "frdm-rw612", "kind": "aegis-device", "host": "127.0.0.1", "port": self.port,
             "pq_pub_file": "ep.pub", "heartbeat_mac": "kmac256",
             "allowed": [{"type": "APP", "measurement_value": good}]}
        e.update(kw)
        return e

    def test_1_attest_device_key_trust(self):
        v = fleet.attest(self.ep(), None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "device-key")
        self.assertEqual(v["pq_signature"], "ML-DSA-65 valid")
        with open(self.image, "rb") as f:
            self.assertEqual(v["measurements"], {"APP": hashlib.sha256(f.read()).hexdigest()})
        self.assertEqual(v["instance_id"], "02" + hashlib.sha256(self.pk).hexdigest())
        self.assertEqual(self.fp, hashlib.sha256(self.pk).hexdigest())

    def test_2_same_seed_same_key_other_seed_other_key(self):
        _, fp_again = self.start(self.seed)
        _, fp_other = self.start(os.urandom(32).hex())
        self.assertEqual(fp_again, self.fp)
        self.assertNotEqual(fp_other, self.fp)

    def test_3_changed_image_quarantined(self):
        e = self.ep()
        e["allowed"][0]["measurement_value"] = "00" * 32
        v = fleet.attest(e, None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertTrue(any("APP" in r for r in v["reasons"]), v["reasons"])

    def test_4_wrong_pinned_key_and_wrong_kind_refused(self):
        other_pk, _ = mldsa.keypair()
        with open(os.path.join(self.d, "other.pub"), "w") as f:
            f.write(other_pk.hex())
        v = fleet.attest(self.ep(pq_pub_file="other.pub"), None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertIn("ML-DSA-65 quote signature invalid", v["reasons"])
        v = fleet.attest(self.ep(kind="aegis-linux"), None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertIn("profile is not aegis-linux-software-v1", v["reasons"])

    def test_5_provision_heartbeat_session(self):
        r = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {"APP": "x"}, timeout=20)
        sid, ch = fleet.query_session(self.ep())
        self.assertEqual(sid, r["session_id"])
        self.assertEqual(ch, r["credential_sha3_256"])
        for n in (1, 2, 3):
            status, ctr = fleet.heartbeat(self.ep(), r["session_key"], timeout=10)
            self.assertEqual(ctr, n)
            self.assertTrue(status.startswith(b"uptime_s=") and status.endswith(b";fw=rw612-0.1.0"), status)
        with self.assertRaises(ValueError):
            fleet.heartbeat(self.ep(heartbeat_mac="sha3-256"), r["session_key"], timeout=10)

    def kem_raw(self, sign_key, bind_ct=True, pk=None):
        nonce = os.urandom(32)
        p = fleet._exchange("127.0.0.1", self.port, "PQKEMINIT " + nonce.hex(), 10).split()
        ek = bytes.fromhex(p[2])
        self.assertTrue(mldsa.verify(self.pk, fleet.KEM_INIT_LABEL, nonce + ek, bytes.fromhex(p[4])))
        ct, _ = mlkem.encaps(ek)
        body = {"v": 1, "type": "credential", "endpoint": "frdm-rw612",
                "endpoint_pq_pk_sha256": hashlib.sha256(pk or self.pk).hexdigest(),
                "kem_ct_sha3_256": fleet._sha3(ct if bind_ct else b"other").hex(), "expires": 4102444800}
        cred = wire.canonical(body) + b"\n" + mldsa.sign(sign_key, fleet.CRED_LABEL, wire.canonical(body))
        return fleet._exchange("127.0.0.1", self.port, "PQKEMFIN %s %s" % (ct.hex(), cred.hex()), 10)

    def test_6_forged_credentials_refused_and_session_kept(self):
        r = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {}, timeout=20)
        _, other_sk = mldsa.keypair()
        self.assertIn("ERR cred signature", self.kem_raw(other_sk))
        self.assertIn("ERR cred other-exchange", self.kem_raw(self.gw_sk, bind_ct=False))
        self.assertIn("ERR cred other-endpoint", self.kem_raw(self.gw_sk, pk=b"another device"))
        self.assertIn("ERR cred no-exchange", fleet._exchange("127.0.0.1", self.port, "PQKEMFIN 00 00", 10))
        sid, _ = fleet.query_session(self.ep())
        self.assertEqual(sid, r["session_id"], "a refused exchange must not replace the session")

    def test_7_malformed_requests(self):
        for line in ("", "PQCHAL zz", "PQCHAL " + "00" * 31, "PQCHAL " + "0" * 63, "HELLO", "PQKEY extra",
                     "PQHB " + "00" * 32 + " extra", "PQKEMINIT " + "00" * 33, "A B C D E"):
            reply = fleet._exchange("127.0.0.1", self.port, line, 10)
            self.assertTrue(reply.startswith("ERR"), (line, reply))
        reply = fleet._exchange("127.0.0.1", self.port, "PQKEY " + "0" * 20000, 10)
        self.assertTrue(reply.startswith("ERR"), reply)


@unittest.skipUnless(os.path.isdir(MLDSA) and os.path.isdir(MLKEM), "mldsa-native / mlkem-native not found")
class Rw612TfmProfile(unittest.TestCase):
    """The same protocol code configured as the TF-M partition does it (endpoints/rw612/tfm/aegis_pq): profile
    aegis-rw612-tfm-v1 with SPE and NSPE, the gateway's "trustzone" label, and the profile pin that stops the
    single-image prover (same chip, same key) from passing as the TrustZone one."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.exe = os.path.join(cls.d, "aegis_rw612_host")
        build(cls.exe)
        cls.gw_pk, cls.gw_sk = mldsa.keypair()
        with open(os.path.join(cls.d, "gw.pub"), "w") as f:
            f.write(cls.gw_pk.hex())
        cls.spe, cls.nspe = os.path.join(cls.d, "spe.bin"), os.path.join(cls.d, "nspe.bin")
        for path, n in ((cls.spe, 0x9F000), (cls.nspe, 70001)):
            with open(path, "wb") as f:
                f.write(os.urandom(n))
        cls.seed, cls.root = os.urandom(32).hex(), os.urandom(32).hex()
        cls.procs = []
        cls.port_tfm = cls.start(cls.spe, cls.nspe)
        cls.port_els = cls.start(cls.spe)          # the single-image prover on the same chip (same seed)
        with socket.create_connection(("127.0.0.1", cls.port_tfm), timeout=5) as s:
            s.sendall(b"PQKEY\n")
            reply = b""
            while not reply.endswith(b"\r\n"):
                reply += s.recv(65536)
        cls.pk = bytes.fromhex(reply.split()[2].decode())
        with open(os.path.join(cls.d, "ep.pub"), "w") as f:
            f.write(cls.pk.hex())

    @classmethod
    def start(cls, *images):
        port = free_port()
        pr = subprocess.Popen([cls.exe, str(port), cls.seed, cls.root, os.path.join(cls.d, "gw.pub"), *images],
                              stdout=subprocess.PIPE, text=True)
        cls.procs.append(pr)
        assert pr.stdout.readline().startswith("READY")
        return port

    @classmethod
    def tearDownClass(cls):
        for pr in cls.procs:
            pr.kill()
            pr.wait()

    def sha(self, path):
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def ep(self, port, **kw):
        e = {"name": "frdm-rw612", "kind": "aegis-device", "host": "127.0.0.1", "port": port, "pq_pub_file": "ep.pub",
             "heartbeat_mac": "kmac256", "profile": "aegis-rw612-tfm-v1",
             "allowed": [{"type": "SPE", "measurement_value": self.sha(self.spe)},
                         {"type": "NSPE", "measurement_value": self.sha(self.nspe)}]}
        e.update(kw)
        return e

    def test_1_trustzone_admitted_with_both_measurements(self):
        v = fleet.attest(self.ep(self.port_tfm), None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "trustzone")
        self.assertEqual(v["measurements"], {"SPE": self.sha(self.spe), "NSPE": self.sha(self.nspe)})

    def test_2_changed_non_secure_image_quarantined(self):
        e = self.ep(self.port_tfm)
        e["allowed"][1]["measurement_value"] = "00" * 32
        v = fleet.attest(e, None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertTrue(any("NSPE" in r for r in v["reasons"]), v["reasons"])

    def test_3_single_image_prover_refused_by_the_profile_pin(self):
        """Same chip, same key, valid signature: only the pin tells the two firmwares apart."""
        v = fleet.attest(self.ep(self.port_els), None, self.d, timeout=10)
        self.assertEqual(v.get("pq_signature"), "ML-DSA-65 valid")
        self.assertFalse(v["admitted"])
        self.assertIn("profile aegis-rw612-els-v1, policy requires aegis-rw612-tfm-v1", v["reasons"])
        unpinned = self.ep(self.port_els, profile=None,
                           allowed=[{"type": "APP", "measurement_value": self.sha(self.spe)}])
        v = fleet.attest(unpinned, None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "device-key")

    def test_4_provision_and_heartbeat(self):
        r = fleet.provision(self.ep(self.port_tfm), self.d, self.gw_sk, "gid", {}, timeout=20)
        status, ctr = fleet.heartbeat(self.ep(self.port_tfm), r["session_key"], timeout=10)
        self.assertEqual(ctr, 1)
        self.assertEqual(status, b"requests=0;fw=rw612-tfm-0.2.0")


if __name__ == "__main__":
    unittest.main()
