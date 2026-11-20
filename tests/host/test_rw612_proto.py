# SPDX-License-Identifier: Apache-2.0
"""The Prover SDK's protocol core (sdk/src/aegis_proto.c, the same C file as in every device's firmware),
built for the PC and run against the gateway's own code (fleet.py): attestation with device-key trust, ML-KEM
provisioning with the credential checks, KMAC256 heartbeats, the session query, and the refusals (a changed
image, a wrong pinned key, a credential from another key, for another exchange or for another endpoint), and the
session's end on the endpoint's own clock (docs/endpoint-expiry.md), which the tests move through a file.
One transcript (docs/architecture.md): an exchange that continues a quote, what the C code refuses in it, and the two
firmwares of this chip that hold the same key (the single-image prover and the TF-M partition): a quote from one and
the exchange from the other, which is audit finding 2 as it exists on this bench.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import hashlib
import os
import re
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
import transcript  # noqa: E402
import wire  # noqa: E402

TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
SDK = os.path.join(ROOT, "sdk")


def build(out):
    """The SDK's core behind a TCP socket, through the reference port (sdk/ports/host)."""
    cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-D_GNU_SOURCE",
           '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"',
           "-I", os.path.join(SDK, "include"), "-I", os.path.join(SDK, "src"), "-I", os.path.join(SDK, "ports", "host"),
           "-I", os.path.join(SDK, "crypto", "mldsa"), "-I", MLDSA, "-I", os.path.join(SDK, "crypto", "mlkem"),
           "-I", MLKEM,
           os.path.join(SDK, "ports", "host", "host_main.c"), os.path.join(SDK, "ports", "host", "aegis_port_host.c"),
           os.path.join(SDK, "src", "aegis_proto.c"), os.path.join(SDK, "src", "aegis_sha256.c"),
           os.path.join(SDK, "src", "aegis_kmac.c"), os.path.join(SDK, "crypto", "mlkem_unit.c"),
           os.path.join(MLDSA, "mldsa_native.c"), "-o", out]
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
        cls.clock = os.path.join(cls.d, "clock")       # seconds added to the endpoint's session clock, or "fail"
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
                              stdout=subprocess.PIPE, text=True, env=dict(os.environ, AEGIS_TEST_CLOCK=cls.clock))
        cls.procs.append(pr)
        line = pr.stdout.readline().split()
        assert line[0] == "READY", line
        return port, line[1]

    @classmethod
    def tearDownClass(cls):
        for pr in cls.procs:
            pr.kill()
            pr.wait()

    def set_clock(self, text):
        with open(self.clock, "w") as f:
            f.write(str(text))

    def ask(self, line):
        return fleet._exchange("127.0.0.1", self.port, line, 10).strip()

    def ep(self, **kw):
        with open(self.image, "rb") as f:
            good = hashlib.sha256(f.read()).hexdigest()
        e = {"name": "frdm-rw612", "kind": "aegis-device", "host": "127.0.0.1", "port": self.port,
             "pq_pub_file": "ep.pub", "heartbeat_mac": "kmac256", "profile": "aegis-rw612-els-v1",
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
        v = fleet.attest(self.ep(kind="aegis-linux", profile="aegis-linux-software-v1"), None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertIn("profile is not aegis-linux-software-v1", v["reasons"])
        v = fleet.attest(self.ep(kind="aegis-linux"), None, self.d, timeout=10)     # a pin the kind cannot have
        self.assertFalse(v["admitted"])
        self.assertTrue(v["reasons"][0].startswith("policy: pinned profile aegis-rw612-els-v1 is not one of kind"), v)

    def test_5_provision_heartbeat_session(self):
        r = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {"APP": "x"}, timeout=20)
        sid, ch = fleet.query_session(self.ep())
        self.assertEqual(sid, r["session_id"])
        self.assertEqual(ch, r["credential_sha3_256"])
        for n in (1, 2, 3):
            status, ctr = fleet.heartbeat(self.ep(), r["session_key"], timeout=10)
            self.assertEqual(ctr, n)
            # the platform's text, then the seconds the session has left: an hour and a sixteenth, less a second or two
            m = re.fullmatch(rb"uptime_s=\d+;link=1;fw=rw612-0\.1\.0;ttl=(\d+)", status)
            self.assertTrue(m and 3820 <= int(m.group(1)) <= 3825, status)
        with self.assertRaises(ValueError):
            fleet.heartbeat(self.ep(heartbeat_mac="sha3-256"), r["session_key"], timeout=10)

    def kem_raw(self, sign_key, bind_ct=True, pk=None, validity=None, edit=None):
        """Run the exchange by hand to send a credential the gateway code would never make. validity replaces the
        "issued" and "expires" fields; edit changes the signed body's text."""
        nonce = os.urandom(32)
        p = fleet._exchange("127.0.0.1", self.port, "PQKEMINIT " + nonce.hex(), 10).split()
        ek = bytes.fromhex(p[2])
        self.assertTrue(mldsa.verify(self.pk, fleet.KEM_INIT_LABEL, nonce + ek, bytes.fromhex(p[4])))
        ct, _ = mlkem.encaps(ek)
        body = {"v": 1, "type": "credential", "endpoint": "frdm-rw612",
                "endpoint_pq_pk_sha256": hashlib.sha256(pk or self.pk).hexdigest(),
                "kem_ct_sha3_256": fleet._sha3(ct if bind_ct else b"other").hex(),
                "kem_ek_sha3_256": fleet._sha3(ek).hex()}
        body.update({"issued": 4102441200, "expires": 4102444800} if validity is None else validity)
        text = wire.canonical(body)
        if edit:
            text = edit(text)
        cred = text + b"\n" + mldsa.sign(sign_key, fleet.CRED_LABEL, text)
        return fleet._exchange("127.0.0.1", self.port, "PQKEMFIN %s %s" % (ct.hex(), cred.hex()), 10)

    def test_6_forged_credentials_refused_and_session_kept(self):
        r = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {}, timeout=20)
        _, other_sk = mldsa.keypair()
        self.assertIn("ERR cred signature", self.kem_raw(other_sk))
        self.assertIn("ERR cred other-exchange", self.kem_raw(self.gw_sk, bind_ct=False))
        self.assertIn("ERR cred other-endpoint", self.kem_raw(self.gw_sk, pk=b"another device"))
        self.assertIn("ERR cred no-exchange", fleet._exchange("127.0.0.1", self.port, "PQKEMFIN 00 00", 10))
        # replay: the gateway's own valid PQKEMFIN from an earlier exchange, sent after a new PQKEMINIT
        rec = {}
        orig = fleet._exchange

        def spy(host, port, line, timeout):
            if line.startswith("PQKEMFIN"):
                rec["fin"] = line
            return orig(host, port, line, timeout)
        fleet._exchange = spy
        try:
            r = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {}, timeout=20)
        finally:
            fleet._exchange = orig
        fleet._exchange("127.0.0.1", self.port, "PQKEMINIT " + os.urandom(32).hex(), 10)
        self.assertIn("ERR cred other-key", fleet._exchange("127.0.0.1", self.port, rec["fin"], 10))
        sid, _ = fleet.query_session(self.ep())
        self.assertEqual(sid, r["session_id"], "a refused exchange must not replace the session")

    def bound_raw(self, name=lambda t2: t2):
        """A quote and the exchange that continues it, by hand; name gives the transcript the credential names (None:
        none). Returns the PQKEMFIN reply and the tag the gateway would compare it with."""
        v = fleet.attest(self.ep(), None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        ch, th = bytes.fromhex(v["quote"]["challenge"]), bytes.fromhex(v["quote"]["token_sha3_256"])
        p = fleet._exchange("127.0.0.1", self.port, "PQKEMINIT " + ch.hex(), 10).split()
        ek, sig = bytes.fromhex(p[2]), bytes.fromhex(p[4])
        t2 = transcript.kem_init(transcript.quote(ch, th), ek)
        self.assertTrue(mldsa.verify(self.pk, transcript.KEM_INIT_LABEL, t2, sig))
        self.assertFalse(mldsa.verify(self.pk, fleet.KEM_INIT_LABEL, ch + ek, sig))
        ct, k = mlkem.encaps(ek)
        body = {"v": 1, "type": "credential", "endpoint": "frdm-rw612",
                "endpoint_pq_pk_sha256": hashlib.sha256(self.pk).hexdigest(),
                "kem_ct_sha3_256": fleet._sha3(ct).hex(), "kem_ek_sha3_256": fleet._sha3(ek).hex(),
                "issued": 4102441200, "expires": 4102444800}
        if name:
            body["transcript_sha3_256"] = name(t2).hex()
        cred = wire.canonical(body) + b"\n" + mldsa.sign(self.gw_sk, fleet.CRED_LABEL, wire.canonical(body))
        reply = fleet._exchange("127.0.0.1", self.port, "PQKEMFIN %s %s" % (ct.hex(), cred.hex()), 10).strip()
        return reply, transcript.confirm_tag(k, transcript.kem_fin(t2, ct, cred))

    def test_a_transcript_bound_exchange(self):
        self.set_clock(0)
        ep = self.ep(transcript="v2")
        v = fleet.attest(ep, None, self.d, timeout=10)
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", v["measurements"], timeout=20, quote=v["quote"])
        self.assertEqual(r["transcript"], "v2")
        self.assertEqual(fleet.query_session(ep), (r["session_id"], r["credential_sha3_256"]))
        self.assertEqual(fleet.heartbeat(ep, r["session_key"], timeout=10)[1], 1)
        # a quote continues one exchange: the same quote again gets the unbound exchange, which the gateway refuses
        with self.assertRaises(fleet.TranscriptRefused) as e:
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=v["quote"])
        self.assertIn("answered the unbound exchange", str(e.exception))
        self.assertEqual(fleet.query_session(ep)[0], r["session_id"], "a refused exchange must not replace the session")
        # a quote of an earlier cycle is not the last one; the last one works
        fleet.attest(ep, None, self.d, timeout=10)
        newer = fleet.attest(ep, None, self.d, timeout=10)
        with self.assertRaises(fleet.TranscriptRefused):
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=v["quote"])
        r2 = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=newer["quote"])
        self.assertNotEqual(r2["session_id"], r["session_id"])
        # and the unbound exchange is what an entry without the key still gets, from the same firmware
        r3 = fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {}, timeout=20)
        self.assertIsNone(r3["transcript"])
        self.assertEqual(fleet.heartbeat(self.ep(), r3["session_key"], timeout=10)[1], 1)

    def test_b_credential_must_name_the_transcript(self):
        self.set_clock(0)
        ep = self.ep(transcript="v2")
        v = fleet.attest(ep, None, self.d, timeout=10)
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=v["quote"])
        for name in (None, lambda t2: bytes(32), lambda t2: t2[::-1]):
            self.assertEqual(self.bound_raw(name)[0], "ERR cred other-transcript")
        self.assertEqual(fleet.query_session(ep)[0], r["session_id"], "a refused credential must not replace the session")
        reply, tag = self.bound_raw()
        self.assertEqual(reply, "PQKEMOK %s END" % tag.hex())

    def test_c_quote_does_not_outlive_a_restart(self):
        """The same seed in a second process: the same key after a restart. It signed no quote, so it answers the
        unbound exchange, and the gateway refuses to finish with it."""
        port, fp = self.start(self.seed)
        self.assertEqual(fp, self.fp)
        ep = self.ep(transcript="v2")
        v = fleet.attest(ep, None, self.d, timeout=10)
        with self.assertRaises(fleet.TranscriptRefused) as e:
            fleet.provision(dict(ep, port=port), self.d, self.gw_sk, "gid", {}, timeout=20, quote=v["quote"])
        self.assertIn("answered the unbound exchange", str(e.exception))
        self.assertEqual(fleet._exchange("127.0.0.1", port, "PQSESSION", 10).strip(), "ERR pq no-session")

    def test_8_session_ends_on_the_endpoints_clock(self):
        """The credential lasts an hour (fleet.CRED_LIFETIME_S); the endpoint ends the session 3825 s (an hour and a
        sixteenth) after the PQKEMFIN on its own clock, whether or not the gateway is still there."""
        self.set_clock(0)
        ep = self.ep()
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20)
        self.assertEqual(r["body"]["expires"] - r["body"]["issued"], 3600)
        fleet.heartbeat(ep, r["session_key"], timeout=10)
        self.set_clock(3600 + 225 - 4)                      # before the end: still answered, a few seconds left
        status, ctr = fleet.heartbeat(ep, r["session_key"], timeout=10)
        self.assertEqual(ctr, 2)
        self.assertTrue(1 <= int(status.rsplit(b";ttl=", 1)[1]) <= 4, status)
        self.assertEqual(fleet.query_session(ep)[0], r["session_id"])
        self.set_clock(3600 + 225)                          # the end: refused, and the session is gone
        with self.assertRaises(ValueError):
            fleet.heartbeat(ep, r["session_key"], timeout=10)
        self.assertEqual(self.ask("PQHB " + "00" * 32), "ERR pq expired")
        self.assertEqual(self.ask("PQSESSION"), "ERR pq expired")
        self.set_clock(0)                                   # it does not come back with the clock
        self.assertEqual(self.ask("PQHB " + "00" * 32), "ERR pq expired")
        self.set_clock(3600 + 225)
        self.assertTrue(fleet.attest(ep, None, self.d, timeout=10)["admitted"])   # attestation needs no session
        r2 = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20)        # what the gateway does next
        status, ctr = fleet.heartbeat(ep, r2["session_key"], timeout=10)
        self.assertEqual(ctr, 1)
        self.assertNotEqual(r2["session_id"], r["session_id"])

    def test_9_no_session_without_a_clock(self):
        """A clock that fails or runs backwards cannot measure a lifetime: the session ends, and none starts."""
        self.set_clock(4000)
        ep = self.ep()
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20)
        fleet.heartbeat(ep, r["session_key"], timeout=10)
        self.set_clock(3990)                                # ten seconds back
        self.assertEqual(self.ask("PQHB " + "00" * 32), "ERR pq expired")
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20)
        self.set_clock("fail")
        self.assertEqual(self.ask("PQSESSION"), "ERR pq expired")
        with self.assertRaises(ValueError) as e:
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20)
        self.assertIn("ERR clock", str(e.exception))
        self.assertTrue(fleet.attest(ep, None, self.d, timeout=10)["admitted"])
        self.set_clock(3990)
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20)
        self.assertEqual(fleet.heartbeat(ep, r["session_key"], timeout=10)[1], 1)

    def test_A_credential_must_carry_a_lifetime(self):
        """ "issued" and "expires" once each, 1 to 10 digits, a lifetime of 1 s to a day; anything else is refused and
        the session in place is kept. The shortest lifetime ends after a second."""
        self.set_clock(8000)
        ep = self.ep()
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20)
        t = 4102444800
        for validity in ({"expires": t}, {"issued": t}, {}, {"issued": t, "expires": t}, {"issued": t, "expires": t - 1},
                         {"issued": t, "expires": t + 86401}, {"issued": str(t), "expires": t + 60},
                         {"issued": t, "expires": float(t + 60)}, {"issued": -5, "expires": 60},
                         {"issued": t * 10, "expires": t * 10 + 60},
                         {"issued": t, "expires": t + 60, "x": {"expires": t + 60}}):
            self.assertEqual(self.kem_raw(self.gw_sk, validity=validity).strip(), "ERR cred validity", validity)
        # the same field twice in the signed text
        twice = lambda text: text[:-1] + b',"expires":%d}' % (t + 3600)  # noqa: E731
        self.assertEqual(self.kem_raw(self.gw_sk, edit=twice).strip(), "ERR cred validity")
        self.assertEqual(fleet.query_session(ep)[0], r["session_id"], "a refused credential must not replace the session")
        fleet.heartbeat(ep, r["session_key"], timeout=10)
        self.assertTrue(self.kem_raw(self.gw_sk, validity={"issued": t, "expires": t + 86400}).startswith("PQKEMOK "))
        self.assertTrue(self.kem_raw(self.gw_sk, validity={"issued": 0, "expires": 1}).startswith("PQKEMOK "))
        self.assertTrue(self.ask("PQSESSION").startswith("PQSESSION "))
        self.set_clock(8001)
        self.assertEqual(self.ask("PQSESSION"), "ERR pq expired")

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
        # without a pin the entry is refused before the endpoint is asked (strict profiles)
        unpinned = self.ep(self.port_els, profile=None,
                           allowed=[{"type": "APP", "measurement_value": self.sha(self.spe)}])
        v = fleet.attest(unpinned, None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertNotIn("pq_signature", v)
        self.assertTrue(v["reasons"][0].startswith("policy: no profile pinned"), v["reasons"])
        v = fleet.attest(dict(unpinned, profile="aegis-rw612-els-v1"), None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "device-key")

    def test_5_enroll_keeps_an_existing_pin(self):
        """enroll-pq must not replace a pinned key with whatever the network returns."""
        import contextlib, io, json as _json
        pol = os.path.join(self.d, "fleet.json")
        with open(pol, "w") as f:
            _json.dump({"endpoints": [self.ep(self.port_els)]}, f)
        before = open(os.path.join(self.d, "ep.pub")).read()
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            fleet.main(["enroll-pq", pol])
        self.assertIn("kept frdm-rw612", out.getvalue())
        self.assertEqual(open(os.path.join(self.d, "ep.pub")).read(), before)

    def test_6_one_key_two_firmwares(self):
        """Audit finding 2 on this chip: the single-image prover and the TF-M partition derive the same ML-DSA-65 key.
        The gateway appraises the TF-M partition's quote (trustzone trust, SPE and NSPE as allowed); the ML-KEM
        exchange is then answered by the single-image prover."""
        ask = lambda port, line: fleet._exchange("127.0.0.1", port, line, 10).strip()  # noqa: E731
        tfm, els = self.ep(self.port_tfm, transcript="v2"), self.ep(self.port_els, transcript="v2")
        v = fleet.attest(tfm, None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "trustzone")
        # the other firmware has no such quote: it answers the unbound exchange
        with self.assertRaises(fleet.TranscriptRefused) as e:
            fleet.provision(els, self.d, self.gw_sk, "gid", v["measurements"], timeout=20, quote=v["quote"])
        self.assertIn("answered the unbound exchange", str(e.exception))
        # even after it signed a quote of its own for the same challenge: that quote says who it is
        self.assertTrue(ask(self.port_els, "PQCHAL " + v["quote"]["challenge"]).startswith("PQTOKEN "))
        with self.assertRaises(fleet.TranscriptRefused) as e:
            fleet.provision(els, self.d, self.gw_sk, "gid", v["measurements"], timeout=20, quote=v["quote"])
        self.assertIn("not signed over the transcript of the quote just appraised", str(e.exception))
        self.assertEqual(ask(self.port_els, "PQSESSION"), "ERR pq no-session")
        # the firmware that was appraised finishes its own transcript
        r = fleet.provision(tfm, self.d, self.gw_sk, "gid", v["measurements"], timeout=20, quote=v["quote"])
        self.assertEqual(fleet.query_session(tfm), (r["session_id"], r["credential_sha3_256"]))
        # without the policy key the swap goes through: a credential listing the TF-M measurements, a session with
        # the single-image prover
        v = fleet.attest(self.ep(self.port_tfm), None, self.d, timeout=10)
        r = fleet.provision(self.ep(self.port_els), self.d, self.gw_sk, "gid", v["measurements"], timeout=20)
        self.assertIsNone(r["transcript"])
        self.assertEqual(set(r["body"]["measurements"]), {"SPE", "NSPE"})
        self.assertEqual(ask(self.port_els, "PQSESSION").split()[1], r["session_id"])

    def test_4_provision_and_heartbeat(self):
        r = fleet.provision(self.ep(self.port_tfm), self.d, self.gw_sk, "gid", {}, timeout=20)
        status, ctr = fleet.heartbeat(self.ep(self.port_tfm), r["session_key"], timeout=10)
        self.assertEqual(ctr, 1)
        self.assertRegex(status, rb"^requests=0;stack=na;fw=rw612-tfm-0\.2\.2;ttl=382[345]$")


if __name__ == "__main__":
    unittest.main()
