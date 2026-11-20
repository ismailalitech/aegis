# SPDX-License-Identifier: Apache-2.0
"""The Prover SDK's standard evidence (sdk/src/aegis_proto.c built with -DAEGIS_EAT_COSE=1, docs/evidence-format.md):
the device's side of "evidence_format": "eat-cose-v1".

  off by default   the core built without the option answers PQEAT as an unknown request, and the verifier does not
                   fall back to the older quote for an entry that asks for standard evidence
  the objects      sdk/tests/eat_check.c makes an EAT at every length that changes an encoding (with ASan and UBSan,
                   and plain); each one is read here by the verifier's decoder (common/cose.py, common/eat.py), by
                   a COSE library (tools/verify_evidence.py: pycose, cbor2, cryptography) and, for the claims, byte
                   for byte against the encoder the verifier's tests use
  the verifier     the C core behind a socket (sdk/ports/host), appraised by fleet.py; a session bound to the EAT
                   quote by transcript v2 (T1 hashes the COSE Sig_structure); an evidence pack of it checked by the
                   standalone checker
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in ("common", "gateway/aegisd", "tools", "tests/host"):
    sys.path.insert(0, os.path.join(ROOT, p))
import cbor  # noqa: E402
import cose  # noqa: E402
import eat  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import transcript  # noqa: E402
import test_rw612_proto as rw  # noqa: E402

try:
    import verify_evidence as checker   # the standalone checker's functions, in this process
except Exception:  # noqa: BLE001 - pycose, cbor2 or ML-DSA in cryptography missing
    checker = None

SDK = rw.SDK
SAN = ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]
HAVE = bool(shutil.which("gcc")) and os.path.isdir(rw.MLDSA) and os.path.isdir(rw.MLKEM)
EAT = ["-DAEGIS_EAT_COSE=1"]


def build_check(out, flags):
    cmd = ["gcc", "-g", "-D_GNU_SOURCE", '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"', "-Wall", "-Wextra", "-Werror",
           "-Wno-unused-parameter", "-Wno-unused-function"] + flags
    for i in (os.path.join(SDK, "include"), os.path.join(SDK, "src"), os.path.join(SDK, "crypto", "mldsa"), rw.MLDSA,
              os.path.join(SDK, "crypto", "mlkem"), rw.MLKEM):
        cmd += ["-I", i]
    cmd += [os.path.join(SDK, "tests", "eat_check.c"), os.path.join(SDK, "src", "aegis_sha256.c"),
            os.path.join(SDK, "src", "aegis_kmac.c"), os.path.join(SDK, "crypto", "mlkem_unit.c"),
            os.path.join(rw.MLDSA, "mldsa_native.c"), "-o", out]
    subprocess.run(cmd, check=True)


def token_bytes(n):
    return bytes((i * 7 + 3) & 0xFF for i in range(n))


@unittest.skipUnless(HAVE, "needs gcc and mldsa-native / mlkem-native")
class Objects(unittest.TestCase):
    """Every object sdk/tests/eat_check.c makes."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def run_check(self, name, flags):
        exe = os.path.join(self.d, name)
        build_check(exe, flags)
        r = subprocess.run([exe], capture_output=True, text=True, timeout=600)
        self.assertEqual(r.returncode, 0, r.stdout[-400:] + r.stderr[-4000:])
        self.assertRegex(r.stdout, r"eat check: \d+ checks, 0 failed")
        lines = [ln.split() for ln in r.stdout.splitlines()]
        pk = bytes.fromhex(next(ln[1] for ln in lines if ln[0] == "KEY"))
        return pk, {ln[1]: tuple(bytes.fromhex(x) for x in ln[2:5]) for ln in lines if ln[0] == "EAT"}

    def expected(self, name):
        """The claims a case must carry, from the same inputs, made by the encoder of the verifier's tests."""
        def comp(i):
            return bytes([0x10 + i]) * 32
        plain = {"one-measurement": ([("APP", comp(0))], "0.1.0"), "exact-buffer": ([("APP", comp(0))], "0.1.0"),
                 "two-measurements": ([("SPE", comp(0)), ("NSPE", comp(1))], "0.1.0"),
                 "labels-23-24-64": ([("a" * 23, comp(0)), ("b" * 24, comp(1)), ("c" * 64, comp(2))], "0.1.0"),
                 "sixteen": ([("C%02d" % i, comp(i)) for i in range(16)], "0.1.0"),
                 "again": ([("APP", comp(0))], "0.1.0"), "version-empty": ([("APP", comp(0))], ""),
                 "version-23": ([("APP", comp(0))], "1" * 23), "version-24": ([("APP", comp(0))], "2" * 24),
                 "version-64": ([("APP", comp(0))], "3" * 64), "work-min": ([("APP", comp(0))], "0.1.0"),
                 "work-full-then-fits": ([("c" * 64, comp(0))], "3" * 64),
                 "platform-key": ([("APP", comp(0))], "0.1.0"), "line-measurement": ([("APP", b"\x77" * 32)], "0.1.0")}
        if name in plain:
            comps, version = plain[name]
            return [(n, d, version) for n, d in comps], None
        if name.startswith(("token-", "line-token")):
            fixed = name.rsplit("-", 1)[1]
            return None, int(fixed) if name.startswith("token-") and fixed.isdigit() and "buffer" not in name else True
        self.fail("a case the test does not know: %s" % name)

    def check_objects(self, pk, objects):
        self.assertGreaterEqual(len(objects), 40)
        kid = hashlib.sha256(bytes.fromhex("a30107033830205907a0") + pk).digest()
        seen_heads = set()
        for name, (challenge, data, t1) in objects.items():
            with self.subTest(name):
                s = cose.verify1(data, pk)                              # the verifier's reading: strict, one encoding
                self.assertEqual((s.kid, s.typ), (kid, "application/eat+cwt"))
                ev = eat.read_evidence(s.payload, pk)
                self.assertEqual(ev["nonce"], challenge)
                # transcript v2: T1 over the bytes the signature covers
                self.assertEqual(t1, transcript.quote(challenge, transcript.token_hash(s.tbs)))
                self.assertEqual(s.tbs, cbor.dumps(["Signature1", s.protected, b"", s.payload]))
                comps, token = self.expected(name)
                if comps is not None:
                    self.assertEqual(s.payload, eat.evidence_payload(challenge, pk, comps, "aegis-rw612-tfm-v1"))
                else:
                    tok = ev["platform_token"]
                    self.assertEqual(tok, token_bytes(len(tok)))
                    if token is not True:
                        self.assertEqual(len(tok), token)
                    self.assertEqual(s.payload, eat.evidence_payload(challenge, pk, platform_token=tok))
                    seen_heads.add((1 if len(tok) + 2 < 24 else 2 if len(tok) + 2 < 256 else 3,
                                    2 if len(s.payload) < 256 else 3))
                if checker is not None and comps is not None:           # a COSE library's reading
                    rep = checker.check_evidence(data, pk, challenge)
                    self.assertEqual(rep["quote_sha3_256"], hashlib.sha3_256(s.tbs).hexdigest())
                    self.assertEqual([(m["name"], m["sha256"], m["version"]) for m in rep["measurements"]],
                                     [(n, d.hex(), v) for n, d, v in comps])
                elif checker is not None:
                    # this program's token is a pattern, not a COSE object: the envelope and the claims only
                    claims, tbs = checker.open_sign1(data, pk, "evidence")
                    self.assertEqual((tbs, claims[10], claims[266]), (s.tbs, challenge, {"platform": b"\xd8\x3d" + tok}))
        # every head length of the nested token and of the payload was crossed
        self.assertEqual(seen_heads, {(1, 2), (2, 2), (2, 3), (3, 3)})
        fills = objects["token-fills-work"][1]
        self.assertEqual(len(eat.read_evidence(cose.verify1(fills, pk).payload, pk)["platform_token"]),
                         2854 - 230)                                    # AEGIS_WORK_LEN(1440), less the EAT around it

    def test_with_sanitizers(self):
        self.check_objects(*self.run_check("eat-asan", ["-O1"] + SAN))

    def test_plain(self):
        self.check_objects(*self.run_check("eat-plain", ["-O2"]))

    def test_the_checks_notice_a_core_that_signs_other_bytes(self):
        """Control: a core that keeps T1 over the payload instead of the Sig_structure is noticed here."""
        src = os.path.join(self.d, "changed")
        os.makedirs(src, exist_ok=True)
        with open(os.path.join(SDK, "src", "aegis_proto.c")) as f:
            text = f.read()
        self.assertEqual(text.count("quote_keep(p, w, n);"), 1)
        with open(os.path.join(src, "aegis_proto.c"), "w") as f:
            f.write(text.replace("quote_keep(p, w, n);", "quote_keep(p, w + EAT_HEAD_LEN, n - EAT_HEAD_LEN);"))
        exe = os.path.join(self.d, "eat-changed")
        build_check(exe, ["-O2", "-I", src])
        r = subprocess.run([exe], capture_output=True, text=True, timeout=600)
        ln = next(ln.split() for ln in r.stdout.splitlines() if ln.startswith("EAT one-measurement "))
        pk = bytes.fromhex(next(x.split()[1] for x in r.stdout.splitlines() if x.startswith("KEY ")))
        s = cose.verify1(bytes.fromhex(ln[3]), pk)
        self.assertNotEqual(bytes.fromhex(ln[4]), transcript.quote(bytes.fromhex(ln[2]), transcript.token_hash(s.tbs)))


@unittest.skipUnless(HAVE, "needs gcc and mldsa-native / mlkem-native")
class Device(unittest.TestCase):
    """The core with the option behind a socket, and the fleet verifier."""

    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.exe, cls.exe_off = os.path.join(cls.d, "host-eat"), os.path.join(cls.d, "host-default")
        rw.build(cls.exe, EAT)
        rw.build(cls.exe_off)
        cls.gw_pk, cls.gw_sk = mldsa.keypair()
        with open(os.path.join(cls.d, "gw.pub"), "w") as f:
            f.write(cls.gw_pk.hex())
        cls.images = []
        for name in ("app.bin", "nspe.bin"):
            path = os.path.join(cls.d, name)
            with open(path, "wb") as f:
                f.write(os.urandom(70001))
            cls.images.append(path)
        cls.seed, cls.root = os.urandom(32).hex(), os.urandom(32).hex()
        cls.rng = os.path.join(cls.d, "rng")
        cls.procs = []
        cls.port, cls.fp = cls.start(cls.exe)
        cls.pk = fleet.request_pq_key("127.0.0.1", cls.port)
        with open(os.path.join(cls.d, "ep.pub"), "w") as f:
            f.write(cls.pk.hex())

    @classmethod
    def start(cls, exe, images=1, **env):
        port = rw.free_port()
        pr = subprocess.Popen([exe, str(port), cls.seed, cls.root, os.path.join(cls.d, "gw.pub")] + cls.images[:images],
                              stdout=subprocess.PIPE, text=True, env=dict(os.environ, AEGIS_TEST_RNG=cls.rng, **env))
        cls.procs.append(pr)
        line = pr.stdout.readline().split()
        assert line[0] == "READY", line
        return port, line[1]

    @classmethod
    def tearDownClass(cls):
        for pr in cls.procs:
            pr.kill()
            pr.wait()
            pr.stdout.close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def digest(self, i=0):
        with open(self.images[i], "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()

    def ep(self, port=None, **kw):
        e = {"name": "frdm-rw612", "kind": "aegis-device", "host": "127.0.0.1", "port": port or self.port,
             "pq_pub_file": "ep.pub", "heartbeat_mac": "kmac256", "profile": "aegis-rw612-els-v1",
             "allowed": [{"type": "APP", "measurement_value": self.digest()}], "evidence_format": "eat-cose-v1"}
        e.update(kw)
        return {k: v for k, v in e.items() if v is not None}

    def ask(self, line, port=None):
        return fleet._exchange("127.0.0.1", port or self.port, line, 10).strip()

    def test_1_the_device_is_admitted_on_standard_evidence(self):
        facts = {}
        v = fleet.attest(self.ep(), None, self.d, 10, facts=facts)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual((v["evidence_format"], v["trust"], v["pq_signature"]), ("eat-cose-v1", "device-key", "ML-DSA-65 valid"))
        self.assertEqual(v["measurements"], {"APP": self.digest()})
        self.assertEqual(v["instance_id"], "01" + hashlib.sha256(self.pk).hexdigest())
        s = cose.verify1(facts["evidence"], self.pk)
        self.assertEqual(s.payload, eat.evidence_payload(bytes.fromhex(v["quote"]["challenge"]), self.pk,
                                                         [("APP", bytes.fromhex(self.digest()), "0.1.0")],
                                                         "aegis-rw612-els-v1"))
        self.assertEqual(v["quote"]["token_sha3_256"], hashlib.sha3_256(s.tbs).hexdigest())
        self.assertLess(len(facts["evidence"]), 3700)
        # the same rules as for the older quote
        e = self.ep()
        e["allowed"][0]["measurement_value"] = "00" * 32
        self.assertFalse(fleet.attest(e, None, self.d, 10)["admitted"])
        self.assertFalse(fleet.attest(self.ep(profile="aegis-rw612-tfm-v1"), None, self.d, 10)["admitted"])

    def test_2_the_same_firmware_still_answers_the_older_request(self):
        v = fleet.attest(self.ep(evidence_format=None), None, self.d, 10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertNotIn("evidence_format", v)
        self.assertEqual(v["instance_id"], "02" + hashlib.sha256(self.pk).hexdigest())

    def test_3_off_by_default(self):
        port, fp = self.start(self.exe_off)
        self.assertEqual(fp, self.fp)
        self.assertEqual(self.ask("PQEAT " + "00" * 32, port), "ERR unknown")
        v = fleet.attest(self.ep(port), None, self.d, 10)
        self.assertFalse(v["admitted"])
        self.assertIn("no EAT evidence", v["reasons"][0])
        self.assertTrue(fleet.attest(self.ep(port, evidence_format=None), None, self.d, 10)["admitted"])

    def test_4_two_measurements_and_a_key_held_by_the_platform(self):
        port, _ = self.start(self.exe, images=2)
        e = self.ep(port, profile="aegis-rw612-tfm-v1",
                    allowed=[{"type": "SPE", "measurement_value": self.digest(0)},
                             {"type": "NSPE", "measurement_value": self.digest(1)}])
        v = fleet.attest(e, None, self.d, 10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual((v["trust"], v["measurements"]), ("trustzone", {"SPE": self.digest(0), "NSPE": self.digest(1)}))
        port, fp = self.start(self.exe, AEGIS_HOST_PLATFORM_KEY="1")
        self.assertEqual(fp, self.fp)
        self.assertTrue(fleet.attest(self.ep(port), None, self.d, 10)["admitted"])

    def test_5_malformed_requests_and_a_failing_generator(self):
        for line in ("PQEAT", "PQEAT 00", "PQEAT " + "00" * 31, "PQEAT " + "00" * 33, "PQEAT " + "zz" * 32,
                     "PQEAT " + "00" * 32 + " 00"):
            self.assertIn(self.ask(line), ("ERR bad-request", "ERR unknown"), line)
        self.assertTrue(self.ask("PQEAT " + "00" * 32).startswith("PQEAT "))
        with open(self.rng, "w") as f:
            f.write("fail")
        try:
            self.assertEqual(self.ask("PQEAT " + "00" * 32), "ERR sign")      # never a signature without randomness
            v = fleet.attest(self.ep(), None, self.d, 10)
            self.assertFalse(v["admitted"])
        finally:
            os.unlink(self.rng)
        self.assertTrue(fleet.attest(self.ep(), None, self.d, 10)["admitted"])

    def test_6_a_session_continues_the_eat_quote(self):
        """Transcript v2 with T1 over the COSE Sig_structure, on both sides."""
        ep = self.ep(transcript="v2")
        v = fleet.attest(ep, None, self.d, 10)
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", v["measurements"], timeout=20, quote=v["quote"])
        self.assertEqual((r["transcript"], r["quote"]), ("v2", v["quote"]))
        status, ctr = fleet.heartbeat(ep, r["session_key"], timeout=10)
        self.assertEqual(ctr, 1)
        # the quote is used up
        with self.assertRaises(fleet.TranscriptRefused):
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=v["quote"])
        # the hash of the whole object, or of the claims, is not what the device signed
        v = fleet.attest(ep, None, self.d, 10)
        with self.assertRaises(fleet.TranscriptRefused):
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20,
                            quote=dict(v["quote"], token_sha3_256=hashlib.sha3_256(b"other").hexdigest()))
        # the device keeps one quote, the last of either kind: an older quote after a newer one of the other kind
        older = fleet.attest(ep, None, self.d, 10)
        newer = fleet.attest(self.ep(transcript="v2", evidence_format=None), None, self.d, 10)
        self.assertTrue(older["admitted"] and newer["admitted"])
        with self.assertRaises(fleet.TranscriptRefused):
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=older["quote"])
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=newer["quote"])
        self.assertEqual(r["transcript"], "v2")
        older = fleet.attest(self.ep(transcript="v2", evidence_format=None), None, self.d, 10)
        newer = fleet.attest(ep, None, self.d, 10)
        with self.assertRaises(fleet.TranscriptRefused):
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=older["quote"])
        self.assertEqual(fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=newer["quote"])["transcript"],
                         "v2")

    def test_7_a_cycle_a_session_and_a_pack_the_standalone_checker_verifies(self):
        state = tempfile.mkdtemp()
        with open(os.path.join(state, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "identity", "pk": self.gw_pk.hex()}}, f)
        with open(os.path.join(state, "identity.sk"), "wb") as f:
            f.write(self.gw_sk)
        pol = os.path.join(self.d, "fleet.json")
        with open(pol, "w") as f:
            json.dump({"timeout_s": 10, "endpoints": [self.ep(provision=True, transcript="v2")]}, f)
        with open(pol, "rb") as f:
            policy_bytes = f.read()
        v, = fleet.run_once(json.loads(policy_bytes), self.d, None, state=state, policy_bytes=policy_bytes)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertIn("bound to quote %s" % v["quote"]["token_sha3_256"][:12], v["credential"])
        self.assertEqual((v["session_binding"], v["attestation_result"]["status"]), ("transcript-v2", "warning"))
        with open(v["attestation_result"]["file"], "rb") as f:
            r = eat.read_ear(f.read(), self.gw_pk)
        self.assertEqual(r["verifier_claims"]["aegis.session-binding"], "transcript-v2")
        self.assertEqual(r["vector"], {0: -33, 2: -35})          # key pinned on first use; measured by the firmware
        out = os.path.join(tempfile.mkdtemp(), "pack")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(fleet.main(["export-evidence", pol, "frdm-rw612", "--out", out, "--state-dir", state,
                                         "--platform", "linux"]), 0)
        if checker is None:
            self.skipTest("the pack was made; checking it needs pycose, cbor2 and cryptography with ML-DSA")
        r = subprocess.run([sys.executable, "-I", os.path.join(ROOT, "tools", "verify_evidence.py"), "pack", out,
                            "--verifier-key", cose.key_thumbprint(self.gw_pk).hex(),
                            "--device-key", cose.key_thumbprint(self.pk).hex()], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        rep = json.loads(r.stdout)
        self.assertTrue(rep["verified"])
        self.assertEqual(rep["evidence"]["quote_sha3_256"], v["quote"]["token_sha3_256"])
        self.assertEqual(rep["evidence"]["measurements"], [{"name": "APP", "sha256": self.digest(), "version": "0.1.0"}])


if __name__ == "__main__":
    unittest.main()
