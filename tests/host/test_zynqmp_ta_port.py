# SPDX-License-Identifier: Apache-2.0
"""The ZynqMP endpoint's OP-TEE port of the Prover SDK (endpoints/zynqmp/optee) against the gateway's own code
(fleet.py) and the endorser (provision/aegis_provision.py), on the PC.

What runs is the board's code: the Linux bridge (bridge/aegis_tee_bridge.c, its main() and socket code unchanged) and
the trusted application (ta/aegis_ta.c with the SDK core, sdk/src/aegis_proto.c), built with the TA's own limits
(ta/sub.mk). They are joined by a stand-in for OP-TEE (optee/tests/ta_board.c: the client library the bridge calls,
the internal API the TA calls, the aegis.boot PTA as the board's FSBL hand-off fills it). What is not the board's:
the key derivation (the stand-in hashes a seed text; optee/tests/run.sh checks OP-TEE's real one), the generator,
and the clock (the PC's, moved through a file).

Checked: attestation with profile aegis-zynqmp-optee-v1 ("trustzone") and the seven measured partitions; a changed
TEE partition quarantined; the development profile without the hand-off; the exchange bound to the quote
(transcript v2), KMAC256 heartbeats, the session query; the session ended by the TA's own clock; no session on a
clock the normal world controls; endorsement of the TA's key and attestation with "endorsement": "required"; the
TA's stack against the size it asks OP-TEE for.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import contextlib
import hashlib
import io
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

os.environ.setdefault("TSS2_LOG", "all+NONE")
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
for p in ("common", "gateway/aegisd", "provision"):
    sys.path.insert(0, os.path.join(ROOT, p))
import aegis_provision as prov  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import psa_token  # noqa: E402

TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
SDK = os.path.join(ROOT, "sdk")
OPTEE = os.path.join(ROOT, "endpoints", "zynqmp", "optee")
TESTS = os.path.join(OPTEE, "tests")
VERIFY = psa_token.verify_with_cryptography
# the boot image's partitions as ta_board.c reports them (the FSBL's list on the board)
PARTS = ["PMUFW", "FSBL", "PL", "TFA", "TFA.1", "TEE", "UBOOT"]


def ta_flags():
    """The TA's build flags from ta/sub.mk: its limits and its version, as the board's build has them."""
    with open(os.path.join(OPTEE, "ta", "sub.mk")) as f:
        mk = f.read()
    flags = re.findall(r"-DAEGIS_(?:MAX_MEASUREMENTS|CLAIMS_MAX)=\w+", mk)
    version = re.search(r'-DAEGIS_DEVICE_VERSION=\\"([^"\\]+)\\"', mk).group(1)
    assert len(flags) == 2, flags
    return flags + ['-DAEGIS_DEVICE_FW="zynqmp-optee"', '-DAEGIS_DEVICE_VERSION="%s"' % version], version


def build(out, gw_pk):
    gen = os.path.join(os.path.dirname(out), "gen")
    os.makedirs(gen, exist_ok=True)
    with open(os.path.join(gen, "gateway_pk.h"), "w") as f:
        f.write("#define AEGIS_GATEWAY_PK { %s }\n" % ", ".join("0x%02x" % b for b in gw_pk))
    flags, _ = ta_flags()
    inc = [os.path.join(TESTS, "stub"), TESTS, gen, os.path.join(OPTEE, "ta"), os.path.join(OPTEE, "include"),
           os.path.join(OPTEE, "..", "handoff"), os.path.join(SDK, "include"), os.path.join(SDK, "src"),
           os.path.join(SDK, "crypto", "mldsa"), MLDSA, os.path.join(SDK, "crypto", "mlkem"), MLKEM]
    srcs = [os.path.join(OPTEE, "bridge", "aegis_tee_bridge.c"), os.path.join(TESTS, "ta_board.c"),
            os.path.join(OPTEE, "ta", "aegis_ta.c"), os.path.join(SDK, "src", "aegis_proto.c"),
            os.path.join(SDK, "src", "aegis_sha256.c"), os.path.join(SDK, "src", "aegis_kmac.c"),
            os.path.join(SDK, "crypto", "mlkem_unit.c"), os.path.join(MLDSA, "mldsa_native.c")]
    subprocess.run(["gcc", "-std=gnu11", "-O2", "-g", "-D_GNU_SOURCE", "-pthread",
                    '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"'] + flags + ["-I" + i for i in inc] + srcs +
                   ["-o", out], check=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def ask(port, line):
    with socket.create_connection(("127.0.0.1", port), timeout=30) as s:
        s.sendall(line.encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf.decode().strip()


def stand_in_digest(label, image=""):
    """ta_board.c's stand-in for a partition's measurement."""
    tail = image.encode() if label == "TEE" else b""
    return hashlib.sha256(b"stand-in for the partition\0" + label.encode() + b"\0" + tail).hexdigest()


@unittest.skipUnless(shutil.which("gcc") and os.path.isdir(MLDSA) and os.path.isdir(MLKEM),
                     "needs gcc and mldsa-native / mlkem-native")
class ZynqmpTaPort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()
        cls.gw_pk, cls.gw_sk = mldsa.keypair()
        cls.exe = os.path.join(cls.d, "zynqmp_ta_board")
        build(cls.exe, cls.gw_pk)
        cls.version = ta_flags()[1]
        cls.procs = []
        cls.clock = os.path.join(cls.d, "clock")
        cls.set_clock(0)
        cls.port, cls.banner = cls.start()
        cls.pk = bytes.fromhex(ask(cls.port, "PQKEY").split()[2])
        os.makedirs(os.path.join(cls.d, "keys"))
        cls.write_key("zynqmp.mldsa65.pub", cls.pk)
        cls.estate = tempfile.mkdtemp()
        prov.init(cls.estate, "bench", key_store="software")     # never this PC's TPM in a test
        cls.endorser = prov.Endorser(cls.estate)
        with contextlib.redirect_stdout(io.StringIO()):
            prov.main(["export", os.path.join(cls.d, "endorsers"), "--state", cls.estate])

    @classmethod
    def set_clock(cls, seconds):
        with open(cls.clock, "w") as f:
            f.write("%d\n" % seconds)

    @classmethod
    def write_key(cls, name, pk):
        with open(os.path.join(cls.d, "keys", name), "w") as f:
            f.write(pk.hex() + "\n")

    @classmethod
    def start(cls, **env):
        """Start the bridge with the TA behind it; returns its port and the TA's start-up line."""
        port = free_port()
        e = dict(os.environ, AEGIS_TEST_CLOCK=cls.clock)
        e.update(env)
        pr = subprocess.Popen([cls.exe, str(port)], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
                              env=e)
        cls.procs.append(pr)
        banner = ""
        for line in pr.stdout:
            if "Aegis TA:" in line:
                banner = line.strip()
            if line.startswith("AEGIS-TEE-BRIDGE ready"):
                return port, banner
        raise AssertionError("the bridge did not start: %s" % banner)

    @classmethod
    def tearDownClass(cls):
        for pr in cls.procs:
            pr.kill()
            pr.wait()
            pr.stdout.close()
        shutil.rmtree(cls.d, ignore_errors=True)
        shutil.rmtree(cls.estate, ignore_errors=True)

    def ep(self, port=None, image="", **kw):
        e = {"name": "zynqmp-te0808", "kind": "aegis-tee", "host": "127.0.0.1", "port": port or self.port,
             "pq_pub_file": "keys/zynqmp.mldsa65.pub", "heartbeat_mac": "kmac256", "profile": fleet.TEE_PROFILE,
             "allowed": [{"type": p, "measurement_value": stand_in_digest(p, image)} for p in PARTS]}
        e.update(kw)
        return e

    def test_1_attest_trustzone_with_the_hand_offs_measurements(self):
        self.assertIn("profile aegis-zynqmp-optee-v1", self.banner)
        self.assertIn("7 measurements, session clock trusted", self.banner)
        v = fleet.attest(self.ep(), None, self.d, timeout=30)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "trustzone")
        self.assertEqual(v["pq_signature"], "ML-DSA-65 valid")
        self.assertEqual(list(v["measurements"]), PARTS)
        self.assertEqual(v["measurements"]["TEE"], stand_in_digest("TEE"))

    def test_2_changed_tee_partition_quarantined_same_key(self):
        port, _ = self.start(AEGIS_TEST_IMAGE="another TA inside OP-TEE")
        self.assertEqual(bytes.fromhex(ask(port, "PQKEY").split()[2]), self.pk)   # the key is the chip's and the UUID's
        v = fleet.attest(self.ep(port), None, self.d, timeout=30)
        self.assertFalse(v["admitted"])
        self.assertTrue(any("TEE" in r for r in v["reasons"]), v["reasons"])
        v = fleet.attest(self.ep(port, image="another TA inside OP-TEE"), None, self.d, timeout=30)
        self.assertTrue(v["admitted"], v["reasons"])

    def test_3_without_the_hand_off_the_development_profile(self):
        port, banner = self.start(AEGIS_TEST_HANDOFF="none")
        self.assertIn("profile aegis-zynqmp-optee-devhuk-v1", banner)
        pk = bytes.fromhex(ask(port, "PQKEY").split()[2])
        self.assertNotEqual(pk, self.pk)
        self.write_key("devhuk.mldsa65.pub", pk)
        ep = self.ep(port, pq_pub_file="keys/devhuk.mldsa65.pub")
        v = fleet.attest(ep, None, self.d, timeout=30)
        self.assertFalse(v["admitted"])                     # the entry pins the chip's profile
        v = fleet.attest(dict(ep, profile=fleet.TEE_DEVHUK_PROFILE, allow_dev_profile=True, allowed=[
            {"type": "BOOTCHAIN", "measurement_value": "00" * 32}]), None, self.d, timeout=30)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "development-shared-key")

    def cycle(self, ep, endorsers=None):
        v = fleet.attest(ep, VERIFY, self.d, timeout=30, endorsers=endorsers)
        self.assertTrue(v["admitted"], v["reasons"])
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", v["measurements"], timeout=60, quote=v["quote"],
                            endorsers=endorsers)
        return v, r

    def test_4_bound_exchange_heartbeat_session(self):
        ep = self.ep(transcript="v2")
        v, r = self.cycle(ep)
        self.assertEqual(r["transcript"], "v2")
        sid, ch = fleet.query_session(ep)
        self.assertEqual((sid, ch), (r["session_id"], r["credential_sha3_256"]))
        for n in (1, 2):
            status, ctr = fleet.heartbeat(ep, r["session_key"], timeout=30)
            self.assertEqual(ctr, n)
            m = re.match(rb"^requests=(\d+);fw=zynqmp-optee-([0-9.]+);ttl=(\d+)$", status)
            self.assertTrue(m, status)
            self.assertEqual(m.group(2).decode(), self.version)
            # the credential's 3600 s and the core's margin for a slow clock (AEGIS_SESSION_LIMIT: 1/16 more)
            self.assertTrue(3815 <= int(m.group(3)) <= 3825, status)
        with self.assertRaises(fleet.TranscriptRefused):        # the quote continues one exchange only
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=60, quote=v["quote"])
        self.assertEqual(fleet.query_session(ep)[0], r["session_id"])

    def test_5_the_session_ends_on_the_tas_clock(self):
        port, _ = self.start()
        ep = self.ep(port, transcript="v2")
        _, r = self.cycle(ep)
        self.assertEqual(fleet.heartbeat(ep, r["session_key"], timeout=30)[1], 1)
        try:
            self.set_clock(3800)                                # within 3600 s and 1/16 more (3825)
            self.assertRegex(ask(port, "PQSESSION"), "^PQSESSION ")
            self.set_clock(3826)
            self.assertEqual(ask(port, "PQHB " + "00" * 32), "ERR pq expired")
            self.assertEqual(ask(port, "PQSESSION"), "ERR pq expired")
            with self.assertRaises(Exception):
                fleet.heartbeat(ep, r["session_key"], timeout=30)
        finally:
            self.set_clock(0)

    def test_6_no_session_on_a_clock_linux_controls(self):
        port, banner = self.start(AEGIS_TEST_TIME_LEVEL="100")
        self.assertIn("NOT trusted: no sessions", banner)
        ep = self.ep(port, transcript="v2")
        v = fleet.attest(ep, None, self.d, timeout=30)
        self.assertTrue(v["admitted"], v["reasons"])          # a quote needs no clock
        with self.assertRaises(ValueError):
            fleet.provision(ep, self.d, self.gw_sk, "gid", v["measurements"], timeout=60, quote=v["quote"])
        self.assertEqual(ask(port, "PQSESSION"), "ERR pq no-session")

    def test_7_endorsed_key_admitted_and_another_chip_refused(self):
        policy = {"endorsers": [self.endorser.policy_entry()]}
        out = tempfile.mkdtemp()
        res = prov.endorse(self.endorser, self.ep(), self.d, out, ecdsa_verify=VERIFY,
                           expect_pk_sha256=hashlib.sha256(self.pk).hexdigest())
        self.assertTrue(res["endorsed"], res)
        self.assertEqual(res["family"], "aegis-tee/" + fleet.TEE_PROFILE)
        ep = self.ep(transcript="v2", endorsement="required")
        policy["endpoints"] = [ep]
        fleet.install_endorsement(policy, self.d, res["record"])
        ep = policy["endpoints"][0]
        v, r = self.cycle(ep, policy["endorsers"])
        self.assertEqual(v["enrolment"], fleet.ENDORSED)
        self.assertEqual(r["transcript"], "v2")
        port, _ = self.start(AEGIS_TEST_SEED="another chip")   # the same image on another chip: another key
        v = fleet.attest(dict(ep, port=port), VERIFY, self.d, timeout=30, endorsers=policy["endorsers"])
        self.assertFalse(v["admitted"])

    def test_8_stack_within_what_the_ta_asks_for(self):
        port, _ = self.start(AEGIS_TEST_STACK="1")
        _, r = self.cycle(self.ep(port, transcript="v2"))
        fleet.heartbeat(self.ep(port), r["session_key"], timeout=30)
        used, size = map(int, ask(port, "TEST-STACK").split()[1:])
        self.assertGreater(used, 8192)
        self.assertLess(used, size * 3 // 4, (used, size))

    def test_9_line_limits(self):
        self.assertEqual(ask(self.port, "X" * 20000), "ERR too-long")
        self.assertEqual(ask(self.port, "PQKEMFIN 00 00"), "ERR cred no-exchange")


if __name__ == "__main__":
    unittest.main()
