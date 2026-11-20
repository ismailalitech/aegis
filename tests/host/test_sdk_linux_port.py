# SPDX-License-Identifier: Apache-2.0
"""The Prover SDK's port to Linux user space (sdk/ports/linux: the C prover a Linux device maker starts from) against
the gateway's own code (fleet.py), on the PC: attestation with software trust, an exchange that continues the quote
(one transcript), a KMAC256 heartbeat, the session query.

What is the port's own: its measurements are the Python prover's (endpoints/zybo/aegis_linux_prover.py, measure())
for the same --measure arguments, so one policy entry fits both provers; a file that cannot be read refuses the quote;
the device secrets are made at the first start, kept in files only their owner can read, give the same key after a
restart, and are refused when someone else could read them.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import hashlib
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, os.path.join(ROOT, "gateway", "aegisd"))
sys.path.insert(0, os.path.join(ROOT, "endpoints", "zybo"))
import fleet  # noqa: E402
import mldsa  # noqa: E402
import aegis_linux_prover as python_prover  # noqa: E402

TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
SDK = os.path.join(ROOT, "sdk")
PORT = os.path.join(SDK, "ports", "linux")


def build(out):
    subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-D_GNU_SOURCE",
                    '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"',
                    "-I", os.path.join(SDK, "include"), "-I", os.path.join(SDK, "src"), "-I", PORT,
                    "-I", os.path.join(SDK, "crypto", "mldsa"), "-I", MLDSA, "-I", os.path.join(SDK, "crypto", "mlkem"),
                    "-I", MLKEM,
                    os.path.join(PORT, "linux_main.c"), os.path.join(PORT, "aegis_port_linux.c"),
                    os.path.join(SDK, "src", "aegis_proto.c"), os.path.join(SDK, "src", "aegis_sha256.c"),
                    os.path.join(SDK, "src", "aegis_kmac.c"), os.path.join(SDK, "crypto", "mlkem_unit.c"),
                    os.path.join(MLDSA, "mldsa_native.c"), "-o", out], check=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def ask(port, line):
    with socket.create_connection(("127.0.0.1", port), timeout=10) as s:
        s.sendall(line.encode() + b"\n")
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
    return buf.decode().strip()


@unittest.skipUnless(shutil.which("gcc") and os.path.isdir(MLDSA) and os.path.isdir(MLKEM),
                     "needs gcc and mldsa-native / mlkem-native")
class SdkLinuxPort(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = d = tempfile.mkdtemp()
        cls.exe = os.path.join(d, "aegis_linux_prover")
        build(cls.exe)
        cls.gw_pk, cls.gw_sk = mldsa.keypair()
        with open(os.path.join(d, "gw.pub"), "w") as f:
            f.write(cls.gw_pk.hex() + "\n")
        cls.files = {}
        for name, data in (("boot.bin", b"first stage boot loader"), ("zImage", os.urandom(300001)),
                           ("board.dtb", os.urandom(4097))):
            cls.files[name] = os.path.join(d, name)
            with open(cls.files[name], "wb") as f:
                f.write(data)
        # the --measure arguments, as text for the C prover and as the Python prover's argument parser reads them
        cls.measure = ["BOOT=" + cls.files["boot.bin"], "KERNEL=%s,%s" % (cls.files["zImage"], cls.files["board.dtb"])]
        cls.groups = [(m.split("=", 1)[0], m.split("=", 1)[1].split(",")) for m in cls.measure]
        cls.state = os.path.join(d, "state")
        cls.procs = []
        cls.port, cls.fp = cls.start()
        shutil.copy(os.path.join(cls.state, "mldsa65.pub"), os.path.join(d, "ep.pub"))

    @classmethod
    def start(cls, state=None, measure=None):
        port = free_port()
        cmd = [cls.exe, "--state", state or cls.state, "--gateway-pk", os.path.join(cls.d, "gw.pub"), "--port", str(port)]
        for m in cls.measure if measure is None else measure:
            cmd += ["--measure", m]
        pr = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
        cls.procs.append(pr)
        line = pr.stdout.readline().split()
        assert line and line[0] == "AEGIS-LINUX-PROVER", line
        return port, line[-1]

    @classmethod
    def tearDownClass(cls):
        for pr in cls.procs:
            pr.kill()
            pr.wait()
            pr.stdout.close()
        shutil.rmtree(cls.d, ignore_errors=True)

    def reference(self):
        """The components the Python prover reports for the same arguments (its measure()), label -> hex digest,
        with PROVER as this prover's own executable."""
        comps = python_prover.measure(self.groups + [("PROVER", [self.exe])])
        return {c[python_prover.SWC_TYPE]: c[python_prover.SWC_VALUE].hex() for c in comps}

    def ep(self, **kw):
        e = {"name": "linux-sdk", "kind": "aegis-linux", "host": "127.0.0.1", "port": self.port, "pq_pub_file": "ep.pub",
             "heartbeat_mac": "kmac256", "profile": "aegis-linux-software-v1",
             "allowed": [{"type": t, "measurement_value": v} for t, v in self.reference().items()]}
        e.update(kw)
        return e

    def test_1_attest_software_trust_with_the_python_provers_measurements(self):
        v = fleet.attest(self.ep(), None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "software")
        self.assertEqual(v["pq_signature"], "ML-DSA-65 valid")
        self.assertEqual(list(v["measurements"]), ["BOOT", "KERNEL", "PROVER"])   # PROVER last, as the Python prover
        self.assertEqual(v["measurements"], self.reference())
        with open(self.files["zImage"], "rb") as a, open(self.files["board.dtb"], "rb") as b:
            self.assertEqual(v["measurements"]["KERNEL"], hashlib.sha256(a.read() + b.read()).hexdigest())

    def test_2_changed_file_quarantined(self):
        e = self.ep()
        with open(self.files["board.dtb"], "ab") as f:
            f.write(b"\x00")
        try:
            v = fleet.attest(e, None, self.d, timeout=10)     # the policy still holds the values from before
        finally:
            with open(self.files["board.dtb"], "rb+") as f:
                f.truncate(4097)
        self.assertFalse(v["admitted"])
        self.assertTrue(any("KERNEL" in r for r in v["reasons"]), v["reasons"])
        self.assertTrue(fleet.attest(self.ep(), None, self.d, timeout=10)["admitted"])

    def test_3_wrong_pinned_key_refused(self):
        other_pk, _ = mldsa.keypair()
        with open(os.path.join(self.d, "other.pub"), "w") as f:
            f.write(other_pk.hex())
        v = fleet.attest(self.ep(pq_pub_file="other.pub"), None, self.d, timeout=10)
        self.assertFalse(v["admitted"])
        self.assertIn("ML-DSA-65 quote signature invalid", v["reasons"])

    def test_4_bound_exchange_heartbeat_session(self):
        ep = self.ep(transcript="v2")
        v = fleet.attest(ep, None, self.d, timeout=10)
        self.assertTrue(v["admitted"], v["reasons"])
        r = fleet.provision(ep, self.d, self.gw_sk, "gid", v["measurements"], timeout=20, quote=v["quote"])
        self.assertEqual(r["transcript"], "v2")
        sid, ch = fleet.query_session(ep)
        self.assertEqual(sid, r["session_id"])
        self.assertEqual(ch, r["credential_sha3_256"])
        for n in (1, 2):
            status, ctr = fleet.heartbeat(ep, r["session_key"], timeout=10)
            self.assertEqual(ctr, n)
            self.assertRegex(status, rb"^uptime_s=\d+;link=1;fw=linux-sdk-0\.1\.0;ttl=382[345]$")
        with self.assertRaises(fleet.TranscriptRefused):      # the quote was used: it continues one exchange only
            fleet.provision(ep, self.d, self.gw_sk, "gid", {}, timeout=20, quote=v["quote"])
        self.assertEqual(fleet.query_session(ep)[0], r["session_id"])   # and the refusal left the session alone
        self.assertIsNone(fleet.provision(self.ep(), self.d, self.gw_sk, "gid", {}, timeout=20)["transcript"])

    def test_5_secrets_only_the_owner_can_read_and_the_same_key_after_a_restart(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.state).st_mode), 0o700)
        for name in ("identity.seed", "exchange.root"):
            st = os.stat(os.path.join(self.state, name))
            self.assertEqual((stat.S_IMODE(st.st_mode), st.st_size), (0o600, 32), name)
        with open(os.path.join(self.state, "identity.seed"), "rb") as a, \
                open(os.path.join(self.state, "exchange.root"), "rb") as b:
            self.assertNotEqual(a.read(), b.read())
        with open(os.path.join(self.d, "ep.pub")) as f:
            pk = f.read().strip()
        self.assertEqual(hashlib.sha256(bytes.fromhex(pk)).hexdigest()[:16], self.fp)
        port, fp = self.start()                               # a second start on the same state directory
        self.assertEqual(fp, self.fp)
        self.assertEqual(ask(port, "PQKEY").split()[2], pk)
        self.assertEqual(ask(port, "PQSESSION"), "ERR pq no-session")    # the session did not come along
        other, fp2 = self.start(state=os.path.join(self.d, "state2"))   # another device: another key
        self.assertNotEqual(fp2, self.fp)
        self.assertNotEqual(ask(other, "PQKEY").split()[2], pk)

    def test_6_a_secret_others_can_read_is_refused(self):
        state = os.path.join(self.d, "state3")
        self.start(state=state)
        os.chmod(os.path.join(state, "identity.seed"), 0o644)
        cmd = [self.exe, "--state", state, "--gateway-pk", os.path.join(self.d, "gw.pub"), "--port", str(free_port())]
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 3)
        self.assertIn("no identity key", r.stderr)

    def test_7_a_file_that_cannot_be_read_refuses_the_quote(self):
        gone = os.path.join(self.d, "gone.bin")
        with open(gone, "wb") as f:
            f.write(b"x")
        port, _ = self.start(measure=["BOOT=" + gone])
        self.assertTrue(ask(port, "PQCHAL " + "11" * 32).startswith("PQTOKEN "))
        os.unlink(gone)
        self.assertEqual(ask(port, "PQCHAL " + "11" * 32), "ERR evidence")
        self.assertEqual(ask(port, "PQKEMFIN 00 00"), "ERR cred no-exchange")
        self.assertEqual(ask(port, "X" * 20000), "ERR too-long")

    def test_8_arguments(self):
        base = [self.exe, "--state", os.path.join(self.d, "state4"), "--gateway-pk", os.path.join(self.d, "gw.pub")]
        for extra in (["--measure", "BOOT"], ["--measure", "=x"], ["--measure", "ALABELOFSIXTEENC=x"],
                      ["--measure", "A=x,,y"], ["--port", "0"], ["stray"]):
            r = subprocess.run(base + extra, capture_output=True, text=True, timeout=20)
            self.assertEqual(r.returncode, 2, extra)
        r = subprocess.run(base[:3] + ["--gateway-pk", self.files["boot.bin"]], capture_output=True, text=True, timeout=20)
        self.assertEqual(r.returncode, 2)
        self.assertFalse(os.path.exists(os.path.join(self.d, "state4")))   # nothing is made before the arguments hold


if __name__ == "__main__":
    unittest.main()
