# SPDX-License-Identifier: Apache-2.0
"""The Prover SDK as an outside device maker consumes it (docs/sdk-porting-guide.md):

  Example     sdk/examples/simulated-device/run.sh end to end against the repository's verifier: admitted with a
              session bound to its quote, a heartbeat, a changed image quarantined, the evidence pack and the audit
              log checked by the standalone checkers; with EAT in COSE_Sign1 and with the default CBOR claims.
  Packaging   the CMake build installed to a prefix and used by another CMake project through find_package, and the
              plain Makefile's install used with nothing but a compiler: the example builds against the installed
              library and headers alone, with and without AEGIS_EAT_COSE.

Needs gcc, make and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR); cmake for the
CMake case; cryptography with ML-DSA for the example, and pycose 1.1.0 with cbor2 5 for its evidence pack."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
SDK = os.path.join(ROOT, "sdk")
EXAMPLE = os.path.join(SDK, "examples", "simulated-device")
HAVE_PQ_TREES = os.path.isdir(MLDSA) and os.path.isdir(MLKEM)


def have_mldsa():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: F401
        return True
    except ImportError:
        return False


def have_pycose():
    try:
        import cbor2  # noqa: F401
        import pycose  # noqa: F401
        return True
    except ImportError:
        return False


def env():
    return dict(os.environ, PYTHON=sys.executable, MLDSA_NATIVE_DIR=MLDSA, MLKEM_NATIVE_DIR=MLKEM)


@unittest.skipUnless(HAVE_PQ_TREES and shutil.which("make") and have_mldsa(),
                     "mldsa-native / mlkem-native, make or ML-DSA in cryptography not found")
class Example(unittest.TestCase):
    def run_example(self, eat):
        d = tempfile.mkdtemp()
        try:
            r = subprocess.run([os.path.join(EXAMPLE, "run.sh"), os.path.join(d, "w")], capture_output=True,
                               text=True, timeout=600, env=dict(env(), AEGIS_EAT_COSE=eat))
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("RESULT: PASS", r.stdout)
        return r.stdout

    @unittest.skipUnless(have_pycose(), "pycose / cbor2 not installed (the standalone evidence checker)")
    def test_end_to_end_eat(self):
        out = self.run_example("1")
        self.assertRegex(out, r"ADMITTED, trust software, session bound to the quote, eat-cose-v1")
        self.assertIn("EAT, result and keys verified", out)
        self.assertRegex(out, r"changed image: quarantined +ok +\(component APP not allowed")
        self.assertRegex(out, r"audit log: tools/verify_audit.py +ok +\(\d+ entries in \d+ signed batches\)")

    @unittest.skipUnless(have_pycose(), "pycose / cbor2 not installed (the standalone audit checker)")
    def test_end_to_end_default_claims(self):
        out = self.run_example("0")
        self.assertRegex(out, r"ADMITTED, trust software, session bound to the quote, aegis claims")
        self.assertNotIn("verify_evidence", out)

    def test_refuses_a_used_work_directory(self):
        d = tempfile.mkdtemp()
        try:
            open(os.path.join(d, "x"), "w").close()
            r = subprocess.run([os.path.join(EXAMPLE, "run.sh"), d], capture_output=True, text=True, env=env())
        finally:
            shutil.rmtree(d, ignore_errors=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("not empty", r.stderr)


CONSUMER_CMAKE = """cmake_minimum_required(VERSION 3.16)
project(consumer C)
find_package(aegis_sdk 1.0 REQUIRED)
if(NOT AEGIS_SDK_API_VERSION EQUAL 1)
  message(FATAL_ERROR "API version ${AEGIS_SDK_API_VERSION}")
endif()
add_executable(device %s)
target_compile_definitions(device PRIVATE _GNU_SOURCE)
target_link_libraries(device PRIVATE aegis::sdk)
"""


@unittest.skipUnless(HAVE_PQ_TREES and shutil.which("make") and shutil.which("gcc"),
                     "mldsa-native / mlkem-native, make or gcc not found")
class Packaging(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.d, ignore_errors=True)

    def run_ok(self, cmd, **kw):
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=600, env=env(), **kw)
        self.assertEqual(r.returncode, 0, " ".join(cmd) + "\n" + r.stdout[-3000:] + r.stderr[-3000:])
        return r

    def check_device_runs(self, exe):
        """The installed-only build starts: it reads a key, derives its identity, listens and says READY."""
        pub, sec, img = (os.path.join(self.d, n) for n in ("v.pub", "s.hex", "fw.bin"))
        with open(pub, "w") as f:
            f.write("ab" * 1952)
        with open(sec, "w") as f:
            f.write(os.urandom(32).hex())
        with open(img, "wb") as f:
            f.write(b"firmware")
        pr = subprocess.Popen([exe, "--verifier-pk", pub, "--secret", sec, "--image", "APP=" + img],
                              stdout=subprocess.PIPE, text=True)
        try:
            line = pr.stdout.readline().split()
        finally:
            pr.terminate()
            pr.wait(10)
            pr.stdout.close()
        self.assertEqual(line[0], "READY", line)
        self.assertEqual(len(line[2]), 64)
        self.assertEqual(pr.returncode, 0)   # SIGTERM ends it cleanly

    def test_makefile_install_and_plain_compiler(self):
        for eat in ("0", "1"):
            with self.subTest(AEGIS_EAT_COSE=eat):
                build, prefix = os.path.join(self.d, "b" + eat), os.path.join(self.d, "p" + eat)
                self.run_ok(["make", "-C", SDK, "-s", "BUILD=" + build, "AEGIS_EAT_COSE=" + eat, "PREFIX=" + prefix,
                             "lib", "install"])
                self.assertEqual(sorted(os.listdir(os.path.join(prefix, "include", "aegis"))),
                                 ["aegis_sdk.h", "aegis_sha256.h"])
                exe = os.path.join(self.d, "dev" + eat)
                defs = ["-DAEGIS_EAT_COSE=1"] if eat == "1" else []
                self.run_ok(["gcc", "-std=c11", "-D_GNU_SOURCE", "-Wall", "-Wextra", "-Werror", *defs,
                             "-I", os.path.join(prefix, "include", "aegis"), os.path.join(EXAMPLE, "sim_device.c"),
                             os.path.join(prefix, "lib", "libaegis_sdk.a"), "-o", exe])
                if eat == "1":
                    nm = self.run_ok(["nm", os.path.join(prefix, "lib", "libaegis_sdk.a")]).stdout
                    self.assertIn(" T aegis_prover_quote_eat", nm)
                self.check_device_runs(exe)

    @unittest.skipUnless(shutil.which("cmake"), "cmake not found")
    def test_cmake_install_and_find_package(self):
        build, prefix = os.path.join(self.d, "build"), os.path.join(self.d, "prefix")
        self.run_ok(["cmake", "-S", SDK, "-B", build, "-DMLDSA_NATIVE_DIR=" + MLDSA, "-DMLKEM_NATIVE_DIR=" + MLKEM,
                     "-DCMAKE_BUILD_TYPE=Release"])
        self.run_ok(["cmake", "--build", build, "-j", "4"])
        for exe in ("aegis_host_prover", "aegis_linux_prover", "aegis_sim_device"):
            self.assertTrue(os.access(os.path.join(build, exe), os.X_OK), exe)
        self.run_ok(["cmake", "--install", build, "--prefix", prefix])
        consumer = os.path.join(self.d, "consumer")
        os.makedirs(consumer)
        with open(os.path.join(consumer, "CMakeLists.txt"), "w") as f:
            f.write(CONSUMER_CMAKE % os.path.join(EXAMPLE, "sim_device.c"))
        cb = os.path.join(self.d, "consumer-build")
        self.run_ok(["cmake", "-S", consumer, "-B", cb, "-DCMAKE_PREFIX_PATH=" + prefix])
        self.run_ok(["cmake", "--build", cb])
        self.check_device_runs(os.path.join(cb, "device"))


if __name__ == "__main__":
    unittest.main()
