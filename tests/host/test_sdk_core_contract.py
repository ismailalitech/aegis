# SPDX-License-Identifier: Apache-2.0
"""The Prover SDK core's contracts at their exact boundaries (sdk/tests/core_contract_check.c says which): inputs
read once whatever happens to the caller's memory, the credential body against the work buffer, the length the
platform reports for its evidence, a heartbeat status buffer one byte short, a random generator that repeats, zero
secrets at start, measurements without a label or a terminator, files the PC port cannot hash whole.

The check program is built twice: with AddressSanitizer and UndefinedBehaviorSanitizer, and plain with -O2, where a
write past a buffer shows in the bytes the program keeps behind each one. Both must pass.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
SDK = os.path.join(ROOT, "sdk")
TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
SAN = ["-fsanitize=address,undefined", "-fno-sanitize-recover=undefined"]


def build(out, flags, core_dir=None):
    """core_dir: a directory with another aegis_proto.c to check instead (a changed copy, to see the checks fire)."""
    inc = [core_dir] if core_dir else []
    inc += [os.path.join(SDK, "include"), os.path.join(SDK, "src"), os.path.join(SDK, "ports", "host"),
            os.path.join(SDK, "crypto", "mldsa"), MLDSA, os.path.join(SDK, "crypto", "mlkem"), MLKEM]
    cmd = ["gcc", "-g", "-D_GNU_SOURCE", '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"', "-Wall", "-Wextra", "-Werror",
           "-Wno-unused-parameter", "-Wno-unused-function"] + flags
    for i in inc:
        cmd += ["-I", i]
    cmd += [os.path.join(SDK, "tests", "core_contract_check.c"), os.path.join(SDK, "ports", "host", "aegis_port_host.c"),
            os.path.join(SDK, "src", "aegis_sha256.c"), os.path.join(SDK, "src", "aegis_kmac.c"),
            os.path.join(SDK, "crypto", "mlkem_unit.c"), os.path.join(MLDSA, "mldsa_native.c"), "-o", out]
    subprocess.run(cmd, check=True)


@unittest.skipUnless(shutil.which("gcc") and os.path.isdir(MLDSA) and os.path.isdir(MLKEM),
                     "needs gcc and mldsa-native / mlkem-native")
class SdkCoreContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def run_check(self, name, flags):
        exe, files = os.path.join(self.d, name), os.path.join(self.d, name + "-files")
        os.mkdir(files)
        build(exe, flags)
        r = subprocess.run([exe, files], capture_output=True, text=True, timeout=300)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertRegex(r.stdout, r"core contract: \d+ checks, 0 failed")

    def test_with_sanitizers(self):
        self.run_check("check-asan", ["-O1"] + SAN)

    def test_plain(self):
        self.run_check("check-plain", ["-O2"])


if __name__ == "__main__":
    unittest.main()
