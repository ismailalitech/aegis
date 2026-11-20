# SPDX-License-Identifier: Apache-2.0
"""Hedged ML-DSA-65 signing on the endpoint verifies with the gateway's liboqs, and is not repeatable.

Builds sdk/tests/mldsa_host_check_hedged.c with the partition's own
ML-DSA configuration (mldsa-native v2.0.0) on the PC. Skipped when gcc or mldsa-native is missing
(for example in CI, which does not fetch mldsa-native).
"""
import os, shutil, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "common"))
PART = os.path.join(ROOT, "sdk", "crypto", "mldsa")
NATIVE = os.environ.get("MLDSA_NATIVE_DIR", os.path.expanduser("~/aegis-tools/mldsa-native/mldsa"))


@unittest.skipUnless(shutil.which("gcc") and os.path.isfile(os.path.join(NATIVE, "mldsa_native.c")),
                     "needs gcc and mldsa-native")
class HedgedSigning(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import mldsa
        cls.mldsa = mldsa
        cls.tmp = tempfile.mkdtemp()
        exe = os.path.join(cls.tmp, "hedged")
        subprocess.run(["gcc", "-O1", '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"', "-I", PART, "-I", NATIVE,
                        os.path.join(ROOT, "sdk", "tests", "mldsa_host_check_hedged.c"), os.path.join(NATIVE, "mldsa_native.c"),
                        "-o", exe], check=True, capture_output=True)
        out = subprocess.run([exe], check=True, capture_output=True, text=True).stdout
        cls.rec = dict(line.split(" ", 1) for line in out.strip().splitlines())

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_both_signatures_verify_with_liboqs(self):
        pk = bytes.fromhex(self.rec["pk"])
        for k in ("sig1", "sig2"):
            self.assertTrue(self.mldsa.verify(pk, b"aegis-endpoint-quote-v1", self.rec["msg"].encode(),
                                              bytes.fromhex(self.rec[k])), k)

    def test_signatures_differ(self):
        self.assertNotEqual(self.rec["sig1"], self.rec["sig2"])

    def test_wrong_message_is_refused(self):
        pk = bytes.fromhex(self.rec["pk"])
        self.assertFalse(self.mldsa.verify(pk, b"aegis-endpoint-quote-v1", b"another message",
                                           bytes.fromhex(self.rec["sig1"])))


if __name__ == "__main__":
    unittest.main()
