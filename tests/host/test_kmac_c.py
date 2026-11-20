# SPDX-License-Identifier: Apache-2.0
"""The partition's C KMAC256 (sdk/src/aegis_kmac.c), built for the PC, against
NIST's KMAC256 samples and against common/kmac.py on random inputs. Skipped without gcc."""
import os, random, shutil, subprocess, sys, tempfile, unittest
HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
PART = os.path.join(ROOT, "sdk", "src")
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, HERE)
import kmac
from test_kmac import NIST


@unittest.skipUnless(shutil.which("gcc"), "needs gcc")
class CKmac(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.exe = os.path.join(cls.tmp, "kmac")
        subprocess.run(["gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-I", PART, os.path.join(PART, "aegis_kmac.c"),
                        os.path.join(ROOT, "sdk", "tests", "kmac_host_check.c"), "-o", cls.exe], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def c(self, key, data, custom, n):
        return subprocess.run([self.exe, key.hex(), data.hex(), custom.hex(), str(n)], check=True,
                              capture_output=True, text=True).stdout.strip()

    def test_nist_kmac256_samples(self):
        for name, alg, key, data, custom, out in NIST:
            if alg == "kmac256":
                self.assertEqual(self.c(bytes.fromhex(key), bytes.fromhex(data), custom.encode(), len(out) // 2), out, name)

    def test_random_against_python(self):
        rnd = random.Random(17)
        for i in range(150):
            key = rnd.randbytes(rnd.choice([0, 1, 32, 135, 136, 137, 300]))
            data = rnd.randbytes(rnd.choice([0, 1, 135, 136, 137, 272, rnd.randrange(0, 700)]))
            custom = rnd.randbytes(rnd.choice([0, 11, 120, 140]))
            n = rnd.choice([1, 32, 64, 136, 137, 300])
            self.assertEqual(self.c(key, data, custom, n), kmac.kmac256(key, data, n, custom).hex(), i)

    def test_heartbeat_shape(self):
        key = bytes(range(32)); x = bytes(range(32)) + (5).to_bytes(8, "little") + b"uptime_s=81;link=1;fw=0.4.0"
        self.assertEqual(self.c(key, x, b"aegis-hb-v2", 32), kmac.kmac256(key, x, 32, b"aegis-hb-v2").hex())


if __name__ == "__main__":
    unittest.main()
