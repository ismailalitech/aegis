"""The STM32H573 secure partition (endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c, the file TF-M builds),
on the PC against the stand-ins and the model of tests/fuzz/stm32/fuzz_stm32_partition.c, without libFuzzer: every
seed of tests/fuzz/stm32/seeds must pass the harness's checks.

Among them the replay after a reset: someone records a KEM_INIT and the gateway's KEM_FINISH, resets the board and
sends both again. The partition must issue another ML-KEM key (32 bytes from the random number generator go into
each one), so the recorded KEM_FINISH is refused and no session comes back. To show that the seeds would catch a
partition whose keys are not new, the harness is also built with a generator that starts again at every reset
(-DFZ_STALE_RNG): the same seeds must then fail.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import glob
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
PART = os.path.join(ROOT, "endpoints", "stm32h573", "tfm-aegis-partition")
FUZZ = os.path.join(ROOT, "tests", "fuzz", "stm32")
SEEDS = os.path.join(FUZZ, "seeds")
REPLAY = ("reset-and-replay", "reset-and-replay-second-exchange")


def gcc(*args):
    subprocess.run(["gcc", "-O2", "-D_GNU_SOURCE", '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"',
                    "-I", PART, "-I", os.path.join(PART, "mldsa"), "-I", MLDSA, "-I", os.path.join(PART, "mlkem"),
                    "-I", MLKEM] + list(args), check=True)


@unittest.skipUnless(shutil.which("gcc") and os.path.isdir(MLDSA) and os.path.isdir(MLKEM),
                     "needs gcc and mldsa-native / mlkem-native")
class Stm32Partition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = d = tempfile.mkdtemp()
        objs = [os.path.join(d, n) for n in ("kmac.o", "mlkem.o", "mldsa.o")]
        for src, obj in zip((os.path.join(PART, "aegis_kmac.c"), os.path.join(PART, "mlkem_unit.c"),
                             os.path.join(MLDSA, "mldsa_native.c")), objs):
            gcc("-c", src, "-o", obj)
        # the partition pins a test gateway key whose secret key the harness holds
        gcc(os.path.join(FUZZ, "gen_gw_pk.c"), objs[2], "-o", os.path.join(d, "gen_gw_pk"))
        with open(os.path.join(d, "fz_gateway_pk.h"), "w") as f:
            subprocess.run([os.path.join(d, "gen_gw_pk")], check=True, stdout=f)
        cls.exe, cls.stale = os.path.join(d, "partition"), os.path.join(d, "partition-stale-rng")
        for exe, extra in ((cls.exe, []), (cls.stale, ["-DFZ_STALE_RNG"])):
            gcc("-Wall", "-Wextra", "-Werror", "-Wno-unused-parameter", "-DFZ_STANDALONE",
                '-DAEGIS_GATEWAY_PK_HEADER="fz_gateway_pk.h"', "-I", d, "-I", os.path.join(FUZZ, "stub"), *extra,
                os.path.join(FUZZ, "fuzz_stm32_partition.c"), *objs, "-o", exe)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def run_seed(self, exe, name):
        return subprocess.run([exe, os.path.join(SEEDS, name)], capture_output=True, text=True)

    def test_every_seed_passes(self):
        seeds = sorted(os.path.basename(p) for p in glob.glob(os.path.join(SEEDS, "*")))
        for name in REPLAY + ("rng-fails-at-kem-key", "rng-fails-at-kem-sign", "rng-zeros-at-kem-key"):
            self.assertIn(name, seeds)
        for name in seeds:
            r = self.run_seed(self.exe, name)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "1 inputs, no finding"), name + ": " + r.stderr)

    def test_replay_after_reset_is_caught_when_the_key_is_not_new(self):
        for name in REPLAY:
            r = self.run_seed(self.stale, name)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn("ORACLE: the KEM key of exchange 1 was issued again", r.stderr, name)


if __name__ == "__main__":
    unittest.main()
