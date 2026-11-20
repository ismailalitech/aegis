# SPDX-License-Identifier: Apache-2.0
"""The Prover SDK's core (sdk/src/aegis_proto.c) answers as the two implementations it replaced, byte for byte, and
the shared fuzz corpus passes the shared harness's checks.

Before the SDK the protocol existed twice: in the STM32H573 partition (the image on the boards, SPE 3183f74a) and in
the RW612 prover's aegis_proto.c (also the ZynqMP TA's). tools/sdk_golden.py ran every seed of the two fuzz harnesses
through that code (commit eb82532), with a deterministic random generator, and recorded a hash of everything it
answered: every status, token, key, signature, tag and heartbeat (vectors/sdk-golden/*.json; two traces of each kind
are there as text). Here the same seeds go through today's code:
  - the STM32 partition, now the SDK's port of that chip on the core (tests/fuzz/stm32/fuzz_stm32_partition.c),
  - the line protocol on the core through the reference port (tests/fuzz/fuzz_sdk_core.c, first input format),
and every hash must be the recorded one. Needs no git history; "tools/sdk_golden.py record" makes the files again
from the old commit, and "tools/sdk_golden.py diff" compares old and new over a whole fuzz corpus.

The rest is about the corpus all families share (tests/fuzz/seeds): every file passes the shared harness's model
(fuzz_sdk_core.c says what it checks), the stm32-* files are that family's seeds under its configuration
(tests/fuzz/merge_seeds.py), and two control builds show that the model would notice a device whose keys are not new
after a reset (-DFZ_STALE_RNG) and one whose quote outlives a reset (-DFZ_QUOTE_OUTLIVES_RESET).
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import glob
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import sdk_golden  # noqa: E402

SEEDS = os.path.join(ROOT, "tests", "fuzz", "seeds")
STM32_SEEDS = os.path.join(ROOT, "tests", "fuzz", "stm32", "seeds")


@unittest.skipUnless(sdk_golden.available(), "needs gcc and mldsa-native / mlkem-native")
class SdkGolden(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def golden(self, kind, at_least):
        n, bad = sdk_golden.check(kind, self.d)
        self.assertGreaterEqual(n, at_least)
        self.assertEqual(bad, [])

    def test_stm32_partition_answers_as_before_the_sdk(self):
        self.golden("stm32", 30)

    def test_line_protocol_answers_as_before_the_sdk(self):
        self.golden("line", 18)

    def run_seed(self, exe, name):
        return subprocess.run([exe, os.path.join(SEEDS, name)], capture_output=True, text=True)

    def test_every_shared_seed_passes(self):
        exe = sdk_golden.build_new("line", self.d)
        seeds = sorted(os.path.basename(p) for p in glob.glob(os.path.join(SEEDS, "*")))
        for name in ("transcript-bound-exchange", "stm32-transcript-bound-exchange", "stm32-reset-and-replay",
                     "sdk-platform-key-binary", "sdk-line-250hz", "sdk-rng-zero-line", "sdk-work-buffer-limit-line"):
            self.assertIn(name, seeds)
        for name in seeds:
            r = self.run_seed(exe, name)
            self.assertEqual((r.returncode, r.stdout.strip().splitlines()[-1:]), (0, ["1 inputs, no finding"]),
                             name + ": " + r.stderr)

    def test_the_corpus_holds_every_stm32_seed_under_that_familys_configuration(self):
        names = sorted(os.path.basename(p) for p in glob.glob(os.path.join(STM32_SEEDS, "*")))
        self.assertEqual(names, sorted(os.path.basename(p)[6:] for p in glob.glob(os.path.join(SEEDS, "stm32-*"))))
        for name in names:
            with open(os.path.join(STM32_SEEDS, name), "rb") as a, open(os.path.join(SEEDS, "stm32-" + name), "rb") as b:
                self.assertEqual(b"AEG\x01\x5f" + a.read(), b.read(), name)

    def test_replay_after_reset_is_caught_when_the_key_is_not_new(self):
        exe = sdk_golden.build_new("line", self.d, ["-DFZ_STALE_RNG"], "line-stale-rng")
        for name in ("stm32-reset-and-replay", "stm32-reset-and-replay-second-exchange", "sdk-reset-replay-line"):
            r = self.run_seed(exe, name)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertRegex(r.stderr, r"ORACLE: the KEM key of exchange \d+ was issued again", name)

    def test_swap_after_reset_is_caught_when_the_quote_outlives_the_reset(self):
        exe = sdk_golden.build_new("line", self.d, ["-DFZ_QUOTE_OUTLIVES_RESET"], "line-quote-outlives-reset")
        for name in ("stm32-transcript-swap-after-reset", "sdk-reset-replay-line"):
            r = self.run_seed(exe, name)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn("ORACLE: quote kept: device 1, model 0", r.stderr, name)
        self.assertEqual(self.run_seed(exe, "transcript-bound-exchange").returncode, 0)


if __name__ == "__main__":
    unittest.main()
