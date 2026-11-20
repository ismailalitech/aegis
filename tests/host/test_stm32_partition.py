"""The STM32H573 secure partition (endpoints/stm32h573/tfm-aegis-partition/aegis_pq_attest.c with the Prover SDK's
core, sdk/src/aegis_proto.c: the files TF-M builds), on the PC against the stand-ins and the model of tests/fuzz/stm32/fuzz_stm32_partition.c, without libFuzzer: every
seed of tests/fuzz/stm32/seeds must pass the harness's checks.

Among them the replay after a reset: someone records a KEM_INIT and the gateway's KEM_FINISH, resets the board and
sends both again. The partition must issue another ML-KEM key (32 bytes from the random number generator go into
each one), so the recorded KEM_FINISH is refused and no session comes back. To show that the seeds would catch a
partition whose keys are not new, the harness is also built with a generator that starts again at every reset
(-DFZ_STALE_RNG): the same seeds must then fail.

One transcript (docs/architecture.md): the transcript seeds run with the others, and two more checks belong to it.
The harness's "--transcript" mode runs one exchange that continues a quote and hands everything a verifier sees to
this test, which checks it with the gateway's code (common/transcript.py, fleet.py's labels) instead of the harness's
own model: the KEM key's signature, the credential the partition accepts, the confirmation tag and the session id.
And a control build whose quote outlives a reset (-DFZ_QUOTE_OUTLIVES_RESET) must fail the swap seed: there the quote
is of one boot and the exchange of the next.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import glob
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, os.path.join(ROOT, "gateway", "aegisd"))
import fleet  # noqa: E402
import mldsa  # noqa: E402
import transcript  # noqa: E402
TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
PART = os.path.join(ROOT, "endpoints", "stm32h573", "tfm-aegis-partition")
FUZZ = os.path.join(ROOT, "tests", "fuzz", "stm32")
SEEDS = os.path.join(FUZZ, "seeds")
REPLAY = ("reset-and-replay", "reset-and-replay-second-exchange")
SWAP = "transcript-swap-after-reset"
PSA_ERROR_INVALID_SIGNATURE = -149


SDK = os.path.join(ROOT, "sdk")


def gcc(*args):
    subprocess.run(["gcc", "-O2", "-D_GNU_SOURCE", '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"',
                    "-I", PART, "-I", os.path.join(SDK, "include"), "-I", os.path.join(SDK, "src"),
                    "-I", os.path.join(SDK, "crypto", "mldsa"), "-I", MLDSA, "-I", os.path.join(SDK, "crypto", "mlkem"),
                    "-I", MLKEM] + list(args), check=True)


@unittest.skipUnless(shutil.which("gcc") and os.path.isdir(MLDSA) and os.path.isdir(MLKEM),
                     "needs gcc and mldsa-native / mlkem-native")
class Stm32Partition(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = d = tempfile.mkdtemp()
        objs = [os.path.join(d, n) for n in ("kmac.o", "mlkem.o", "mldsa.o", "sha256.o")]
        for src, obj in zip((os.path.join(SDK, "src", "aegis_kmac.c"), os.path.join(SDK, "crypto", "mlkem_unit.c"),
                             os.path.join(MLDSA, "mldsa_native.c"), os.path.join(SDK, "src", "aegis_sha256.c")), objs):
            gcc("-c", src, "-o", obj)
        # the partition pins a test gateway key whose secret key the harness holds
        gcc(os.path.join(FUZZ, "gen_gw_pk.c"), objs[2], "-o", os.path.join(d, "gen_gw_pk"))
        with open(os.path.join(d, "fz_gateway_pk.h"), "w") as f:
            subprocess.run([os.path.join(d, "gen_gw_pk")], check=True, stdout=f)
        cls.exe, cls.stale = os.path.join(d, "partition"), os.path.join(d, "partition-stale-rng")
        cls.keeps_quote = os.path.join(d, "partition-quote-outlives-reset")
        for exe, extra in ((cls.exe, []), (cls.stale, ["-DFZ_STALE_RNG"]),
                           (cls.keeps_quote, ["-DFZ_QUOTE_OUTLIVES_RESET"])):
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
        for name in REPLAY + ("rng-fails-at-kem-key", "rng-fails-at-kem-sign", "rng-zeros-at-kem-key", SWAP,
                              "transcript-bound-exchange", "transcript-credential-without-it",
                              "transcript-quote-used-once", "transcript-other-quote-in-between",
                              "transcript-unbound-in-between", "transcript-refused-steps", "transcript-raw-messages"):
            self.assertIn(name, seeds)
        for name in seeds:
            r = self.run_seed(self.exe, name)
            self.assertEqual((r.returncode, r.stdout.strip()), (0, "1 inputs, no finding"), name + ": " + r.stderr)

    def test_replay_after_reset_is_caught_when_the_key_is_not_new(self):
        for name in REPLAY:
            r = self.run_seed(self.stale, name)
            self.assertNotEqual(r.returncode, 0, name)
            self.assertIn("ORACLE: the KEM key of exchange 1 was issued again", r.stderr, name)

    def test_swap_after_reset_is_caught_when_the_quote_outlives_the_reset(self):
        """The seeds would notice a partition that continued, after a reset, a quote signed before it."""
        r = self.run_seed(self.keeps_quote, SWAP)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("ORACLE: the KEM key of an exchange that continues no quote is not signed as the first version's",
                      r.stderr)
        self.assertEqual(self.run_seed(self.keeps_quote, "transcript-bound-exchange").returncode, 0)

    def exchange(self, t2_of):
        """One exchange that continues a quote (the harness's --transcript mode); t2_of gives the T2 the gateway's
        credential names, from the T2 this side computed."""
        pr = subprocess.Popen([self.exe, "--transcript"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        v = {}
        try:
            while "kem_sig" not in v:
                name, _, value = pr.stdout.readline().strip().partition("=")
                self.assertTrue(name, "the harness stopped early")
                v[name] = bytes.fromhex(value)
            t1 = transcript.quote(v["challenge"], transcript.token_hash(v["token"]))
            v["t2"] = transcript.kem_init(t1, v["ek"])
            out, _ = pr.communicate(t2_of(v["t2"]).hex() + "\n", timeout=60)
        finally:
            pr.kill()
        for line in out.splitlines():
            name, _, value = line.partition("=")
            v[name] = int(value) if name in ("finish", "session_status") else bytes.fromhex(value)
        return v

    def test_transcript_is_the_one_the_gateway_computes(self):
        v = self.exchange(lambda t2: t2)
        self.assertTrue(mldsa.verify(v["pk"], fleet.PQ_LABEL, v["token"], v["quote_sig"]))
        self.assertIn(v["challenge"], v["token"])
        # the KEM key is signed over T2 with the transcript's label, and not as the first version's
        self.assertTrue(mldsa.verify(v["pk"], transcript.KEM_INIT_LABEL, v["t2"], v["kem_sig"]))
        self.assertFalse(mldsa.verify(v["pk"], fleet.KEM_INIT_LABEL, v["challenge"] + v["ek"], v["kem_sig"]))
        self.assertFalse(mldsa.verify(v["pk"], fleet.KEM_INIT_LABEL, v["t2"], v["kem_sig"]))
        # the partition accepted a credential naming the T2 computed here, and its tag and session are T3's
        self.assertEqual(v["finish"], 0)
        t3 = transcript.kem_fin(v["t2"], v["ct"], v["cred"])
        self.assertEqual(v["tag"], transcript.confirm_tag(v["k"], t3))
        self.assertNotEqual(v["tag"], fleet._sha3(b"aegis-confirm-v1", v["k"], v["challenge"], fleet._sha3(v["ct"]),
                                                  fleet._sha3(v["cred"])))
        self.assertEqual(v["session_status"], 0)
        session = transcript.session_key(v["k"], t3)
        self.assertEqual(v["session"], hashlib.sha3_256(b"aegis-session-id-v1" + session).digest() + fleet._sha3(v["cred"]))

    def test_credential_for_another_transcript_is_refused(self):
        for other in (lambda t2: bytes(32), lambda t2: t2[:-1] + bytes([t2[-1] ^ 1])):
            v = self.exchange(other)
            self.assertEqual(v["finish"], PSA_ERROR_INVALID_SIGNATURE)
            self.assertEqual(v["tag"], b"")
            self.assertNotEqual(v["session_status"], 0)


if __name__ == "__main__":
    unittest.main()
