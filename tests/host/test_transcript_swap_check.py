# SPDX-License-Identifier: Apache-2.0
"""tests/board/transcript_swap_check.py, the transcript check for the boards, run on the PC.

Against the RW612 prover's protocol code (endpoints/rw612/prover/src/aegis_proto.c, built by test_rw612_proto.py's
recipe), where a reset is the program started again with the same device secrets, and a swap is the program started
again with the same secrets and another image to measure:
  - live passes on the running image;
  - swap stops (exit 2) when there was no reset;
  - after a reset of the same image, the recorded quote cannot be continued until this boot has signed it again,
    which it can, byte for byte, because it reports what was appraised;
  - after a swap to another image with the same key, it cannot be continued at all.
Against the simulated device of test_transcript.py, for what no real image does:
  - an image from before the transcript: live stops with exit 3, the gateway having refused the exchange; a quote
    recorded from it, or a swap to it, ends without a session;
  - an endpoint whose quote outlives a reset fails the check (S1), so the check would notice one.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR) for the first part."""
import hashlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "common"))
sys.path.insert(0, HERE)
import mldsa  # noqa: E402
import test_rw612_proto as rw  # noqa: E402
import test_transcript as tt  # noqa: E402

CHECK = os.path.join(ROOT, "tests", "board", "transcript_swap_check.py")
NAME = "pc-endpoint"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = d = tempfile.mkdtemp()
        cls.gw_pk, gw_sk = mldsa.keypair()
        with open(os.path.join(d, "gw.pub"), "w") as f:
            f.write(cls.gw_pk.hex())
        with open(os.path.join(d, "identity.sk"), "wb") as f:      # the gateway's state, as fleet.py reads it
            f.write(gw_sk)
        with open(os.path.join(d, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "test gateway"}}, f)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.d, ignore_errors=True)

    def check(self, phase, tag):
        r = subprocess.run([sys.executable, CHECK, phase, os.path.join(self.d, "policy-%s.json" % tag), NAME,
                            "--file", os.path.join(self.d, "quote-%s.json" % tag), "--state", self.d, "--wait", "10"],
                           capture_output=True, text=True)
        self.assertIn(r.returncode, (0, 1, 2, 3), r.stderr)
        return r.returncode, json.loads(r.stdout)

    def policy(self, tag, entry):
        with open(os.path.join(self.d, "policy-%s.json" % tag), "w") as f:
            json.dump({"endpoints": [dict(entry, name=NAME)]}, f)


@unittest.skipUnless(shutil.which("gcc") and os.path.isdir(rw.MLDSA) and os.path.isdir(rw.MLKEM),
                     "needs gcc and mldsa-native / mlkem-native")
class OnTheProtocolCode(Base):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.exe = os.path.join(cls.d, "aegis_rw612_host")
        rw.build(cls.exe)
        cls.images = [os.path.join(cls.d, "image-a.bin"), os.path.join(cls.d, "image-b.bin")]
        for path in cls.images:
            with open(path, "wb") as f:
                f.write(os.urandom(4096))
        cls.secrets = [os.urandom(32).hex(), os.urandom(32).hex()]  # the device's seed and provisioning root
        cls.proc = None

    @classmethod
    def tearDownClass(cls):
        cls.stop()
        super().tearDownClass()

    @classmethod
    def stop(cls):
        if cls.proc:
            cls.proc.kill()
            cls.proc.wait()
            cls.proc.stdout.close()
            cls.proc = None

    def boot(self, port, image=0):
        """Start the endpoint, or start it again: the same keys, nothing else kept; the image it measures."""
        self.stop()
        cmd = [self.exe, str(port)] + self.secrets + [os.path.join(self.d, "gw.pub"), self.images[image]]
        type(self).proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True)
        self.assertEqual(self.proc.stdout.readline().split()[0], "READY")

    def enrol(self):
        port = rw.free_port()
        self.boot(port)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"PQKEY\n")
            reply = b""
            while not reply.endswith(b"\r\n"):
                reply += s.recv(65536)
        with open(os.path.join(self.d, "ep-%d.pub" % port), "w") as f:
            f.write(reply.split()[2].decode())
        with open(self.images[0], "rb") as f:
            good = hashlib.sha256(f.read()).hexdigest()
        self.policy(port, {"kind": "aegis-device", "host": "127.0.0.1", "port": port, "pq_pub_file": "ep-%d.pub" % port,
                           "heartbeat_mac": "kmac256", "profile": "aegis-rw612-els-v1",
                           "allowed": [{"type": "APP", "measurement_value": good}]})
        return port, good

    def test_live(self):
        port, _ = self.enrol()
        rc, res = self.check("live", port)
        self.assertEqual(rc, 0, res)
        self.assertTrue(res["image_knows_the_transcript"])
        self.assertTrue(res["L1_bound_exchange"].startswith("accepted, session "), res)
        self.assertTrue(res["L1_endpoint_reports_the_same_session"] and res["L2_session_kept"] and res["L4_session_kept"])
        for key in ("L2_same_quote_again", "L3_older_quote"):
            self.assertTrue(res[key].startswith("refused: ") and "the endpoint answered the unbound exchange" in res[key])
        self.assertTrue(res["L3_newer_quote"].startswith("accepted"), res)
        self.assertEqual((res["L4_credential_without_the_transcript"], res["L4_credential_for_another_transcript"]),
                         ("ERR cred other-transcript",) * 2)
        self.assertTrue(res["L5_entry_without_transcript"].startswith("first version's exchange accepted"), res)
        self.assertTrue(res["L6_last_cycle"].startswith("accepted, session "), res)

    def test_reset_of_the_same_image(self):
        port, good = self.enrol()
        rc, rec = self.check("quote", port)
        self.assertEqual(rc, 0, rec)
        self.assertEqual(rec["measurements"], {"APP": good})
        with open(os.path.join(self.d, "quote-%d.json" % port)) as f:
            self.assertEqual(sorted(json.load(f)),
                             ["challenge", "endpoint", "measurements", "recorded_at", "token_sha3_256"])
        rc, res = self.check("swap", port)                   # no reset yet
        self.assertEqual(rc, 2, res)
        self.assertIn("S0_reset", res)
        self.boot(port)
        rc, res = self.check("swap", port)
        self.assertEqual(rc, 0, res)
        self.assertEqual(res["S0_session_after_reset"], "ERR pq no-session")
        # S1: nothing in this boot's RAM to continue
        self.assertIn("the endpoint answered the unbound exchange", res["S1_recorded_quote_continued"])
        self.assertEqual((res["S1_credential_sent"], res["S1_session"]), (False, "ERR pq no-session"))
        # S2: the same image signs the same claims for the same challenge, and may then continue them
        self.assertTrue(res["S2_quote_for_the_recorded_challenge"].startswith("the recorded quote, byte for byte"), res)
        self.assertEqual((res["S2_measurements_now"], res["S2_admitted_now"]), ({"APP": good}, True))
        self.assertTrue(res["S2_recorded_quote_continued"].startswith("accepted: this boot signed the recorded quote"))
        self.assertTrue(res["S3_new_cycle"].startswith("accepted, session "), res)

    def test_swap_to_another_image_with_the_same_key(self):
        port, good = self.enrol()
        rc, rec = self.check("quote", port)
        self.assertEqual(rc, 0, rec)
        self.boot(port, image=1)                             # the same secrets: the same key; another image
        rc, res = self.check("swap", port)
        self.assertEqual(rc, 0, res)
        self.assertIn("the endpoint answered the unbound exchange", res["S1_recorded_quote_continued"])
        self.assertEqual((res["S1_credential_sent"], res["S1_session"]), (False, "ERR pq no-session"))
        self.assertTrue(res["S2_quote_for_the_recorded_challenge"].startswith("another quote ("), res)
        self.assertNotEqual(res["S2_measurements_now"], {"APP": good})
        self.assertEqual(res["recorded_measurements"], {"APP": good})
        self.assertEqual(res["S2_recorded_quote_continued"],
                         "refused: ML-KEM key not signed over the transcript of the quote just appraised")
        # what runs now is not what the policy admits: no exchange at all
        self.assertTrue(res["S2_admitted_now"][0].startswith("component APP not allowed"), res)
        self.assertTrue(res["S3_new_cycle"].startswith("refused: not admitted by the policy, so no exchange"), res)
        self.assertEqual(rw.fleet._exchange("127.0.0.1", port, "PQSESSION", 10).strip(), "ERR pq no-session")
        # and the check itself does not start on an endpoint the policy does not admit
        rc, res = self.check("live", port)
        self.assertEqual(rc, 2, res)
        self.assertTrue(res["not_admitted"][0].startswith("component APP not allowed"), res)


class OnTheSimulatedDevice(Base):
    """One key, the images of test_transcript.py."""

    def setUp(self):
        self.dev = tt.Device(self.gw_pk)
        with open(os.path.join(self.d, "dev-%d.pub" % self.dev.port), "w") as f:
            f.write(self.dev.pk.hex())
        self.policy(self.dev.port, {"kind": "aegis-pq", "host": "127.0.0.1", "port": self.dev.port,
                                    "pq_pub_file": "dev-%d.pub" % self.dev.port,
                                    "allowed": [{"type": "SPE", "measurement_value": tt.GOOD_S},
                                                {"type": "NSPE", "measurement_value": tt.GOOD_NS}]})

    def test_image_from_before_the_transcript(self):
        self.dev.boot(tt.FW_A_OLD)
        rc, res = self.check("live", self.dev.port)
        self.assertEqual(rc, 3, res)
        self.assertFalse(res["image_knows_the_transcript"])
        self.assertIn("REFUSED by the gateway: transcript v2 required, but the endpoint answered the unbound exchange",
                      res["L1_bound_exchange"])
        self.assertIsNone(self.dev.session)

    def test_swap_to_an_image_from_before_the_transcript(self):
        rc, rec = self.check("quote", self.dev.port)
        self.assertEqual(rc, 0, rec)
        self.assertTrue(rec["session_for_the_reset_check"].startswith("bound, "), rec)
        self.dev.boot(tt.FW_B_OLD)                           # as after flashing the previous secure image
        rc, res = self.check("swap", self.dev.port)
        self.assertEqual(rc, 0, res)
        for key in ("S1_recorded_quote_continued", "S2_recorded_quote_continued"):
            self.assertTrue(res[key].startswith("refused: ") and "the endpoint answered the unbound exchange" in res[key])
        self.assertTrue(res["S2_quote_for_the_recorded_challenge"].startswith("another quote ("), res)
        self.assertTrue(res["S3_new_cycle"].startswith("refused: not admitted by the policy"), res)
        self.assertIsNone(self.dev.session)                  # no session with the image that was not appraised

    def test_quote_recorded_from_an_image_from_before_the_transcript(self):
        self.dev.boot(tt.FW_A_OLD)
        rc, rec = self.check("quote", self.dev.port)
        self.assertEqual(rc, 0, rec)
        self.assertTrue(rec["session_for_the_reset_check"].startswith("unbound (this image does not know"), rec)
        self.dev.boot(tt.FW_B)                               # an upgrade in between
        rc, res = self.check("swap", self.dev.port)
        self.assertEqual(rc, 0, res)
        self.assertIn("the endpoint answered the unbound exchange", res["S1_recorded_quote_continued"])
        self.assertEqual(res["S2_recorded_quote_continued"],
                         "refused: ML-KEM key not signed over the transcript of the quote just appraised")

    def test_a_quote_that_outlives_the_reset_fails_the_check(self):
        rc, rec = self.check("quote", self.dev.port)
        self.assertEqual(rc, 0, rec)
        kept = self.dev.quote
        self.dev.boot(tt.FW_A)
        self.dev.quote = kept                                # not RAM: the quote is still there after the reset
        rc, res = self.check("swap", self.dev.port)
        self.assertEqual(rc, 1, res)
        self.assertEqual(res["S1_recorded_quote_continued"], "ACCEPTED (bad)")
        self.assertTrue(res["S1_credential_sent"])


if __name__ == "__main__":
    unittest.main()
