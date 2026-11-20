"""tests/board/reset_replay_check.py, the reset-and-replay check for the boards, run on the PC against the RW612
prover's protocol code (endpoints/rw612/prover/src/aegis_proto.c, built by test_rw612_proto.py's recipe). A reset is
the program started again with the same device secrets.

  - an endpoint that puts fresh random bytes into every ML-KEM key passes: the recorded PQKEMINIT gets another key
    after the reset, the recorded PQKEMFIN is refused, a new exchange works;
  - without a reset in between, the check stops (exit 2) instead of passing for the wrong reason;
  - an endpoint whose generator starts again at every reset (AEGIS_TEST_STALE_RNG, host_main.c) fails it: the
    recorded key comes back and the recorded PQKEMFIN is accepted. That is what the STM32H573 partition did before
    it took random bytes into the key; its own PC test is test_stm32_partition.py.
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
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

CHECK = os.path.join(ROOT, "tests", "board", "reset_replay_check.py")
NAME = "pc-endpoint"


@unittest.skipUnless(shutil.which("gcc") and os.path.isdir(rw.MLDSA) and os.path.isdir(rw.MLKEM),
                     "needs gcc and mldsa-native / mlkem-native")
class ResetReplayCheck(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = d = tempfile.mkdtemp()
        cls.exe = os.path.join(d, "aegis_rw612_host")
        rw.build(cls.exe)
        gw_pk, gw_sk = mldsa.keypair()
        with open(os.path.join(d, "gw.pub"), "w") as f:
            f.write(gw_pk.hex())
        with open(os.path.join(d, "identity.sk"), "wb") as f:      # the gateway's state, as fleet.py reads it
            f.write(gw_sk)
        with open(os.path.join(d, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "test gateway"}}, f)
        with open(os.path.join(d, "image.bin"), "wb") as f:
            f.write(os.urandom(4096))
        cls.secrets = [os.urandom(32).hex(), os.urandom(32).hex()]  # the device's seed and provisioning root
        cls.proc = None

    @classmethod
    def tearDownClass(cls):
        cls.stop()
        shutil.rmtree(cls.d, ignore_errors=True)

    @classmethod
    def stop(cls):
        if cls.proc:
            cls.proc.kill()
            cls.proc.wait()
            cls.proc.stdout.close()
            cls.proc = None

    def boot(self, port, stale):
        """Start the endpoint, or start it again: the same keys, nothing else kept."""
        env = dict(os.environ)
        env.pop("AEGIS_TEST_STALE_RNG", None)
        if stale:
            env["AEGIS_TEST_STALE_RNG"] = "1"
        self.stop()
        cmd = [self.exe, str(port)] + self.secrets + [os.path.join(self.d, "gw.pub"), os.path.join(self.d, "image.bin")]
        type(self).proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, text=True, env=env)
        self.assertEqual(self.proc.stdout.readline().split()[0], "READY")

    def check(self, phase, port, *more):
        r = subprocess.run([sys.executable, CHECK, phase, os.path.join(self.d, "policy-%d.json" % port), NAME,
                            "--file", os.path.join(self.d, "recording-%d.json" % port), "--state", self.d] + list(more),
                           capture_output=True, text=True)
        self.assertIn(r.returncode, (0, 1, 2), r.stderr)
        return r.returncode, json.loads(r.stdout)

    def enrol(self, stale):
        port = rw.free_port()
        self.boot(port, stale)
        with socket.create_connection(("127.0.0.1", port), timeout=5) as s:
            s.sendall(b"PQKEY\n")
            reply = b""
            while not reply.endswith(b"\r\n"):
                reply += s.recv(65536)
        with open(os.path.join(self.d, "ep-%d.pub" % port), "w") as f:
            f.write(reply.split()[2].decode())
        with open(os.path.join(self.d, "policy-%d.json" % port), "w") as f:
            json.dump({"endpoints": [{"name": NAME, "kind": "aegis-device", "host": "127.0.0.1", "port": port,
                                      "pq_pub_file": "ep-%d.pub" % port, "heartbeat_mac": "kmac256"}]}, f)
        return port

    def test_fresh_keys_pass(self):
        port = self.enrol(stale=False)
        rc, rec = self.check("record", port)
        self.assertEqual((rc, rec["R_first_exchange_since_reset"]), (0, True), rec)
        with open(os.path.join(self.d, "recording-%d.json" % port)) as f:
            self.assertEqual(sorted(json.load(f)),                    # no session key in the recording
                             ["ek", "endpoint", "kem_fin", "kem_init", "recorded_at", "session_id"])
        rc, res = self.check("replay", port)                 # no reset yet: the recorded session is still there
        self.assertEqual(rc, 2, res)
        self.assertIn("A_reset", res)
        self.boot(port, stale=False)
        rc, res = self.check("replay", port, "--tries", "3")
        self.assertEqual(rc, 0, res)
        self.assertEqual((res["B_keys_signed_by_the_endpoint"], res["B_recorded_key_issued_again"],
                          res["B_keys_all_different"], res["C_refused_every_time"], res["E_new_session_kept"]),
                         (True, False, True, True, True), res)
        self.assertEqual(res["C_recorded_finish"], ["ERR cred other-key"] * 3, res)   # it names the recorded key
        self.assertEqual((res["D_session"], res["D_heartbeat"]), ("ERR pq no-session",) * 2, res)

    def test_keys_that_come_back_after_a_reset_fail(self):
        port = self.enrol(stale=True)
        rc, rec = self.check("record", port)
        self.assertEqual(rc, 0, rec)
        self.boot(port, stale=True)
        rc, res = self.check("replay", port)
        self.assertEqual(rc, 1, res)
        self.assertTrue(res["B_recorded_key_issued_again"], res)
        self.assertTrue(res["C_recorded_finish"][0].startswith("PQKEMOK "), res)   # the old session is back
        self.assertFalse(res["C_refused_every_time"], res)
        self.assertTrue(res["D_session"].startswith("PQSESSION " + rec["R_session"]), res)

    def test_second_exchange_since_reset(self):
        """The recording made at the second exchange since a reset: the stale endpoint repeats the key at the second
        try, so a replay with fewer tries does not see it (the check's text says so)."""
        port = self.enrol(stale=True)
        self.assertEqual(self.check("record", port)[0], 0)
        rc, rec = self.check("record", port)
        self.assertEqual((rc, rec["R_first_exchange_since_reset"]), (0, False), rec)
        self.boot(port, stale=True)
        rc, res = self.check("replay", port, "--tries", "1")
        self.assertEqual((rc, res["B_recorded_key_issued_again"]), (0, False), res)
        self.boot(port, stale=True)
        rc, res = self.check("replay", port)
        self.assertEqual((rc, res["B_recorded_key_issued_again"]), (1, True), res)
        self.assertEqual([x.split()[0] for x in res["C_recorded_finish"][:2]], ["ERR", "PQKEMOK"], res)


if __name__ == "__main__":
    unittest.main()
