# SPDX-License-Identifier: Apache-2.0
"""The fleet loop on an ordinary Linux host (fleet.py --platform linux, docs/pc-verifier.md), with simulated endpoints.

  - two verifiers on one endpoint: the provers serve one connection at a time and reset a second one; read-only
    requests are retried, so both verifiers get their verdict;
  - credentials: a Linux-host verifier provisions only endpoints whose policy entry names its own key in
    "verifier_pin_sha256"; anywhere else it sends no KEM or heartbeat traffic at all;
  - observe-only by default, portable state paths, the PC policy example, gen_gateway_pin.py --identity.
"""
import contextlib
import hashlib
import io
import json
import os
import socket
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.join(HERE, "..", "..")
for p in (HERE, os.path.join(ROOT, "common"), os.path.join(ROOT, "gateway", "aegisd"), os.path.join(ROOT, "gateway", "sysserv")):
    sys.path.insert(0, os.path.abspath(p))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import aegisd  # noqa: E402
import fleet  # noqa: E402
import psa_token  # noqa: E402
from test_fleet import FakeEndpoint, GOOD_NS, GOOD_S, PQ_KEYS, SIGNER  # noqa: E402

ALLOWED = [{"type": "SPE", "measurement_value": GOOD_S, "signer_id": SIGNER},
           {"type": "NSPE", "measurement_value": GOOD_NS, "signer_id": SIGNER}]


def _rst(conn):
    """Close with a TCP reset, as lwIP's tcp_abort does."""
    conn.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    conn.close()


class SingleSlot:
    """A front for a FakeEndpoint that behaves like the STM32 and RW612 provers' TCP server: one connection at a
    time, a second one reset at accept. It also resets the first `reset_first` connections and records every
    request line it forwards. hold_s keeps the slot busy after each reply (the time the device spends signing)."""

    def __init__(self, backend_port, hold_s=0.0, reset_first=0):
        self.backend, self.hold_s, self.reset_left = backend_port, hold_s, reset_first
        self.lines, self.resets, self.busy = [], 0, threading.Lock()
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(8)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.srv.accept()
            if self.reset_left > 0 or not self.busy.acquire(blocking=False):
                self.reset_left = max(self.reset_left - 1, 0)
                self.resets += 1
                _rst(c)
                continue
            threading.Thread(target=self.serve, args=(c,), daemon=True).start()

    def serve(self, c):
        try:
            buf = b""
            while b"\n" not in buf:
                chunk = c.recv(65536)
                if not chunk:
                    break
                buf += chunk
            line = buf.split(b"\n")[0]
            self.lines.append(line.decode().split(" ")[0])
            with socket.create_connection(("127.0.0.1", self.backend), timeout=10) as b:
                b.sendall(line + b"\n")
                reply = b""
                while b"\n" not in reply:
                    chunk = b.recv(65536)
                    if not chunk:
                        break
                    reply += chunk
            time.sleep(self.hold_s)
            c.sendall(reply)
        finally:
            c.close()
            self.busy.release()


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.dir = tempfile.mkdtemp()
        cls.pem = os.path.join(cls.dir, "iak.pub.pem")
        with open(cls.pem, "wb") as f:
            f.write(cls.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
        cls.pqf = os.path.join(cls.dir, "pq.pub")
        with open(cls.pqf, "w") as f:
            f.write(PQ_KEYS[0][0].hex())

    def endpoint(self, mode="kem-good", **front):
        ep = FakeEndpoint(self.key, mode)
        slot = SingleSlot(ep.port, **front)
        conf = {"name": "ep", "kind": "aegis-pq", "host": "127.0.0.1", "port": slot.port, "pq_pub_file": self.pqf,
                "iak_pub_pem": self.pem, "allowed": ALLOWED}
        return ep, slot, conf

    def linux_identity(self):
        """A verifier identity made the way the runbook makes it: aegisd.py --platform linux init."""
        d = tempfile.mkdtemp()
        mid, rel = os.path.join(d, "machine-id"), os.path.join(d, "os-release")
        with open(mid, "w") as f:
            f.write("0123456789abcdef0123456789abcdef\n")
        with open(rel, "w") as f:
            f.write('NAME="Test"\n')
        state = os.path.join(d, "state")
        rec = aegisd.init_identity(state, aegisd.LinuxHostSource(mid, rel))
        return state, hashlib.sha256(bytes.fromhex(rec["body"]["pk"])).hexdigest()


class TwoVerifiers(Base):
    def test_reset_at_accept_is_retried(self):
        _, slot, conf = self.endpoint(reset_first=2)
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=5)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(slot.resets, 2)

    def test_busy_beyond_the_retries_is_a_quarantine_with_a_reason(self):
        _, slot, conf = self.endpoint(reset_first=fleet.BUSY_RETRIES + 1)
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=5)
        self.assertFalse(v["admitted"])
        self.assertTrue(any("busy with another verifier" in r for r in v["reasons"]), v["reasons"])

    def test_two_verifiers_at_once_both_get_a_verdict(self):
        """The gateway and the PC attest the same single-connection endpoint at the same moment."""
        _, slot, conf = self.endpoint(hold_s=0.3)
        out = [None, None]

        def run(i):
            out[i] = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=5)
        ts = [threading.Thread(target=run, args=(i,)) for i in (0, 1)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        self.assertTrue(all(v["admitted"] for v in out), [v["reasons"] for v in out])
        self.assertGreaterEqual(slot.resets, 1, "the fake should have refused one of them")

    def test_quote_is_the_only_request_of_an_attestation(self):
        """Attestation sends PQCHAL and nothing else: no KEM exchange, no heartbeat, nothing that touches the session
        another verifier holds on the endpoint."""
        _, slot, conf = self.endpoint()
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=5)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(slot.lines, ["PQCHAL"])

    def test_unusable_replies_are_quarantined_with_the_reply_shown(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(4)

        def answer():
            while True:
                c, _ = srv.accept()
                c.recv(4096)
                c.sendall(b"HELLO there\r\n")
                c.close()
        threading.Thread(target=answer, daemon=True).start()
        conf = {"name": "g", "kind": "aegis-pq", "host": "127.0.0.1", "port": srv.getsockname()[1],
                "pq_pub_file": self.pqf, "allowed": ALLOWED}
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=5)
        self.assertEqual(v["reasons"], ["no attestation: no PQ quote in reply: 'HELLO there'"])
        with self.assertRaisesRegex(ValueError, "no PQ key in reply: 'HELLO there'"):
            fleet.request_pq_key("127.0.0.1", conf["port"])
        with self.assertRaisesRegex(ValueError, "no token in reply: 'HELLO there'"):
            fleet.request_token("127.0.0.1", conf["port"], b"\0" * 32, 5)

    def test_provisioning_is_never_retried(self):
        _, slot, conf = self.endpoint(reset_first=1)
        with self.assertRaises(fleet.EndpointBusy):
            fleet.provision(conf, self.dir, PQ_KEYS[1][1], "gid", {}, timeout=5)
        self.assertEqual((slot.resets, slot.lines), (1, []))


class Credentials(Base):
    def step(self, conf, state, require_pin):
        conf = dict(conf, provision=True)
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=5)
        self.assertTrue(v["admitted"], v["reasons"])
        return fleet.credential_step(conf, v, self.dir, state=state, require_pin=require_pin)

    def test_linux_host_without_pin_sends_no_kem(self):
        state, _ = self.linux_identity()
        _, slot, conf = self.endpoint()
        r = self.step(conf, state, require_pin=True)
        self.assertTrue(r.startswith("not issued: no verifier_pin_sha256"), r)
        self.assertEqual(slot.lines, ["PQCHAL"])
        self.assertFalse(os.path.exists(os.path.join(state, "credentials")))

    def test_pin_of_another_verifier_sends_no_kem(self):
        state, own = self.linux_identity()
        _, slot, conf = self.endpoint()
        other = hashlib.sha256(PQ_KEYS[1][0]).hexdigest()
        r = self.step(dict(conf, verifier_pin_sha256=other), state, require_pin=True)
        self.assertIn("the endpoint pins verifier key %s" % other[:16], r)
        self.assertIn("this verifier is %s" % own[:16], r)
        self.assertEqual(slot.lines, ["PQCHAL"])

    def test_own_pin_issues_then_heartbeats(self):
        state, own = self.linux_identity()
        _, slot, conf = self.endpoint()
        conf = dict(conf, verifier_pin_sha256=own.upper())
        self.assertTrue(self.step(conf, state, require_pin=True).startswith("issued session "))
        self.assertTrue(self.step(conf, state, require_pin=True).startswith("valid, heartbeat 1"))
        self.assertEqual(slot.lines, ["PQCHAL", "PQKEMINIT", "PQKEMFIN", "PQCHAL", "PQHB"])

    def test_pin_without_identity(self):
        _, slot, conf = self.endpoint()
        state = tempfile.mkdtemp()
        r = self.step(dict(conf, verifier_pin_sha256="ab" * 32), state, require_pin=True)
        self.assertIn("no verifier identity in %s" % state, r)
        self.assertEqual(slot.lines, ["PQCHAL"])

    def test_gateway_without_pin_keeps_provisioning(self):
        """On the gateway (require_pin off) an entry without a pin behaves as before: the current images pin its key."""
        state, _ = self.linux_identity()
        _, slot, conf = self.endpoint()
        self.assertTrue(self.step(conf, state, require_pin=False).startswith("issued session "))

    def test_malformed_pin_refused_by_policy(self):
        conf = {"name": "x", "kind": "aegis-pq", "pq_pub_file": "k", "verifier_pin_sha256": "<fill in>"}
        self.assertIn("policy: verifier_pin_sha256 is not 64 hex digits", fleet.policy_errors(conf))
        self.assertEqual(fleet.policy_errors(dict(conf, verifier_pin_sha256="0f" * 32)), [])


class HostDefaults(Base):
    def test_state_dir(self):
        with mock.patch.dict(os.environ, {"AEGIS_STATE_DIR": "/srv/aegis"}):
            self.assertEqual(fleet.default_state_dir("linux"), "/srv/aegis")
        env = {k: v for k, v in os.environ.items() if k not in ("AEGIS_STATE_DIR", "XDG_STATE_HOME")}
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(fleet.os, "geteuid", return_value=1000):
            self.assertEqual(fleet.default_state_dir("polarfire"), "/var/lib/aegis")
            self.assertEqual(fleet.default_state_dir("linux"), os.path.join(os.path.expanduser("~"), ".local", "state", "aegis"))
            with mock.patch.dict(os.environ, {"XDG_STATE_HOME": "/x"}):
                self.assertEqual(fleet.default_state_dir("linux"), "/x/aegis")
        with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(fleet.os, "geteuid", return_value=0):
            self.assertEqual(fleet.default_state_dir("linux"), "/var/lib/aegis")

    def hook_policy(self):
        d = tempfile.mkdtemp()
        mark = os.path.join(d, "ran")
        hook = os.path.join(d, "hook.sh")
        with open(hook, "w") as f:
            f.write("#!/bin/sh\ntouch %s\n" % mark)
        os.chmod(hook, os.stat(hook).st_mode | stat.S_IXUSR)
        pol = os.path.join(d, "policy.json")
        with open(pol, "w") as f:   # an entry refused by policy: a verdict without any network
            json.dump({"enforce_cmd": [hook], "endpoints": [{"name": "uno", "kind": "psa", "host": "h", "port": 1}]}, f)
        return pol, mark, d

    def run_main(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = fleet.main(argv)
        return rc, out.getvalue(), err.getvalue()

    def test_observe_only_on_linux(self):
        pol, mark, d = self.hook_policy()
        rc, out, err = self.run_main(["once", pol, "--platform", "linux", "--state-dir", d])
        self.assertEqual(rc, 0)
        self.assertFalse(os.path.exists(mark), "enforce_cmd must not run on a Linux host without --enforce")
        self.assertIn("observe-only", err)
        self.assertIsNone(json.loads(out)[0]["enforce_rc"])
        self.run_main(["once", pol, "--platform", "linux", "--state-dir", d, "--enforce"])
        self.assertTrue(os.path.exists(mark))

    def test_gateway_still_enforces(self):
        pol, mark, d = self.hook_policy()
        self.run_main(["once", pol, "--platform", "polarfire", "--state-dir", d])
        self.assertTrue(os.path.exists(mark))

    def test_watch_honours_no_credentials_and_writes_under_the_state_dir(self):
        pol, _, d = self.hook_policy()
        state = os.path.join(d, "nested", "state")
        seen = []
        real = fleet.run_once

        def spy(*a, **kw):
            seen.append(kw)
            return real(*a, **kw)
        with mock.patch.object(fleet, "run_once", side_effect=spy), \
                mock.patch.object(fleet.time, "sleep", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.run_main(["watch", pol, "--platform", "linux", "--state-dir", state, "--no-credentials"])
        self.assertEqual(seen[0]["credentials"], False)
        self.assertEqual((seen[0]["require_pin"], seen[0]["enforce_hooks"], seen[0]["state"]), (True, False, state))
        with open(os.path.join(state, "fleet-state.json")) as f:
            self.assertEqual(json.load(f)["verdicts"][0]["endpoint"], "uno")

    def test_pc_policy_example_passes_check(self):
        rc, out, _ = self.run_main(["check", os.path.join(ROOT, "gateway", "policy", "fleet.pc.example.json"),
                                    "--platform", "linux", "--state-dir", tempfile.mkdtemp()])
        self.assertEqual(rc, 0, out)
        for name in ("stm32h573-dk ok", "stm32h573-dk-2 ok", "frdm-rw612 ok", "platform linux", "observe-only"):
            self.assertIn(name, out)
        with open(os.path.join(ROOT, "gateway", "policy", "fleet.pc.example.json")) as f:
            pol = json.load(f)
        for ep in pol["endpoints"]:
            self.assertTrue(ep["host"].startswith("192.0.2."), "documentation addresses only: %s" % ep["host"])
            self.assertFalse(ep.get("provision"), "the example is attestation only")
        self.assertNotIn("enforce_cmd", pol)

    def test_gen_gateway_pin_from_a_local_identity(self):
        state, own = self.linux_identity()
        out = subprocess.run([sys.executable, os.path.join(ROOT, "tools", "gen_gateway_pin.py"), "--sha256-only",
                              "--identity", os.path.join(state, "identity.json")],
                             capture_output=True, text=True, check=True).stdout.strip()
        self.assertEqual(out, own)
        self.assertEqual(fleet.verifier_pk_sha256(state), own)
        hdr = os.path.join(tempfile.mkdtemp(), "gateway_pk.h")
        subprocess.run([sys.executable, os.path.join(ROOT, "tools", "gen_gateway_pin.py"), "--out", hdr,
                        "--identity", os.path.join(state, "identity.json")], capture_output=True, check=True)
        with open(hdr) as f:
            text = f.read()
        self.assertIn(own, text)
        self.assertEqual(text.count("0x"), 1952)


if __name__ == "__main__":
    unittest.main()
