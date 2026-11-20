# SPDX-License-Identifier: Apache-2.0
"""Gateway hardening (WP1, the rest of it): strict profiles, verified-first PSA parsing, loud enforcement failures and
expiring admissions. No hardware and no root: fake endpoints on 127.0.0.1 and a fake enforcement hook."""
import contextlib
import io
import json
import os
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("common", "gateway/aegisd", "tests/host"):
    sys.path.insert(0, os.path.join(ROOT, p))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import cbor  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import psa_token  # noqa: E402
import test_fleet as tf  # noqa: E402

PK, SK = tf.PQ_KEYS[0]
MEAS = "ab" * 32


class PlainEndpoint:
    """A plain-claims endpoint (aegis-tee and friends): answers PQCHAL with ML-DSA-65-signed CBOR claims."""

    def __init__(self, profile, claims_edit=None):
        self.profile, self.claims_edit = profile, claims_edit
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        self.asked = 0
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.srv.accept()
            with c:
                line = c.recv(4096).split(b"\n")[0].decode()
                self.asked += 1
                ch = bytes.fromhex(line.split()[1])
                claims = {265: self.profile, 10: ch, 256: b"\x02" + b"\x55" * 32,
                          2399: [{1: "BOOTCHAIN", 2: bytes.fromhex(MEAS)}]}
                if self.claims_edit:
                    self.claims_edit(claims)
                tok = cbor.dumps(claims)
                sig = mldsa.sign(SK, fleet.PQ_LABEL, tok)
                c.sendall(b"PQTOKEN %d %s %d %s END\r\n" % (len(tok), tok.hex().encode(), len(sig), sig.hex().encode()))


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.mkdtemp()
        with open(os.path.join(cls.dir, "ep.pub"), "w") as f:
            f.write(PK.hex())
        cls.key = ec.generate_private_key(ec.SECP256R1())
        cls.pem = os.path.join(cls.dir, "iak.pem")
        with open(cls.pem, "wb") as f:
            f.write(cls.key.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))

    def tee(self, sends, **kw):
        ep = PlainEndpoint(sends, kw.pop("claims_edit", None))
        e = {"name": "zynq", "kind": "aegis-tee", "host": "127.0.0.1", "port": ep.port, "pq_pub_file": "ep.pub",
             "allowed": [{"type": "BOOTCHAIN", "measurement_value": MEAS}]}
        e.update(kw)
        return ep, e


class StrictProfiles(Base):
    def test_psa_without_key_refused_without_asking(self):
        ep = tf.FakeEndpoint(self.key, "good")
        conf = {"name": "uno", "kind": "psa", "host": "127.0.0.1", "port": ep.port, "allowed": []}
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=1)
        self.assertFalse(v["admitted"])
        self.assertEqual(v["reasons"], ["policy: kind psa without iak_pub_pem (unsigned tokens are not accepted)"])
        conf.pop("kind")          # "psa" is the default kind: same rule
        self.assertFalse(fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=1)["admitted"])

    def test_psa_with_key_still_admitted(self):
        ep = tf.FakeEndpoint(self.key, "good")
        conf = {"name": "ok", "kind": "psa", "host": "127.0.0.1", "port": ep.port, "iak_pub_pem": self.pem,
                "allowed": [{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
                            {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}]}
        v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=2)
        self.assertTrue(v["admitted"], v["reasons"])

    def test_missing_profile_pin_refused_without_asking(self):
        ep, conf = self.tee(fleet.TEE_PROFILE)
        v = fleet.attest(conf, None, self.dir, timeout=5)
        self.assertFalse(v["admitted"])
        self.assertTrue(v["reasons"][0].startswith("policy: no profile pinned (kind aegis-tee"), v["reasons"])
        self.assertEqual(ep.asked, 0)

    def test_production_profile_pinned_admitted_as_trustzone(self):
        _, conf = self.tee(fleet.TEE_PROFILE, profile=fleet.TEE_PROFILE)
        v = fleet.attest(conf, None, self.dir, timeout=5)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "trustzone")
        self.assertNotIn("warning", v)

    def test_dev_profile_refused_by_default(self):
        for optin in (None, False, "true", 1):     # only the JSON value true opts in
            ep, conf = self.tee(fleet.TEE_DEVHUK_PROFILE, profile=fleet.TEE_DEVHUK_PROFILE)
            if optin is not None:
                conf["allow_dev_profile"] = optin
            v = fleet.attest(conf, None, self.dir, timeout=5)
            self.assertFalse(v["admitted"], optin)
            self.assertIn("development profile", v["reasons"][0])
            self.assertIn("allow_dev_profile", v["reasons"][0])
            self.assertEqual(ep.asked, 0)

    def test_dev_profile_admitted_with_opt_in_weaker_label_and_warning(self):
        _, conf = self.tee(fleet.TEE_DEVHUK_PROFILE, profile=fleet.TEE_DEVHUK_PROFILE, allow_dev_profile=True)
        v = fleet.attest(conf, None, self.dir, timeout=5)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["trust"], "development-shared-key")
        self.assertIn("same on every chip", v["warning"])
        line, prio = fleet.journal_line(v)
        self.assertIn("ADMITTED (development-shared-key trust)", line)
        self.assertIn("WARNING: development profile", line)
        self.assertEqual(prio, fleet.LOG_WARNING)

    def test_opt_in_does_not_let_dev_key_pass_as_production(self):
        # the endpoint answers with the dev profile, the entry pins the production one: the opt-in changes nothing
        _, conf = self.tee(fleet.TEE_DEVHUK_PROFILE, profile=fleet.TEE_PROFILE, allow_dev_profile=True)
        v = fleet.attest(conf, None, self.dir, timeout=5)
        self.assertFalse(v["admitted"])
        self.assertIn("profile %s, policy requires %s" % (fleet.TEE_DEVHUK_PROFILE, fleet.TEE_PROFILE), v["reasons"])

    def test_pin_outside_the_kind_refused(self):
        _, conf = self.tee(fleet.TEE_PROFILE, profile=fleet.DEVICE_TFM_PROFILE)
        v = fleet.attest(conf, None, self.dir, timeout=5)
        self.assertFalse(v["admitted"])
        self.assertTrue(v["reasons"][0].startswith("policy: pinned profile aegis-rw612-tfm-v1 is not one of"))

    def test_unknown_kind_and_heartbeat_mac_refused(self):
        self.assertEqual(fleet.policy_errors({"name": "x", "kind": "tpm"}), ["policy: unknown kind 'tpm'"])
        self.assertIn("policy: unknown heartbeat_mac 'md5'",
                      fleet.policy_errors({"name": "x", "kind": "aegis-pq", "pq_pub_file": "k", "heartbeat_mac": "md5"}))

    def test_check_command(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = fleet.main(["check", os.path.join(ROOT, "gateway", "policy", "fleet.example.json")])
        self.assertEqual(rc, 0, out.getvalue())
        self.assertIn("zynqmp-te0808 ok WARNING", out.getvalue())
        pol = os.path.join(self.dir, "bad.json")
        with open(pol, "w") as f:
            json.dump({"endpoints": [{"name": "uno", "kind": "psa", "host": "h", "port": 1},
                                     {"name": "z", "kind": "aegis-tee", "host": "h", "port": 1, "pq_pub_file": "k",
                                      "profile": fleet.TEE_DEVHUK_PROFILE}]}, f)
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = fleet.main(["check", pol])
        self.assertEqual(rc, 1)
        self.assertIn("uno REFUSED: policy: kind psa without iak_pub_pem", out.getvalue())
        self.assertIn("z REFUSED: policy: profile aegis-zynqmp-optee-devhuk-v1 is a development profile", out.getvalue())

    def test_example_policy_names_kmac_heartbeats(self):
        with open(os.path.join(ROOT, "gateway", "policy", "fleet.example.json")) as f:
            pol = json.load(f)
        for ep in pol["endpoints"]:
            if ep.get("provision"):
                self.assertEqual(ep.get("heartbeat_mac", fleet.DEFAULT_HEARTBEAT_MAC), "kmac256", ep["name"])
        self.assertEqual(fleet.DEFAULT_HEARTBEAT_MAC, "kmac256")


def es256_token(key, payload, protected=None):
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    protected = cbor.dumps({1: -7}) if protected is None else protected
    tbs = cbor.dumps(["Signature1", protected, b"", payload])
    r, s = decode_dss_signature(key.sign(tbs, ec.ECDSA(hashes.SHA256())))
    return cbor.dumps(cbor.Tag(18, [protected, {}, payload, r.to_bytes(32, "big") + s.to_bytes(32, "big")]))


class VerifiedFirst(Base):
    def pub(self):
        with open(self.pem, "rb") as f:
            return f.read()

    def test_claims_not_decoded_before_the_signature(self):
        tok = es256_token(self.key, cbor.dumps({10: b"x" * 32}))
        tampered = es256_token(ec.generate_private_key(ec.SECP256R1()), cbor.dumps({10: b"x" * 32}))
        with mock.patch.object(psa_token, "claims_from_map", side_effect=AssertionError("decoded first")) as dec:
            with self.assertRaisesRegex(psa_token.TokenError, "token signature invalid"):
                psa_token.verify(tampered, self.pub(), psa_token.verify_with_cryptography)
            dec.assert_not_called()
        self.assertEqual(psa_token.verify(tok, self.pub(), psa_token.verify_with_cryptography)["challenge"], b"x" * 32)

    def test_unsigned_hostile_payload_reports_the_signature(self):
        # a payload the decoder refuses, under a wrong signature: the answer is about the signature, not the payload
        bad_payload = bytes.fromhex("a1" "8101" "02")
        tok = es256_token(ec.generate_private_key(ec.SECP256R1()), bad_payload)
        with self.assertRaisesRegex(psa_token.TokenError, "token signature invalid"):
            psa_token.verify(tok, self.pub(), psa_token.verify_with_cryptography)

    def test_every_decode_error_becomes_tokenerror(self):
        tok = es256_token(self.key, cbor.dumps({10: b"x" * 32}))
        for exc in (TypeError("t"), ValueError("v"), KeyError("k"), RecursionError("r"), IndexError("i"),
                    AttributeError("a"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "u"), OverflowError("o")):
            with mock.patch.object(psa_token, "claims_from_map", side_effect=exc):
                with self.assertRaises(psa_token.TokenError, msg=repr(exc)):
                    psa_token.verify(tok, self.pub(), psa_token.verify_with_cryptography)
                with self.assertRaises(psa_token.TokenError, msg=repr(exc)):
                    psa_token.parse(tok)
                with self.assertRaises(psa_token.TokenError, msg=repr(exc)):
                    psa_token.parse_plain(cbor.dumps({}))
            with mock.patch.object(psa_token.cbor, "loads", side_effect=exc):
                with self.assertRaises(psa_token.TokenError, msg=repr(exc)):
                    psa_token.envelope(tok)

    def test_signed_but_malformed_claims_never_crash_attest(self):
        """A key holder (or a broken image) signs claims of the wrong shapes: refused, no exception."""
        bad_claims = [{10: 5}, {-75006: "x"}, {-75006: [{2: 7, 1: "SPE"}]}, {-75006: [{1: ["x"], 2: b"a"}]},
                      {10: b"", -75006: [{1: "SPE", 2: b"\x11" * 32, 5: 3}]}, {"profile": {"a": 1}}]
        for claims in bad_claims:
            tok = es256_token(self.key, cbor.dumps(claims))

            class Ep(tf.FakeEndpoint):
                def loop(inner):
                    c, _ = inner.srv.accept()
                    with c:
                        c.recv(4096)
                        c.sendall(b"TOKEN %d %s END\r\n" % (len(tok), tok.hex().encode()))
            ep = Ep(self.key)
            conf = {"name": "h", "kind": "psa", "host": "127.0.0.1", "port": ep.port, "iak_pub_pem": self.pem,
                    "allowed": [{"type": "SPE", "measurement_value": "11" * 32}]}
            v = fleet.attest(conf, psa_token.verify_with_cryptography, self.dir, timeout=2)
            self.assertFalse(v["admitted"], claims)

    def test_plain_claims_of_wrong_shape_refused(self):
        _, conf = self.tee(fleet.TEE_PROFILE, profile=fleet.TEE_PROFILE,
                           claims_edit=lambda c: c.update({2399: [{1: "BOOTCHAIN", 2: 12345}]}))
        v = fleet.attest(conf, None, self.dir, timeout=5)
        self.assertFalse(v["admitted"])
        self.assertTrue(any("malformed" in r for r in v["reasons"]), v["reasons"])

    def test_run_once_survives_an_attest_crash(self):
        pol = {"endpoints": [{"name": "a", "kind": "psa", "iak_pub_pem": "x", "host": "h", "port": 1}]}
        with mock.patch.object(fleet, "attest", side_effect=RecursionError("deep")):
            v, = fleet.run_once(pol, self.dir, None, credentials=False)
        self.assertFalse(v["admitted"])
        self.assertEqual(v["reasons"], ["attestation error: RecursionError: deep"])

    def test_cbor_bytes_keys_refused(self):
        with self.assertRaises(cbor.CBORError):
            cbor.loads(bytes.fromhex("a1" "4161" "01"))             # {h'61': 1}
        with self.assertRaises(psa_token.TokenError):
            psa_token.parse_plain(bytes.fromhex("a1" "4161" "01"))
        self.assertEqual(cbor.loads(bytes.fromhex("a2" "0a" "4161" "6161" "01")), {10: b"a", "a": 1})


class Enforcement(Base):
    def hook(self, body):
        path = os.path.join(tempfile.mkdtemp(), "hook.sh")
        with open(path, "w") as f:
            f.write("#!/bin/sh\n" + body + "\n")
        os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
        return path

    def policy(self, hook):
        # a psa entry without a key: refused by policy, so no network is needed for the verdict
        return {"enforce_cmd": [hook], "endpoints": [{"name": "uno", "kind": "psa", "host": "h", "port": 1}]}

    def run_quiet(self, pol, **kw):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            res = fleet.run_once(pol, self.dir, None, credentials=False, **kw)
        return res, err.getvalue()

    def test_failed_quarantine_is_loud(self):
        h = self.hook('echo "aegis-enforce: quarantine $1 (10.0.0.9) failed" >&2; echo "Error: no such set" >&2; exit 3')
        (v,), err = self.run_quiet(self.policy(h))
        self.assertEqual(v["enforce_rc"], 3)
        self.assertEqual(v["enforcement"], "FAILED")
        self.assertIn("Error: no such set", v["enforce_error"])
        line, prio = fleet.journal_line(v)
        self.assertIn("uno QUARANTINED [enforcement FAILED rc=3: aegis-enforce: quarantine uno (10.0.0.9) failed]",
                      line)
        self.assertEqual(prio, fleet.LOG_ERR)
        self.assertIn("Error: no such set", err)      # the full stderr reaches the journal too

    def test_successful_hook_is_quiet(self):
        (v,), err = self.run_quiet(self.policy(self.hook("exit 0")))
        self.assertEqual((v["enforce_rc"], v["enforcement"]), (0, "ok"))
        line, prio = fleet.journal_line(v)
        self.assertNotIn("enforcement", line)
        self.assertIsNone(prio)
        self.assertEqual(err, "")

    def test_missing_hook_is_a_failure(self):
        (v,), _ = self.run_quiet(self.policy("/nonexistent/aegis-enforce.sh"))
        self.assertEqual(v["enforcement"], "FAILED")
        self.assertIn("[enforcement FAILED rc=none: hook could not be started", fleet.journal_line(v)[0])

    def test_failure_without_message(self):
        (v,), _ = self.run_quiet(self.policy(self.hook("exit 5")))
        self.assertIn("[enforcement FAILED rc=5: no message]", fleet.journal_line(v)[0])

    def test_no_hook(self):
        pol = self.policy("x")
        pol.pop("enforce_cmd")
        (v,), _ = self.run_quiet(pol)
        self.assertIsNone(v["enforce_rc"])
        self.assertNotIn("enforcement", v)

    def test_hook_gets_the_admission_ttl(self):
        out = os.path.join(tempfile.mkdtemp(), "env")
        h = self.hook('echo "$1 $2 $AEGIS_ADMIT_TTL" > %s' % out)
        self.run_quiet(self.policy(h), interval=30)
        with open(out) as f:
            self.assertEqual(f.read().split(), ["uno", "quarantine", str(fleet.admit_ttl(self.policy(h), 30))])

    def test_journal_priority_prefix_only_under_systemd(self):
        for env, want in (({"JOURNAL_STREAM": "8:1234"}, "<3>x\n"), ({}, "x\n")):
            out = io.StringIO()
            with mock.patch.dict(os.environ, env, clear=False), contextlib.redirect_stdout(out):
                if not env:
                    os.environ.pop("JOURNAL_STREAM", None)
                fleet.log("x", fleet.LOG_ERR)
            self.assertEqual(out.getvalue(), want)

    def test_enforce_script_reports_its_own_message_first(self):
        """aegis-enforce.sh without root or nft: an endpoint missing from the policy fails with exit 3 and the
        script's own line first (the line fleet.py puts in the journal)."""
        pol = os.path.join(tempfile.mkdtemp(), "fleet.json")
        with open(pol, "w") as f:
            json.dump({"endpoints": [{"name": "ep1", "host": "10.0.0.1"}]}, f)
        r = subprocess.run([os.path.join(ROOT, "gateway", "enforce", "aegis-enforce.sh"), "nosuch", "quarantine"],
                           capture_output=True, text=True, env=dict(os.environ, AEGIS_POLICY=pol))
        self.assertEqual(r.returncode, 3)
        self.assertTrue(r.stderr.startswith("aegis-enforce: quarantine nosuch failed: no address for it in"), r.stderr)


class AdmissionTtl(unittest.TestCase):
    def test_ttl_covers_a_full_cycle(self):
        pol = {"timeout_s": 20, "endpoints": [{"provision": True}, {"provision": True}, {}, {}]}
        ttl = fleet.admit_ttl(pol, 30)
        worst_gap = 30 + 2 * (20 + 40) + 2 * 20      # the sleep plus the slowest possible cycle
        self.assertGreater(ttl, worst_gap)
        self.assertEqual(ttl, 2 * 30 + worst_gap - 30)

    def test_ttl_covers_the_transcript_retry(self):
        """An entry with "transcript" may take a second quote and a second provisioning in one cycle
        (credential_step): the pause before it, timeout_s and another 40 s."""
        pol = {"timeout_s": 20, "endpoints": [{"provision": True, "transcript": "v2"}, {}]}
        worst_gap = 30 + (20 + 40) + (fleet.BUSY_BACKOFF_S[1] + 20 + 40) + 20
        self.assertGreater(fleet.admit_ttl(pol, 30), worst_gap)
        self.assertEqual(fleet.admit_ttl(pol, 30), int(2 * 30 + worst_gap - 30 + 0.999))

    def test_ttl_floor_and_override(self):
        self.assertEqual(fleet.admit_ttl({"endpoints": []}, 1), 60)
        self.assertEqual(fleet.admit_ttl({"admit_ttl_s": 45, "endpoints": [{}]}, 30), 45)
        self.assertEqual(fleet.admit_ttl({"admit_ttl_s": "soon", "endpoints": []}, 30), 60)   # ignored, not fatal

    def test_ruleset_declares_an_expiring_set(self):
        with open(os.path.join(ROOT, "gateway", "enforce", "aegis.nft")) as f:
            nft = f.read()
        block = nft[nft.index("set admitted {"):]
        block = block[:block.index("}")]
        self.assertIn("flags timeout", block)
        self.assertRegex(block, r"\btimeout \d+[smh]\b")


if __name__ == "__main__":
    unittest.main()
