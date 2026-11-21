# SPDX-License-Identifier: Apache-2.0
"""Aegis 1.2, the verifier (docs/evidence-format.md, docs/audit-and-policy.md):

  signed pack     export-evidence signs manifest.json and the export time (manifest.cose, its own typ); the
                  standalone checker refuses a pack whose signature fails, and reports an older pack's export time as
                  not signed
  audit head      an attestation result names the audit log's last batch on disk when it was signed
                  (aegis.audit-head); tools/verify_audit.py --result checks a result against a log
  disabled        "disabled": true in an entry: not contacted, quarantined, its session revoked, said in the result
  min_trust       a floor on the trust label, per entry and fleet-wide; `check` names a floor that is never met
  warnings        the verdict's warning and the vector's details in the result (aegis.warnings)
  compatibility   Aegis 1.1's readers (from the v1.1.0 tag, where git has it) accept what 1.2 writes

Simulated endpoints (no hardware). Claim names and numbers are written out as the documents give them.
"""
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("TSS2_LOG", "all+NONE")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("common", "gateway/aegisd", "provision", "tests/host"):
    sys.path.insert(0, os.path.join(ROOT, p))

import audit  # noqa: E402
import cbor  # noqa: E402
import cose  # noqa: E402
import eat  # noqa: E402
import evidence_pack  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import test_evidence_format as te  # noqa: E402
import test_fleet as tf  # noqa: E402

EatDevice, run, checker, thumb, NEEDS_LIBS = te.EatDevice, te.run, te.checker, te.thumb, te.NEEDS_LIBS
AUDIT_CHECKER = os.path.join(ROOT, "tools", "verify_audit.py")
PACK_TYP = "application/vnd.aegis.evidence-pack+cbor"
PACK_FORMAT = "tag:github.com,2026:ismailalitech/aegis/evidence-pack/v1"
ORDER = ["trustzone", "trustzone-devkey", "device-key", "software", "development-shared-key"]
XPK, XSK = mldsa.keypair()          # somebody else's key


def audit_checker(*args):
    r = subprocess.run([sys.executable, "-I", AUDIT_CHECKER, *args], capture_output=True, text=True,
                       cwd=tempfile.gettempdir())
    try:
        return r.returncode, json.loads(r.stdout)
    except ValueError:
        return r.returncode, {"verified": False, "reason": r.stdout + r.stderr}


def v11(path):
    """A file as Aegis 1.1 shipped it (tag v1.1.0), written to a directory of its own; None where git does not have
    the tag (a shallow checkout)."""
    r = subprocess.run(["git", "-C", ROOT, "show", "v1.1.0:" + path], capture_output=True)
    if r.returncode != 0:
        return None
    d = tempfile.mkdtemp()
    out = os.path.join(d, os.path.basename(path))
    with open(out, "wb") as f:
        f.write(r.stdout)
    return out


class V12(te.Bench):
    def setUp(self):
        super().setUp()
        patch = mock.patch.dict(fleet.AUDIT_SETTINGS, min_interval_s=0)     # each cycle's batch at once
        patch.start()
        self.addCleanup(patch.stop)

    def cycle(self, trail=None, **kw):
        kw.setdefault("credentials", False)
        res = fleet.run_once(self.policy, self.d, te.VERIFY, state=self.state, policy_bytes=self.policy_bytes,
                             audit=trail, **kw)
        if trail is not None:
            with contextlib.redirect_stderr(io.StringIO()):
                trail.flush()
        return {v["endpoint"]: v for v in res}

    def read(self, name):
        return eat.read_ear(self.result(name), self.vpk)

    def ver(self, name):
        """The verifier claims (1006) of the endpoint's signed result, as signed."""
        return next(iter(cbor.loads(cose.parse(self.result(name)).payload)[266].values()))[1006]

    def check(self, *more):
        return run(fleet.main, ["check", self.pol, "--state-dir", self.state, "--platform", "linux", *more])


# ---- disabled ------------------------------------------------------------------------------------------------------

class Disabled(V12):
    def test_a_disabled_entry_is_not_contacted_and_its_result_says_so(self):
        dev, on = EatDevice(), EatDevice()
        self.add("off", dev, disabled=True)
        self.add("on", on, disabled=False)
        vs = self.cycle()
        v = vs["off"]
        self.assertEqual((v["admitted"], v["reasons"], v["disabled"]), (False, ["disabled by policy"], True))
        self.assertEqual(dev.asked, [])                         # not contacted
        self.assertTrue(vs["on"]["admitted"], vs["on"]["reasons"])
        self.assertNotIn("disabled", vs["on"])                  # "disabled": false is the entry as before
        r = self.read("off")
        # incomplete: nothing was appraised (docs/evidence-format.md); the reason in ear.status-details
        self.assertEqual((r["status"], r["admitted"], r["disabled"]), ("incomplete", False, True))
        self.assertEqual(r["details"], ["disabled by policy"])
        self.assertIs(self.ver("off")["aegis.disabled"], True)
        self.assertEqual(r["vector"], {0: 0})
        self.assertNotIn("aegis.disabled", self.ver("on"))
        self.assertFalse(self.read("on")["disabled"])

    def test_a_disabled_entry_loses_its_session_and_is_quarantined_by_the_hook(self):
        dev = EatDevice()
        self.add("dev", dev, disabled=True, provision=True)
        cdir = os.path.join(self.state, "credentials")
        os.makedirs(cdir)
        for f in ("dev.json", "dev.session"):
            with open(os.path.join(cdir, f), "w") as fh:
                fh.write("{}")
        hook_log = os.path.join(self.d, "hook.log")
        hook = os.path.join(self.d, "hook.py")
        with open(hook, "w") as f:
            f.write("import sys\nopen(%r, 'a').write(' '.join(sys.argv[1:]) + '\\n')\n" % hook_log)
        self.policy["enforce_cmd"] = [sys.executable, hook]
        self.save()
        v = self.cycle(credentials=True, enforce_hooks=True)["dev"]
        self.assertEqual((v["admitted"], v["credential"], v["enforcement"]), (False, "revoked", "ok"))
        self.assertEqual(os.listdir(cdir), [])
        with open(hook_log) as f:
            self.assertEqual(f.read(), "dev quarantine\n")
        self.assertEqual(dev.asked, [])

    def test_a_disabled_value_that_is_not_true_or_false_is_a_refusal(self):
        dev = EatDevice()
        for value in ("yes", "true", 1, 0, None, [], {}, [True]):
            e = dict(self.add("dev", dev), disabled=value)
            v = self.attest(e)
            self.assertFalse(v["admitted"])
            self.assertIn("policy: disabled is not true or false", v["reasons"])
            self.assertNotIn("disabled", v)
        self.assertEqual(dev.asked, [])
        # disabled together with another mistake: both said, still not contacted
        v = self.attest(dict(self.add("dev", dev), disabled=True, evidence_format="eat-cose-v9"))
        self.assertEqual(v["reasons"][0], "disabled by policy")
        self.assertTrue(any("unknown evidence_format" in r for r in v["reasons"]))
        self.assertEqual(dev.asked, [])

    def test_check_lists_a_disabled_entry(self):
        self.add("off", EatDevice(), disabled=True)
        self.add("on", EatDevice())
        rc, out = self.check()
        self.assertEqual(rc, 0, out)                            # asked for, not a mistake
        self.assertIn("off DISABLED: disabled by policy: not contacted, quarantined every cycle", out)
        self.assertIn("on ok", out)
        self.policy["endpoints"][0]["disabled"] = "yes"
        self.save()
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("off REFUSED: policy: disabled is not true or false", out)

    def test_a_reader_refuses_a_disabled_claim_that_contradicts_the_result(self):
        payload = cbor.loads(eat.ear_payload({"endpoint": "dev", "admitted": True, "reasons": [], "trust": "trustzone",
                                              "enrolment": "endorsed"},
                                             {"stage": "appraised", "signature": True, "components_ok": True},
                                             eat.policy_id(b"{}"), 1000))
        a = next(iter(payload[266].values()))
        for bad in (True, False, 1, "true"):
            a[1006]["aegis.disabled"] = bad
            with self.assertRaises(eat.Refused):
                eat.read_ear(cose.sign1(self.vsk, self.vpk, cbor.dumps(payload, sort=True)), self.vpk)


# ---- min_trust -----------------------------------------------------------------------------------------------------

class MinTrust(V12):
    def test_the_order_of_the_labels(self):
        self.assertEqual(list(fleet.TRUST_ORDER), ORDER)
        for i, t in enumerate(ORDER):
            for j, floor in enumerate(ORDER):
                self.assertEqual(fleet.trust_meets(t, floor), i <= j, (t, floor))
        for t in (None, "", "TrustZone", "none", 1):
            self.assertFalse(any(fleet.trust_meets(t, f) for f in ORDER))
        self.assertFalse(fleet.trust_meets("trustzone", "nonsense"))

    def test_a_verdict_below_its_floor_is_quarantined_every_cycle(self):
        tfm, els = EatDevice(), EatDevice(platform="aegis-rw612-els-v1")       # trustzone; device-key
        self.add("tfm", tfm, min_trust="trustzone")
        self.add("els", els, min_trust="trustzone")
        self.add("els-ok", els, min_trust="device-key")
        self.add("els-low", els, min_trust="software")
        for _ in range(2):
            vs = self.cycle()
            self.assertTrue(vs["tfm"]["admitted"], vs["tfm"]["reasons"])
            self.assertEqual((vs["tfm"]["trust"], vs["tfm"]["min_trust"]), ("trustzone", "trustzone"))
            self.assertEqual((vs["els"]["admitted"], vs["els"]["reasons"]),
                             (False, ["trust device-key below min_trust trustzone"]))
            self.assertTrue(vs["els-ok"]["admitted"] and vs["els-low"]["admitted"])
        r = self.read("els")
        # contraindicated: the evidence was appraised and is not enough for this entry
        self.assertEqual((r["status"], r["min_trust"], r["admitted"]), ("contraindicated", "trustzone", False))
        self.assertIn("trust device-key below min_trust trustzone", r["details"])
        self.assertEqual(self.read("tfm")["min_trust"], "trustzone")

    def test_the_fleet_wide_floor_and_an_entry_s_own(self):
        els = EatDevice(platform="aegis-rw612-els-v1")
        self.add("fleet-floor", els)
        self.add("own-floor", els, min_trust="device-key")      # the entry's own replaces the fleet's
        self.policy["min_trust"] = "trustzone"
        self.save()
        vs = self.cycle()
        self.assertEqual(vs["fleet-floor"]["reasons"], ["trust device-key below min_trust trustzone"])
        self.assertTrue(vs["own-floor"]["admitted"], vs["own-floor"]["reasons"])
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("min_trust trustzone can NEVER be met: this entry's trust is device-key", out)
        self.assertIn("min_trust device-key: met by trust device-key (the entry's own floor; the policy's is "
                      "trustzone)", out)

    def test_a_verdict_without_a_label_meets_no_floor(self):
        # kind psa with its own (not TF-M's development) key: no trust label
        e = {"name": "psa", "host": "127.0.0.1", "port": tf.FakeEndpoint(self.iak).port, "iak_pub_pem": "iak.pem",
             "allowed": [{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
                         {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}]}
        self.assertTrue(fleet.attest(e, te.VERIFY, self.d, 5)["admitted"])
        v = fleet.attest(dict(e, min_trust="development-shared-key"), te.VERIFY, self.d, 5)
        self.assertEqual((v["admitted"], v["reasons"]), (False, ["trust none below min_trust development-shared-key"]))
        self.policy["endpoints"].append(dict(e, min_trust="development-shared-key"))
        self.save()
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("min_trust development-shared-key can NEVER be met: this entry's trust is none", out)

    def test_check_names_each_floor_that_can_never_be_met(self):
        dev = EatDevice()
        for name, kind, profile, floor, never in (
                ("linux", "aegis-linux", fleet.LINUX_PROFILE, "trustzone", "software"),
                ("linux-ok", "aegis-linux", fleet.LINUX_PROFILE, "software", None),
                ("tee-dev", "aegis-tee", fleet.TEE_DEVHUK_PROFILE, "software", "development-shared-key"),
                ("tfm", "aegis-device", fleet.DEVICE_TFM_PROFILE, "trustzone", None),
                ("els", "aegis-device", fleet.DEVICE_PROFILE, "trustzone-devkey", "device-key")):
            self.add(name, dev, kind=kind, profile=profile, min_trust=floor,
                     allow_dev_profile=True if profile == fleet.TEE_DEVHUK_PROFILE else None)
        self.add_pq("pq", dev, min_trust="trustzone")           # its ES256 key is not TF-M's development one
        self.add("pq-nokey", dev, kind="aegis-pq", profile=None, min_trust="device-key")
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        lines = out.splitlines()
        for name, label in (("linux", "software"), ("tee-dev", "development-shared-key"), ("els", "device-key"),
                            ("pq-nokey", "none")):
            i = lines.index(next(x for x in lines if x.startswith(name + " ")))
            self.assertIn("can NEVER be met: this entry's trust is %s" % label, lines[i + 1], name)
        for name, label in (("linux-ok", "software"), ("tfm", "trustzone"), ("pq", "trustzone")):
            i = lines.index(next(x for x in lines if x.startswith(name + " ")))
            self.assertIn("met by trust %s" % label, lines[i + 1], name)
        self.assertEqual(dev.asked, [])
        # TF-M's published development key gives kind aegis-pq trustzone-devkey, kind psa development-shared-key
        with open(os.path.join(self.d, "dev-iak.pem"), "wb") as f:
            f.write(b"-----BEGIN PUBLIC KEY-----\n" + __import__("base64").encodebytes(fleet.TFM_DEV_IAK_DER) +
                    b"-----END PUBLIC KEY-----\n")
        self.assertEqual(fleet.possible_trust({"kind": "aegis-pq", "iak_pub_pem": "dev-iak.pem"}, self.d),
                         {"trustzone-devkey"})
        self.assertEqual(fleet.possible_trust({"iak_pub_pem": "dev-iak.pem"}, self.d), {"development-shared-key"})
        self.assertEqual(fleet.possible_trust({"iak_pub_pem": "iak.pem"}, self.d), {None})
        self.assertEqual(fleet.possible_trust({"kind": "aegis-pq", "iak_pub_pem": "missing.pem"}, self.d),
                         {"trustzone", "trustzone-devkey"})

    def test_a_floor_the_verifier_does_not_know_is_a_refusal(self):
        dev = EatDevice()
        for value in ("TrustZone", "trustzone ", "", "none", 1, None, True, ["trustzone"], {"x": 1}):
            v = self.attest(dict(self.add("dev", dev), min_trust=value))
            self.assertFalse(v["admitted"])
            self.assertTrue(any(r.startswith("policy: unknown min_trust") for r in v["reasons"]), v["reasons"])
        self.assertEqual(dev.asked, [])
        # at the top level: every entry that has no floor of its own is refused
        self.policy["min_trust"] = "strong"
        self.save()
        vs = self.cycle()
        self.assertTrue(all(not v["admitted"] for v in vs.values()))
        self.assertEqual(dev.asked, [])
        rc, out = self.check()
        self.assertEqual(rc, 1, out)
        self.assertIn("unknown min_trust 'strong'", out)


# ---- warnings and details in the result ---------------------------------------------------------------------------

class Warnings(V12):
    def test_the_warning_and_the_vector_details_are_in_the_result(self):
        self.add("els", EatDevice(platform="aegis-rw612-els-v1"))           # pinned on first use, self-measured
        self.add("tee", EatDevice(platform=fleet.TEE_DEVHUK_PROFILE), kind="aegis-tee",
                 profile=fleet.TEE_DEVHUK_PROFILE, allow_dev_profile=True)
        vs = self.cycle()
        self.assertTrue(all(v["admitted"] for v in vs.values()), vs)
        r = self.read("els")
        self.assertEqual(r["status"], "warning")
        self.assertEqual(r["warnings"], [
            "instance-identity: the key is pinned without an endorsement: nothing names the device that holds it",
            "executables: the components are measured by the measured software itself (trust: device-key)"])
        self.assertEqual(r["vector_details"], {0: ["the key is pinned without an endorsement: nothing names the device "
                                                   "that holds it"],
                                               2: ["the components are measured by the measured software itself "
                                                   "(trust: device-key)"]})
        r = self.read("tee")
        self.assertEqual(r["warnings"][0], vs["tee"]["warning"])
        self.assertIn("instance-identity: the key of this development profile is the same on every chip", r["warnings"])
        self.assertEqual(self.ver("tee")["aegis.warnings"], r["warnings"])

    def test_an_affirming_result_has_none(self):
        e = self.add("dev", EatDevice())
        self.enrol(e)
        v = self.cycle()["dev"]
        self.assertTrue(v["admitted"], v["reasons"])
        r = self.read("dev")
        self.assertEqual((r["status"], r["warnings"]), ("affirming", None))
        self.assertNotIn("aegis.warnings", self.ver("dev"))

    def test_the_claim_is_bounded(self):
        vd = {0: ["i" * 1000] * 5, 2: ["e" * 10] * 5}
        texts = eat.warning_texts({"warning": "w" * 5000}, vd)
        self.assertEqual(len(texts), 8)
        self.assertTrue(all(0 < len(t) <= 300 for t in texts))
        self.assertEqual(texts[0], "w" * 300)
        self.assertEqual(texts[1], ("instance-identity: " + "i" * 1000)[:300])
        self.assertIsNone(eat.warning_texts({"warning": ""}, {}))
        payload = eat.ear_payload({"endpoint": "dev", "admitted": True, "reasons": [], "warning": "w" * 5000,
                                   "trust": "software"},
                                  {"stage": "appraised", "signature": True, "components_ok": True},
                                  eat.policy_id(b"{}"), 1000)
        r = eat.read_ear(cose.sign1(self.vsk, self.vpk, payload), self.vpk)
        self.assertEqual(r["warnings"][0], "w" * 300)

    def test_a_claim_not_of_its_form_is_refused_by_both_readers(self):
        good = cbor.loads(eat.ear_payload({"endpoint": "dev", "admitted": False, "reasons": ["x"]}, {"stage": "policy"},
                                          eat.policy_id(b"{}"), 1000))
        head = {"aegis.audit-log": bytes(16), "aegis.audit-batch": 1, "aegis.audit-head": bytes(32)}
        cases = [{"aegis.warnings": v} for v in ([], ["x"] * 9, [""], ["x" * 301], "x", [1], [b"x"], None)]
        cases += [{"aegis.min-trust": v} for v in ("", "x" * 65, 1, ["trustzone"], None)]
        cases += [{k: v for k, v in head.items() if k != gone} for gone in head]          # one of the three missing
        cases += [dict(head, **{k: v}) for k, v in (("aegis.audit-log", bytes(15)), ("aegis.audit-log", "00" * 16),
                                                     ("aegis.audit-batch", 0), ("aegis.audit-batch", -1),
                                                     ("aegis.audit-batch", "1"), ("aegis.audit-batch", True),
                                                     ("aegis.audit-batch", 1 << 53), ("aegis.audit-head", bytes(31)),
                                                     ("aegis.audit-head", None), ("aegis.audit-log", [bytes(16)]))]
        with open(os.path.join(self.d, "v.pub"), "w") as f:
            f.write(self.vpk.hex())
        for case in cases:
            c = cbor.loads(cbor.dumps(good))
            next(iter(c[266].values()))[1006].update(case)
            data = cose.sign1(self.vsk, self.vpk, cbor.dumps(c, sort=True))
            with self.assertRaises(eat.Refused, msg=case):
                eat.read_ear(data, self.vpk)
            if te.have_checker_libs():
                path = os.path.join(self.d, "r.cbor")
                with open(path, "wb") as f:
                    f.write(data)
                rc, rep = checker("result", path, "--key", os.path.join(self.d, "v.pub"))
                self.assertEqual((rc, rep["verified"]), (1, False), (case, rep))


# ---- the audit log's head in the result ------------------------------------------------------------------------------

class AuditHead(V12):
    def setUp(self):
        super().setUp()
        self.policy["audit_log"] = True
        self.dev = EatDevice()
        self.e = self.add("dev", self.dev)
        self.trail = fleet.open_audit(self.policy, self.state, start={"cmd": "test"})
        self.adir = os.path.join(self.state, "audit")

    def keep(self, name="result.cbor"):
        path = os.path.join(self.d, name)
        shutil.copy(os.path.join(self.state, "attestation", "dev", "result.cbor"), path)
        return path

    def test_a_result_names_the_last_batch_on_disk_when_it_was_signed(self):
        v = self.cycle(self.trail)["dev"]
        # the first result of a new log: nothing is on disk yet, so it names no head
        self.assertIsNone(self.read("dev")["audit_head"])
        self.assertNotIn("audit_head", v["attestation_result"])
        first = audit.verify(self.adir, [self.vpk])["logs"][0]
        self.assertEqual(first["last_batch"], 1)
        # the second names batch 1, the batch that holds the first cycle's decision
        v = self.cycle(self.trail)["dev"]
        h = self.read("dev")["audit_head"]
        self.assertEqual((h["log"].hex(), h["batch"], h["sha256"].hex()), (first["log"], 1, first["head"]))
        self.assertEqual(v["attestation_result"]["audit_head"], {"log": first["log"], "batch": 1,
                                                                 "sha256": first["head"]})
        ver = self.ver("dev")
        self.assertEqual((ver["aegis.audit-log"], ver["aegis.audit-batch"], ver["aegis.audit-head"]),
                         (bytes.fromhex(first["log"]), 1, bytes.fromhex(first["head"])))
        # the head lags: with min_interval_s the decision of this cycle waits, and the next result still names the
        # last batch on disk, not the one that will hold it
        self.trail.log.min_interval_s = 3600
        self.dev.edit = lambda c: c.update({273: [te.component("SPE", "99" * 32)]})
        self.cycle(self.trail)
        self.assertEqual(self.read("dev")["audit_head"]["batch"], audit.verify(self.adir, [self.vpk])["logs"][0]
                         ["last_batch"])
        self.assertTrue(self.trail.log.pending)                 # the refusal waits in memory
        # without an audit log, no head: the result is as in 1.1
        self.policy.pop("audit_log")
        self.cycle(None)
        self.assertIsNone(self.read("dev")["audit_head"])
        for k in ("aegis.audit-log", "aegis.audit-batch", "aegis.audit-head"):
            self.assertNotIn(k, self.ver("dev"))

    @NEEDS_LIBS
    def test_the_checker_finds_a_result_s_head_in_the_log(self):
        self.cycle(self.trail)
        no_head = self.keep("first.cbor")
        self.cycle(self.trail)
        steady = self.keep("steady.cbor")
        self.dev.edit = lambda c: c.update({273: [te.component("SPE", "99" * 32)]})
        self.cycle(self.trail)              # a decision that changed: logged, with its result, in the batch after
        changed = self.keep("changed.cbor")
        self.cycle(self.trail)
        after = self.keep("after.cbor")
        key = os.path.join(self.state, "identity.json")
        rc, rep = audit_checker("log", self.adir, "--key", key, "--result", steady, "--result", changed,
                                "--result", after)
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        a, b, c = rep["anchors"]
        self.assertEqual((a["batch"], b["batch"], c["batch"]), (1, 1, 2))
        self.assertIn("not in the log", a["decision"])          # the same decision: not logged again
        self.assertEqual((b["decision"]["event"], b["decision"]["subject"], b["decision"]["batch"]),
                         ("refuse", "dev", 2))
        self.assertIn("at or after", b["time_order"])
        # a result that names no head (the log's first, or 1.1's) is not one to check a log with
        rc, rep = audit_checker("log", self.adir, "--key", key, "--result", no_head)
        self.assertEqual(rc, 1, rep)
        self.assertIn("names no audit-log head", rep["reason"])
        # the log cut off before the head the result names
        recs = te_records(self.adir)
        cut = os.path.join(tempfile.mkdtemp(), "audit")
        os.makedirs(cut)
        with open(os.path.join(cut, "audit-000001.cbor"), "wb") as f:
            f.write(recs[0])
        rc, rep = audit_checker("log", cut, "--key", key, "--no-freshness", "--result", after)
        self.assertEqual(rc, 1, rep)
        self.assertIn("the end was cut off", rep["reason"])
        # the log replaced by another one of the same key
        shutil.rmtree(self.adir)
        trail = fleet.open_audit(self.policy, self.state, start={"cmd": "again"})
        self.cycle(trail)
        rc, rep = audit_checker("log", self.adir, "--key", key, "--result", steady)
        self.assertEqual(rc, 1, rep)
        self.assertIn("the log was replaced", rep["reason"])
        # a result signed by another key than the log's
        payload = cose.parse(open(changed, "rb").read()).payload
        forged = os.path.join(self.d, "forged.cbor")
        with open(forged, "wb") as f:
            f.write(cose.sign1(XSK, XPK, payload))
        rc, rep = audit_checker("log", self.adir, "--key", key, "--result", forged)
        self.assertEqual(rc, 1, rep)
        self.assertIn("not given", rep["reason"])
        # an audit batch given as a result is not one (typ)
        batch = os.path.join(self.d, "batch.cbor")
        with open(batch, "wb") as f:
            f.write(te_records(self.adir)[0])
        rc, rep = audit_checker("log", self.adir, "--key", key, "--result", batch)
        self.assertEqual(rc, 1, rep)
        self.assertIn("typ is not", rep["reason"])

    def test_the_audit_log_records_disabled_and_min_trust_decisions(self):
        self.cycle(self.trail)
        self.e["min_trust"] = "trustzone"
        self.save()
        self.cycle(self.trail)                                  # the floor is met: another decision all the same
        self.e["min_trust"] = "trustzone"
        self.policy["endpoints"].append(dict(self.e, name="els", port=EatDevice(platform="aegis-rw612-els-v1").port,
                                             pq_pub_file="keys/dev.pub", profile="aegis-rw612-els-v1"))
        self.save()
        self.cycle(self.trail)
        self.cycle(self.trail)                                  # refused for the same reason: no new entry
        self.e["disabled"] = True
        self.save()
        self.cycle(self.trail)
        self.cycle(self.trail)
        entries = audit.verify(self.adir, [self.vpk], with_entries=True)["entries"]
        mine = [(e["event"], e["subject"], e["details"].get("min_trust"), e["details"].get("disabled"),
                 tuple(e["details"].get("reasons", ()))) for e in entries if e["event"] in ("admit", "refuse")]
        self.assertEqual(mine, [
            ("admit", "dev", None, None, ()),
            ("admit", "dev", "trustzone", None, ()),
            ("refuse", "els", "trustzone", None, ("trust device-key below min_trust trustzone",)),
            ("refuse", "dev", None, True, ("disabled by policy",))])

    def test_looking_at_the_head_keeps_what_the_writer_must_say(self):
        """Log.head() runs before every signed result: a torn end it cuts off is still said in the next batch."""
        self.cycle(self.trail)
        seg = audit.segments(self.adir)[-1][1]
        with open(seg, "ab") as f:
            f.write(b"\xd2\x84\x58")                                # half a record: the process died writing
        self.assertEqual(self.trail.head()[1], 1)
        self.trail.log.add("start", None, {}, 1)
        with contextlib.redirect_stderr(io.StringIO()):
            self.trail.flush(final=True)
        events = [e["event"] for e in audit.verify(self.adir, [self.vpk], with_entries=True)["entries"]]
        self.assertIn("recovered", events)
        # and a log that has not begun yet: looking queues no "log-start" twice
        other = fleet.AuditTrail(te_state(self.vpk, self.vsk), fleet.AUDIT_SETTINGS, promise=False)
        self.assertIsNone(other.head())
        self.assertIsNone(other.head())
        other.log.add("start", None, {}, 1)
        with contextlib.redirect_stderr(io.StringIO()):
            other.flush(final=True)
        self.assertEqual([e["event"] for e in audit.verify(other.log.dir, [self.vpk], with_entries=True)["entries"]],
                         ["log-start", "start"])


def te_records(directory):
    out = []
    for _, path in audit.segments(directory):
        with open(path, "rb") as f:
            out += [raw for _, raw in audit.split(f.read())]
    return out


def te_state(pk, sk):
    state = tempfile.mkdtemp()
    with open(os.path.join(state, "identity.json"), "w") as f:
        json.dump({"body": {"v": 1, "type": "identity", "pk": pk.hex()}}, f)
    with open(os.path.join(state, "identity.sk"), "wb") as f:
        f.write(sk)
    return state


# ---- the signed pack -----------------------------------------------------------------------------------------------

class SignedPack(V12):
    def export(self, name="dev", *more):
        out = os.path.join(tempfile.mkdtemp(), "pack")
        rc, text = run(fleet.main, ["export-evidence", self.pol, name, "--out", out, "--state-dir", self.state,
                                    "--platform", "linux", *more])
        self.assertEqual(rc, 0, text)
        with open(os.path.join(out, "manifest.json"), "rb") as f:
            return out, f.read(), text

    def test_the_verifier_signs_the_manifest_and_the_export_time(self):
        self.add("dev", EatDevice())
        self.cycle()
        out, man_bytes, text = self.export()
        man = json.loads(man_bytes)
        self.assertEqual(man["signed_manifest"], "manifest.cose")
        self.assertIn("exported at %d (signed in manifest.cose)" % man["exported"], text)
        self.assertNotIn("manifest.cose", man["files"])
        with open(os.path.join(out, "manifest.cose"), "rb") as f:
            signed = f.read()
        # the document's bytes: typ, format, claims 1 to 5
        s = cose.verify1(signed, self.vpk, typ=PACK_TYP)
        c = cbor.loads(s.payload)
        with open(os.path.join(out, "attestation-result.cbor"), "rb") as f:
            result = f.read()
        self.assertEqual(c, {1: PACK_FORMAT, 2: "dev", 3: man["exported"], 4: hashlib.sha256(man_bytes).digest(),
                             5: hashlib.sha256(result).digest()})
        self.assertEqual(evidence_pack.read(signed, self.vpk, man_bytes, result)["exported"], man["exported"])
        # the result of the manifest: what the signed result says besides
        self.assertEqual(man["result"]["warnings"], self.read("dev")["warnings"])

    @NEEDS_LIBS
    def test_the_checker_reports_the_signed_export_time_and_refuses_a_bad_signature(self):
        self.add("dev", EatDevice())
        self.add("other", EatDevice(pk=te.PK2, sk=te.SK2))
        self.cycle()
        out, man_bytes, _ = self.export()
        other, _, _ = self.export("other")
        man = json.loads(man_bytes)
        trust = ["--verifier-key", thumb(self.vpk).hex(), "--device-key", thumb(te.PK).hex()]
        rc, rep = checker("pack", out, *trust, "--require-signed-export")
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        self.assertEqual((rep["export_time"]["time"], rep["export_time"]["signed"]), (man["exported"], True))
        self.assertEqual(rep["attestation_result"]["warnings"], self.read("dev")["warnings"])

        def changed(edit, *more):
            d = os.path.join(tempfile.mkdtemp(), "pack")
            shutil.copytree(out, d)
            edit(d)
            rc, rep = checker("pack", d, *trust, *more)
            self.assertEqual((rc, rep["verified"]), (1, False), rep)
            return rep["reason"]

        def manifest(edit):
            def f(d):
                with open(os.path.join(d, "manifest.json")) as fh:
                    m = json.load(fh)
                edit(m)
                with open(os.path.join(d, "manifest.json"), "w") as fh:
                    json.dump(m, fh, indent=1)
            return f

        def put(data):
            def f(d):
                with open(os.path.join(d, "manifest.cose"), "wb") as fh:
                    fh.write(data)
            return f
        # the export time moved, or the manifest written again
        self.assertIn("not the manifest the verifier signed", changed(manifest(lambda m: m.update(exported=1))))
        self.assertIn("not the manifest the verifier signed", changed(manifest(lambda m: None)))
        # the signature itself: a bit flipped, another pack's, another key's, another object of the same key
        with open(os.path.join(out, "manifest.cose"), "rb") as f:
            signed = f.read()
        flipped = bytearray(signed)
        flipped[200] ^= 1
        self.assertIn("does not verify", changed(put(bytes(flipped))))
        self.assertIn("not the manifest the verifier signed", changed(lambda d: shutil.copy(
            os.path.join(other, "manifest.cose"), os.path.join(d, "manifest.cose"))))
        payload = cose.parse(signed).payload
        self.assertIn("kid is not", changed(put(cose.sign1(XSK, XPK, payload, typ=PACK_TYP))))
        self.assertIn("typ is not", changed(put(cose.sign1(self.vsk, self.vpk, payload))))
        self.assertIn("typ is not", changed(lambda d: shutil.copy(os.path.join(d, "attestation-result.cbor"),
                                                                    os.path.join(d, "manifest.cose"))))
        c = cbor.loads(payload)
        for edit in ({6: 1}, {1: "x"}, {3: -1}, {3: "now"}, {2: ""}, {4: bytes(31)}, {5: None}):
            bad = {**c, **edit}
            self.assertIn("pack signature", changed(put(cose.sign1(self.vsk, self.vpk, cbor.dumps(bad, sort=True),
                                                                   typ=PACK_TYP))), edit)
            with self.assertRaises(evidence_pack.Refused):
                evidence_pack.read(cose.sign1(self.vsk, self.vpk, cbor.dumps(bad, sort=True), typ=PACK_TYP), self.vpk)
        # the signature removed while the manifest still names it
        self.assertIn("names manifest.cose and the pack has none",
                      changed(lambda d: os.remove(os.path.join(d, "manifest.cose"))))
        self.assertIn("other than manifest.cose", changed(manifest(lambda m: m.update(signed_manifest="../x"))))

    @NEEDS_LIBS
    def test_a_pack_without_a_signature_verifies_and_says_its_time_is_not_signed(self):
        """A pack exported by Aegis 1.1 (no manifest.cose, no "signed_manifest")."""
        self.add("dev", EatDevice())
        self.cycle()
        out, man_bytes, _ = self.export()
        os.remove(os.path.join(out, "manifest.cose"))
        man = json.loads(man_bytes)
        del man["signed_manifest"]
        with open(os.path.join(out, "manifest.json"), "w") as f:
            json.dump(man, f, indent=1)
        trust = ["--verifier-key", thumb(self.vpk).hex(), "--device-key", thumb(te.PK).hex()]
        rc, rep = checker("pack", out, *trust)
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        self.assertEqual((rep["export_time"]["time"], rep["export_time"]["signed"]), (man["exported"], False))
        self.assertIn("export time not signed", rep["export_time"]["note"])
        rc, rep = checker("pack", out, *trust, "--require-signed-export")
        self.assertEqual((rc, rep["verified"]), (1, False), rep)
        self.assertIn("not signed", rep["reason"])

    def test_one_key_three_objects_none_taken_for_another(self):
        """The verifier's key signs results, audit batches and pack statements: each reader requires its own typ."""
        self.add("dev", EatDevice())
        self.cycle()
        out, man_bytes, _ = self.export()
        with open(os.path.join(out, "manifest.cose"), "rb") as f:
            signed = f.read()
        result = self.result("dev")
        with self.assertRaises(cose.Refused):
            eat.read_ear(signed, self.vpk)
        with self.assertRaises((cose.Refused, audit.Refused)):
            audit.open_batch(signed, self.vpk)
        with self.assertRaises((cose.Refused, evidence_pack.Refused)):
            evidence_pack.read(result, self.vpk)
        lg = audit.Log(os.path.join(tempfile.mkdtemp(), "a"), self.vpk, lambda: self.vsk)
        lg.add("start", None, {}, 1)
        batch = lg.flush(1)[0].raw
        with self.assertRaises((cose.Refused, evidence_pack.Refused)):
            evidence_pack.read(batch, self.vpk)
        for junk in (b"", b"\xd2", signed[:-1], signed + b"\x00", cbor.dumps([1, 2]), mldsa.keypair()[0]):
            with self.assertRaises((cose.Refused, evidence_pack.Refused)):
                evidence_pack.read(junk, self.vpk)


# ---- what 1.1 readers make of what 1.2 writes --------------------------------------------------------------------------

class Compatibility(V12):
    def everything(self):
        """A 1.2 result with every new claim, and its pack."""
        self.policy["audit_log"] = True
        self.add("dev", EatDevice(platform="aegis-rw612-els-v1"), min_trust="device-key")
        trail = fleet.open_audit(self.policy, self.state, start={"cmd": "test"})
        self.cycle(trail)
        self.cycle(trail)
        r = self.read("dev")
        self.assertTrue(r["audit_head"] and r["warnings"] and r["min_trust"])
        return r

    def test_the_1_1_result_reader_accepts_a_1_2_result(self):
        path = v11("common/eat.py")
        if path is None:
            self.skipTest("git does not have the tag v1.1.0 here")
        import importlib.util
        spec = importlib.util.spec_from_file_location("eat_v11", path)
        old = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(old)
        self.everything()
        r = old.read_ear(self.result("dev"), self.vpk)
        self.assertEqual((r["status"], r["admitted"]), ("warning", True))
        self.assertIn("aegis.audit-head", r["verifier_claims"])
        # a disabled entry's result too
        self.e = self.policy["endpoints"][0]
        self.e["disabled"] = True
        self.save()
        self.cycle()
        self.assertEqual(old.read_ear(self.result("dev"), self.vpk)["status"], "incomplete")

    @NEEDS_LIBS
    def test_the_1_1_checker_verifies_a_1_2_pack_and_the_1_2_checker_a_1_1_result(self):
        path = v11("tools/verify_evidence.py")
        if path is None:
            self.skipTest("git does not have the tag v1.1.0 here")
        self.everything()
        out = os.path.join(tempfile.mkdtemp(), "pack")
        rc, text = run(fleet.main, ["export-evidence", self.pol, "dev", "--out", out, "--state-dir", self.state,
                                    "--platform", "linux"])
        self.assertEqual(rc, 0, text)
        r = subprocess.run([sys.executable, "-I", path, "pack", out, "--verifier-key", thumb(self.vpk).hex()],
                           capture_output=True, text=True, cwd=tempfile.gettempdir())
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertTrue(json.loads(r.stdout)["verified"])
        # a result as 1.1 wrote it (none of the new claims) reads in 1.2 with them absent
        payload = cbor.loads(cose.parse(self.result("dev")).payload)
        ver = next(iter(payload[266].values()))[1006]
        for k in ("aegis.audit-log", "aegis.audit-batch", "aegis.audit-head", "aegis.warnings", "aegis.min-trust"):
            del ver[k]
        old = cose.sign1(self.vsk, self.vpk, cbor.dumps(payload, sort=True))
        r = eat.read_ear(old, self.vpk)
        self.assertEqual((r["audit_head"], r["warnings"], r["disabled"], r["min_trust"]), (None, None, False, None))
        p = os.path.join(self.d, "old.cbor")
        with open(p, "wb") as f:
            f.write(old)
        with open(os.path.join(self.d, "v.pub"), "w") as f:
            f.write(self.vpk.hex())
        rc, rep = checker("result", p, "--key", os.path.join(self.d, "v.pub"))
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        self.assertNotIn("audit_head", rep)

    def test_a_policy_without_the_new_keys_runs_as_before(self):
        self.add("dev", EatDevice())
        v = self.cycle()["dev"]
        for k in ("disabled", "min_trust"):
            self.assertNotIn(k, v)
        self.assertNotIn("audit_head", v["attestation_result"])
        ver = self.ver("dev")
        for k in ("aegis.audit-log", "aegis.audit-batch", "aegis.audit-head", "aegis.disabled", "aegis.min-trust"):
            self.assertNotIn(k, ver)


if __name__ == "__main__":
    unittest.main()
