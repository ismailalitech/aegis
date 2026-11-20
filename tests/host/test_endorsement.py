# SPDX-License-Identifier: Apache-2.0
"""Endorsed enrolment (docs/enrolment.md): the provisioning tool, the record, the verifier's rules and the commit.

Simulated endpoints (no hardware): the provisioning tool (provision/aegis_provision.py) endorses a device over the
line protocol, `fleet.py enroll-endorsed` installs the record, and the fleet verifier's own code decides.

  accepted   an endorsed key; a second verifier with the same record; a full cycle with a session
  refused    no record; a substituted key file (and the same swap is admitted under trust on first use: the control);
             a device that does not hold the endorsed key; a record from an endorser the policy does not list, or a
             revoked one; a record altered in any field or in its signature; an expired record; the record of
             another device or family; a quote whose components are not the endorsed ones, or lack one
  enrolment  a device that fails appraisal, a record that cannot be written, an install that fails between its two
             files: no trusted entry, no half-written file; a failed re-enrolment leaves the old one in force
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from unittest import mock

os.environ.setdefault("TSS2_LOG", "all+NONE")
ROOT = os.path.join(os.path.dirname(__file__), "..", "..")
for p in ("common", "gateway/aegisd", "provision", "tests/host"):
    sys.path.insert(0, os.path.abspath(os.path.join(ROOT, p)))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import aegis_provision as prov  # noqa: E402
import cbor  # noqa: E402
import endorsement  # noqa: E402
import fleet  # noqa: E402
import keystore  # noqa: E402
import mldsa  # noqa: E402
import psa_token  # noqa: E402
import test_fleet as tf  # noqa: E402
import test_gateway_hardening as th  # noqa: E402
import test_rw612_proto as rw  # noqa: E402

VERIFY = psa_token.verify_with_cryptography
OTHER_NS = "99" * 32          # what FakeEndpoint reports as NSPE in mode pq-tampered
ALLOWED = [{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
           {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}]


class PlainDevice:
    """A plain-claims device (the RW612, the ZynqMP TA): PQKEY, and PQCHAL answered with ML-DSA-65-signed CBOR claims.
    Counts the requests it gets."""

    def __init__(self, profile, claims_edit=None):
        import socket
        import threading
        self.profile, self.claims_edit, self.asked = profile, claims_edit, 0
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(4)
        self.port = self.srv.getsockname()[1]
        threading.Thread(target=self.loop, daemon=True).start()

    def loop(self):
        while True:
            c, _ = self.srv.accept()
            with c:
                line = c.recv(4096).split(b"\n")[0].decode()
                self.asked += 1
                if line == "PQKEY":
                    c.sendall(b"PQKEY %d %s END\r\n" % (len(th.PK), th.PK.hex().encode()))
                    continue
                claims = {265: self.profile, 10: bytes.fromhex(line.split()[1]), 256: b"\x02" + b"\x55" * 32,
                          2399: [{1: "BOOTCHAIN", 2: bytes.fromhex(th.MEAS)}]}
                if self.claims_edit:
                    self.claims_edit(claims)
                tok = cbor.dumps(claims)
                sig = mldsa.sign(th.SK, fleet.PQ_LABEL, tok)
                c.sendall(b"PQTOKEN %d %s %d %s END\r\n" % (len(tok), tok.hex().encode(), len(sig), sig.hex().encode()))


def closed_port():
    import socket
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def run(main, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(argv)
    return rc, out.getvalue()


def snapshot(d):
    out = {}
    for r, _, files in os.walk(d):
        for n in files:
            with open(os.path.join(r, n), "rb") as f:
                out[os.path.join(r, n)] = f.read()
    return out


def tmp_files(*dirs):
    return [os.path.join(r, n) for d in dirs for r, _, files in os.walk(d) for n in files if ".tmp." in n]


class Bench(unittest.TestCase):
    """One endorser, two devices with different keys and the same firmware, one verifier policy directory."""

    @classmethod
    def setUpClass(cls):
        cls.iak = ec.generate_private_key(ec.SECP256R1())
        cls.estate = tempfile.mkdtemp()
        prov.init(cls.estate, "bench", key_store="software")      # never this PC's TPM in a test
        cls.endorser = prov.Endorser(cls.estate)

    def setUp(self):
        self.d = tempfile.mkdtemp()                               # the verifier's policy directory
        self.out = tempfile.mkdtemp()                             # where the endorser leaves its records
        with open(os.path.join(self.d, "iak.pem"), "wb") as f:
            f.write(self.iak.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
        self.dev_a, self.dev_b = tf.FakeEndpoint(self.iak, "pq-good"), tf.FakeEndpoint(self.iak, "pq-good")
        self.dev_b.pq_pk, self.dev_b.pq_sk = tf.PQ_KEYS[1]
        self.dev_b.pq_other_sk = tf.PQ_KEYS[0][1]
        run(prov.main, ["export", os.path.join(self.d, "endorsers"), "--state", self.estate])
        self.policy = {"timeout_s": 5, "endorsers": [self.endorser.policy_entry()],
                       "endpoints": [self.entry("dev-a", self.dev_a), self.entry("dev-b", self.dev_b)]}
        self.save()

    def entry(self, name, dev, **kw):
        e = {"name": name, "kind": "aegis-pq", "host": "127.0.0.1", "port": dev.port, "iak_pub_pem": "iak.pem",
             "pq_pub_file": "keys/%s.mldsa65.pub" % name, "allowed": [dict(a) for a in ALLOWED],
             "endorsement": "required"}
        e.update(kw)
        return e

    def save(self):
        self.pol = os.path.join(self.d, "fleet.json")
        with open(self.pol, "w") as f:
            json.dump(self.policy, f)

    def ep(self, name="dev-a"):
        return next(e for e in self.policy["endpoints"] if e["name"] == name)

    def endorse(self, name="dev-a", endorser=None, **kw):
        res = prov.endorse(endorser or self.endorser, self.ep(name), self.d, self.out, ecdsa_verify=VERIFY, **kw)
        return res

    def enrol(self, name="dev-a", **kw):
        res = self.endorse(name, **kw)
        self.assertTrue(res["endorsed"], res)
        fleet.install_endorsement(self.policy, self.d, res["record"])
        return res

    def attest(self, name="dev-a", **edit):
        return fleet.attest(dict(self.ep(name), **edit), VERIFY, self.d, 5, self.policy.get("endorsers"))

    def record_path(self, name="dev-a"):
        return os.path.join(self.d, "endorsements", "%s.json" % name)

    def key_path(self, name="dev-a"):
        return os.path.join(self.d, "keys", "%s.mldsa65.pub" % name)

    def edit_record(self, fn, name="dev-a"):
        with open(self.record_path(name)) as f:
            rec = json.load(f)
        fn(rec)
        with open(self.record_path(name), "w") as f:
            json.dump(rec, f)

    def assertRefused(self, v, text):
        self.assertFalse(v["admitted"], v)
        self.assertTrue(any(text in r for r in v["reasons"]), v["reasons"])


class Accepted(Bench):
    def test_endorsed_key_is_admitted_and_the_enrolment_is_fast(self):
        res = self.endorse(serial="ST-LINK 0042", notes="bench, direct cable")
        self.assertTrue(res["endorsed"], res)
        self.assertLess(res["elapsed_s"], 60)
        self.assertEqual(os.listdir(self.out), ["dev-a.json"])
        rc, out = run(fleet.main, ["enroll-endorsed", self.pol, res["record"]])
        self.assertEqual(rc, 0, out)
        self.assertIn("enrolled dev-a", out)
        v = self.attest()
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["enrolment"], "endorsed")
        e = v["endorsement"]
        self.assertEqual((e["endorser_name"], e["device_state"], e["serial"]), ("bench", "development", "ST-LINK 0042"))
        self.assertEqual(e["device_pk_sha256"], endorsement.pk_sha256(tf.PQ_KEYS[0][0]))
        self.assertEqual(e["record_sha256"], res["record_sha256"])
        self.assertIn("[endorsed by bench]", fleet.journal_line(v)[0])

    def test_the_record_says_what_was_appraised(self):
        res = self.endorse(serial="A1", valid_days=30)
        with open(res["record"], "rb") as f:
            data = f.read()
        rec = endorsement.loads(data)
        b = rec["body"]
        self.assertEqual((b["v"], b["type"], b["device"], b["kind"], b["serial"]), (1, "endorsement", "dev-a",
                                                                                   "aegis-pq", "A1"))
        self.assertNotIn("profile", b)                 # aegis-pq: the family is the kind
        self.assertEqual(b["measurements"], sorted(ALLOWED, key=lambda m: m["type"]))
        self.assertEqual(b["endorser_pk_sha256"], self.endorser.pk_sha256)
        self.assertEqual(b["expires"] - b["issued"], 30 * 86400)
        self.assertEqual(bytes.fromhex(rec["device_pk"]), tf.PQ_KEYS[0][0])
        self.assertEqual(len(b["evidence"]["challenge"]), 64)
        self.assertLess(len(data), endorsement.MAX_RECORD)
        # the ledger has the signature that was made
        with open(os.path.join(self.estate, prov.LEDGER)) as f:
            last = json.loads(f.read().splitlines()[-1])
        self.assertEqual((last["device"], last["record_sha256"], last["serial"]), ("dev-a", res["record_sha256"], "A1"))

    def test_a_cycle_gives_the_endorsed_endpoint_a_session(self):
        self.dev_a.mode = "kem-good"
        self.enrol()
        self.ep()["provision"] = True
        gw_pk, gw_sk = mldsa.keypair()
        state = tempfile.mkdtemp()
        with open(os.path.join(state, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "identity", "pk": gw_pk.hex()}}, f)
        with open(os.path.join(state, "identity.sk"), "wb") as f:
            f.write(gw_sk)
        pol = dict(self.policy, endpoints=[self.ep()])
        v, = fleet.run_once(pol, self.d, VERIFY, state=state)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertTrue(v["credential"].startswith("issued session"), v["credential"])
        v, = fleet.run_once(pol, self.d, VERIFY, state=state)
        self.assertTrue(v["credential"].startswith("valid, heartbeat"), v["credential"])
        # the record goes: the next cycle quarantines and revokes, without an exchange
        os.unlink(self.record_path())
        v, = fleet.run_once(pol, self.d, VERIFY, state=state)
        self.assertRefused(v, "no endorsement record")
        self.assertEqual(v["credential"], "revoked")
        self.assertFalse(os.path.exists(os.path.join(state, "credentials", "dev-a.session")))

    def test_a_session_goes_only_to_the_key_the_quote_was_verified_with(self):
        self.dev_a.mode = "kem-good"
        self.enrol()
        sk = mldsa.keypair()[1]
        trust = {"endorsers": self.policy["endorsers"]}
        v = self.attest()
        self.assertTrue(v["admitted"], v["reasons"])
        with self.assertRaises(ValueError) as c:       # provision() checks the endorsement itself
            fleet.provision(self.ep(), self.d, sk, "gid", {}, timeout=5)
        self.assertIn("no trusted endorsers", str(c.exception))
        with self.assertRaises(ValueError) as c:
            fleet.provision(self.ep(), self.d, sk, "gid", {}, timeout=5, expect_pk_sha256="00" * 32, **trust)
        self.assertIn("pinned key changed", str(c.exception))
        r = fleet.provision(self.ep(), self.d, sk, "gid", {}, timeout=5,
                            expect_pk_sha256=v["device_pk_sha256"], **trust)
        self.assertEqual(len(r["session_key"]), 32)

    def test_plain_claims_family_end_to_end(self):
        dev = PlainDevice(fleet.TEE_PROFILE)
        e = {"name": "zynq", "kind": "aegis-tee", "profile": fleet.TEE_PROFILE, "host": "127.0.0.1",
             "port": dev.port, "pq_pub_file": "keys/zynq.pub", "endorsement": "required",
             "allowed": [{"type": "BOOTCHAIN", "measurement_value": th.MEAS}]}
        self.policy["endpoints"].append(e)
        res = self.enrol("zynq")
        self.assertEqual(res["family"], "aegis-tee/" + fleet.TEE_PROFILE)
        v = self.attest("zynq")
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual((v["trust"], v["enrolment"]), ("trustzone", "endorsed"))
        # the same record under an entry of another family: refused before the device is asked
        asked = dev.asked
        v = self.attest("zynq", kind="aegis-device", profile=fleet.DEVICE_TFM_PROFILE)
        self.assertRefused(v, "the record endorses family aegis-tee/")
        self.assertEqual(dev.asked, asked)


class Refused(Bench):
    def test_unendorsed_key_is_refused_without_asking_the_device(self):
        os.makedirs(os.path.join(self.d, "keys"))
        with open(self.key_path(), "w") as f:           # the key as trust on first use left it
            f.write(tf.PQ_KEYS[0][0].hex() + "\n")
        dev = PlainDevice(fleet.TEE_PROFILE)            # counts what it is asked
        v = self.attest(port=dev.port)
        self.assertRefused(v, "endorsement required: no endorsement record")
        self.assertEqual((v["enrolment"], dev.asked), ("refused", 0))
        self.assertNotIn("[endorsed", fleet.journal_line(v)[0])
        # without the key in the entry: today's behaviour, and the verdict says which
        v = fleet.attest({k: x for k, x in self.ep().items() if k != "endorsement"}, VERIFY, self.d, 5)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["enrolment"], "trust-on-first-use")
        self.assertIn("[trust on first use]", fleet.journal_line(v)[0])

    def test_substituted_key_is_refused(self):
        self.enrol("dev-a")
        self.enrol("dev-b")
        with open(self.key_path("dev-b")) as f:
            key_b = f.read()
        with open(self.key_path("dev-a"), "w") as f:    # someone who can write the key file swaps the key
            f.write(key_b)
        v = self.attest("dev-a")
        self.assertRefused(v, "substituted key")
        # ... and redirects the entry to the device that holds that key
        v = self.attest("dev-a", port=self.dev_b.port)
        self.assertRefused(v, "substituted key")
        # ... and brings that device's own, genuine record along
        with open(self.record_path("dev-b")) as f, open(self.record_path("dev-a"), "w") as g:
            g.write(f.read())
        v = self.attest("dev-a", port=self.dev_b.port)
        self.assertRefused(v, "the record endorses device 'dev-b', not 'dev-a'")

    def test_the_same_substitution_is_admitted_under_trust_on_first_use(self):
        """The control: what the endorsement is for. Same key swap, same redirect, an entry without the key."""
        self.enrol("dev-a")
        self.enrol("dev-b")
        with open(self.key_path("dev-b")) as f, open(self.key_path("dev-a"), "w") as g:
            g.write(f.read())
        tofu = {k: x for k, x in self.ep("dev-a").items() if k != "endorsement"}
        v = fleet.attest(dict(tofu, port=self.dev_b.port), VERIFY, self.d, 5)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual(v["enrolment"], "trust-on-first-use")

    def test_a_device_without_the_endorsed_key_is_refused(self):
        self.enrol("dev-a")
        v = self.attest("dev-a", port=self.dev_b.port)      # another genuine device at the address
        self.assertRefused(v, "ML-DSA-65 quote signature invalid (the device that answered does not hold the endorsed")
        self.assertEqual(v["enrolment"], "endorsed")

    def test_untrusted_endorser_is_refused(self):
        state = tempfile.mkdtemp()
        prov.init(state, "rogue", key_store="software")
        rogue = prov.Endorser(state)
        res = self.endorse(endorser=rogue)                  # a well-formed record, signed by a key nobody trusts
        self.assertTrue(res["endorsed"], res)
        rc, out = run(fleet.main, ["enroll-endorsed", self.pol, res["record"]])
        self.assertEqual(rc, 1)
        self.assertIn("not a trusted endorser", out)
        self.assertFalse(os.path.exists(self.record_path()) or os.path.exists(self.key_path()))
        # put in place by hand, it is still refused by the loop
        os.makedirs(os.path.dirname(self.record_path()))
        os.makedirs(os.path.dirname(self.key_path()))
        with open(res["record"]) as f, open(self.record_path(), "w") as g:
            g.write(f.read())
        with open(self.key_path(), "w") as f:
            f.write(tf.PQ_KEYS[0][0].hex())
        self.assertRefused(self.attest(), "not a trusted endorser")
        # the rogue calling itself "bench" changes nothing: the key decides, not the name
        self.edit_record(lambda r: r["body"].update(endorser="bench"))
        self.assertRefused(self.attest(), "not a trusted endorser")
        # and a policy with no list at all trusts nobody
        v = fleet.attest(self.ep(), VERIFY, self.d, 5)
        self.assertRefused(v, "the policy lists no trusted endorsers")

    def test_revoked_endorser_is_refused(self):
        self.enrol()
        self.assertTrue(self.attest()["admitted"])
        self.policy["endorsers"][0]["revoked"] = True
        self.assertRefused(self.attest(), "endorser bench is revoked")

    def test_endorser_key_file_that_is_not_the_pinned_key_is_refused(self):
        self.enrol()
        with open(os.path.join(self.d, self.policy["endorsers"][0]["pk_file"]), "w") as f:
            f.write(mldsa.keypair()[0].hex())
        self.assertRefused(self.attest(), "is not the key the policy pins")
        self.policy["endorsers"] = [{"name": "bench", "pk_file": "endorsers/bench.mldsa65.pub"}]      # no pin
        self.assertRefused(self.attest(), '"endorsers" is not {name, pk_file, pk_sha256')

    def test_tampered_record_is_refused(self):
        self.enrol()
        with open(self.record_path()) as f:
            good = f.read()
        other = endorsement.pk_sha256(tf.PQ_KEYS[1][0])

        def flip_sig(r):
            r["sig"] = r["sig"][:100] + ("0" if r["sig"][100] != "0" else "1") + r["sig"][101:]
        edits = {
            "another key": lambda r: r["body"].update(device_pk_sha256=other),
            "another device": lambda r: r["body"].update(device="dev-b"),
            "another measurement": lambda r: r["body"]["measurements"][0].update(measurement_value=OTHER_NS),
            "a later expiry": lambda r: r["body"].update(expires=r["body"]["issued"] + 10 ** 9),
            "another state": lambda r: r["body"].update(device_state="closed"),
            "a new claim": lambda r: r["body"].update(valid_everywhere=True),
            "another version": lambda r: r["body"].update(v=1.0),
            "no signature": lambda r: r.pop("sig"),
            "a flipped signature": flip_sig,
            "another format": lambda r: r.update(format="aegis-endorsement-v0"),
        }
        for what, fn in edits.items():
            with open(self.record_path(), "w") as f:
                f.write(good)
            self.edit_record(fn)
            v = self.attest()
            self.assertRefused(v, "endorsement required")
            self.assertEqual(v["enrolment"], "refused", what)
        for junk in (b"", b"{", b"[]", b"null", b'{"format":"aegis-endorsement-v1"}', b"\xff" * 40,
                     b"[" * 100000, b"[" * 60000, b"{" + b" " * endorsement.MAX_RECORD + b"}"):
            with open(self.record_path(), "wb") as f:
                f.write(junk)
            self.assertRefused(self.attest(), "endorsement required")
        with open(self.record_path(), "w") as f:
            f.write(good)
        self.assertTrue(self.attest()["admitted"])

    def test_a_signature_made_for_something_else_is_not_an_endorsement(self):
        """The label: the endorser's key signing the same bytes as a credential or an identity is not accepted."""
        self.enrol()
        with open(self.record_path()) as f:
            rec = json.load(f)
        import wire
        for label in (fleet.CRED_LABEL, wire.LABEL_IDENTITY, endorsement.ENDORSER_LABEL, fleet.PQ_LABEL):
            sig = mldsa.sign(self.endorser.sk, label, wire.canonical(rec["body"]))
            self.edit_record(lambda r: r.update(sig=sig.hex()))
            self.assertRefused(self.attest(), "does not verify")

    def test_a_claim_this_version_does_not_know_is_refused_even_when_signed(self):
        """A later endorser may add a restriction; a verifier that ignored it would trust more than was signed."""
        self.enrol()
        import wire

        def add(r):
            r["body"]["only_for_verifier"] = "someone-else"
            r["sig"] = mldsa.sign(self.endorser.sk, endorsement.LABEL, wire.canonical(r["body"])).hex()
        self.edit_record(add)
        self.assertRefused(self.attest(), "keys this verifier does not know: only_for_verifier")

    def test_expired_record_is_refused(self):
        res = self.enrol(valid_days=1)
        with open(res["record"]) as f:
            issued = json.load(f)["body"]["issued"]
        trust = self.policy["endorsers"]
        pk, e = fleet.device_key(self.ep(), self.d, trust, now=issued + 86399)
        self.assertEqual(e["expires"], issued + 86400)
        with self.assertRaises(endorsement.Refused) as c:
            fleet.device_key(self.ep(), self.d, trust, now=issued + 86400)
        self.assertIn("expired", str(c.exception))
        with mock.patch.object(fleet.time, "time", return_value=issued + 86400.0):
            self.assertRefused(self.attest(), "the endorsement expired")
        self.assertTrue(self.attest()["admitted"])

    def test_quote_must_report_the_endorsed_components(self):
        self.enrol()
        # other firmware, and a policy that has been made to allow it: the endorsement still does not
        self.dev_a.mode = "pq-tampered"
        self.ep()["allowed"].append({"type": "NSPE", "measurement_value": OTHER_NS, "signer_id": tf.SIGNER})
        v = self.attest()
        self.assertRefused(v, "endorsement: component NSPE is not the endorsed one")
        self.assertEqual(len(v["reasons"]), 1)          # the policy's own list would have admitted it
        tofu = {k: x for k, x in self.ep().items() if k != "endorsement"}
        self.assertTrue(fleet.attest(tofu, VERIFY, self.d, 5)["admitted"])

    def test_quote_that_leaves_out_an_endorsed_component_is_refused(self):
        second = {1: "APP", 2: bytes.fromhex("cd" * 32)}
        dev = PlainDevice(fleet.TEE_PROFILE, lambda c: c[2399].append(second))
        e = {"name": "zynq", "kind": "aegis-tee", "profile": fleet.TEE_PROFILE, "host": "127.0.0.1",
             "port": dev.port, "pq_pub_file": "keys/zynq.pub", "endorsement": "required",
             "allowed": [{"type": "BOOTCHAIN", "measurement_value": th.MEAS},
                         {"type": "APP", "measurement_value": "cd" * 32}]}
        self.policy["endpoints"].append(e)
        self.enrol("zynq")
        self.assertTrue(self.attest("zynq")["admitted"])
        dev.claims_edit = None                          # the quote now reports BOOTCHAIN alone
        v = self.attest("zynq")
        self.assertRefused(v, "endorsement: endorsed component APP is not in the quote")
        dev.claims_edit = lambda c: c[2399].append({1: "EXTRA", 2: b"\x01" * 32})
        self.ep("zynq")["allowed"].append({"type": "EXTRA", "measurement_value": "01" * 32})
        self.assertRefused(self.attest("zynq"), "endorsement: component 'EXTRA' is not in the endorsement")

    def test_policy_values_that_must_not_fall_back(self):
        e = {"name": "x", "kind": "aegis-pq", "pq_pub_file": "k"}
        self.assertEqual(fleet.policy_errors(dict(e, endorsement="required")), [])
        for bad in ("requird", "optional", True, 1, ""):
            self.assertIn("unknown endorsement", " ".join(fleet.policy_errors(dict(e, endorsement=bad))), bad)
        self.assertIn("needs a post-quantum kind",
                      " ".join(fleet.policy_errors({"name": "u", "kind": "psa", "iak_pub_pem": "p",
                                                    "endorsement": "required"})))
        dev = {"name": "z", "kind": "aegis-tee", "pq_pub_file": "k", "profile": fleet.TEE_DEVHUK_PROFILE,
               "allow_dev_profile": True, "endorsement": "required"}
        self.assertIn("one key for every chip", " ".join(fleet.policy_errors(dev)))

    def test_enroll_pq_does_not_take_an_endorsed_entry_s_key_from_the_network(self):
        rc, out = run(fleet.main, ["enroll-pq", self.pol])
        self.assertEqual(rc, 0)
        self.assertIn("skipped dev-a", out)
        self.assertFalse(os.path.exists(self.key_path()))
        rc, out = run(fleet.main, ["enroll-pq", self.pol, "--force"])
        self.assertFalse(os.path.exists(self.key_path()))

    def test_check_reports_the_enrolment_of_each_entry(self):
        self.enrol("dev-a")
        tofu = {k: x for k, x in self.ep("dev-b").items() if k != "endorsement"}
        self.policy["endpoints"] = [self.ep("dev-a"), dict(tofu, name="dev-c")]
        self.save()
        rc, out = run(fleet.main, ["check", self.pol, "--platform", "linux", "--state-dir", tempfile.mkdtemp()])
        self.assertEqual(rc, 0, out)
        self.assertIn("enrolment: endorsed by bench", out)
        self.assertIn("device state development", out)
        self.assertIn("enrolment: trust on first use", out)
        os.unlink(self.record_path("dev-a"))
        rc, out = run(fleet.main, ["check", self.pol, "--platform", "linux", "--state-dir", tempfile.mkdtemp()])
        self.assertEqual(rc, 1, out)
        self.assertIn("enrolment: endorsement REFUSED: no endorsement record", out)


class Review(Bench):
    """Findings of the review of step 8, each with the test that would have caught it."""

    def test_names_that_reach_outside_their_directory_are_refused(self):
        self.enrol()
        with open(self.record_path()) as f:
            rec = json.load(f)
        import wire
        outside = os.path.join(os.path.dirname(self.d), "escaped.json")
        there = os.path.exists(outside) and os.stat(outside).st_mtime_ns
        for bad in ("../escaped", ".hidden", "a/b", "a\\b", "", "x" * 65, "dev a", "..", "dev\n"):
            body = dict(rec["body"], device=bad)
            with self.assertRaises(endorsement.Refused, msg=bad):
                endorsement.check_body(body)
            signed = dict(rec, body=body, sig=mldsa.sign(self.endorser.sk, endorsement.LABEL,
                                                          wire.canonical(body)).hex())
            path = os.path.join(self.out, "bad.json")
            with open(path, "w") as f:
                json.dump(signed, f)
            with self.assertRaises(endorsement.Refused):          # signed by the trusted endorser, still refused
                fleet.install_endorsement(self.policy, self.d, path)
            self.assertIn("is not a name", " ".join(fleet.policy_errors(dict(self.ep(), name=bad))), bad)
        self.assertEqual(there, os.path.exists(outside) and os.stat(outside).st_mtime_ns)
        for good in ("dev-a", "stm32h573-dk-2", "frdm-rw612", "a.b_c", "x" * 64):
            self.assertTrue(endorsement.is_name(good), good)
            self.assertEqual(fleet.policy_errors(dict(self.ep(), name=good)), [], good)
        # a policy entry named so: refused, and the credential step touches no file of that name
        state = tempfile.mkdtemp()
        v = fleet.attest(dict(self.ep(), name="../escaped"), VERIFY, self.d, 5, self.policy["endorsers"])
        self.assertRefused(v, "is not a name")
        cs = fleet.credential_step(dict(self.ep(), name="../escaped", provision=True), v, self.d, state=state)
        self.assertIn("not a file name", cs)

    def test_duplicate_keys_and_non_numbers_are_not_json(self):
        self.enrol()
        with open(self.record_path(), "rb") as f:
            good = f.read()
        endorsement.loads(good)
        dup = good.replace(b'"format":', b'"format": "aegis-endorsement-v1", "format":', 1)
        self.assertNotEqual(dup, good)
        body_dup = good.replace(b'"device":', b'"device": "dev-b", "device":', 1)
        for data in (dup, body_dup, good.replace(b'"issued": ', b'"issued": NaN, "x": ', 1),
                     good.replace(b'"issued": ', b'"issued": Infinity, "y": ', 1), b'{"a": -Infinity}'):
            with self.assertRaises(endorsement.Refused) as c:
                endorsement.loads(data)
            self.assertIn("not JSON", str(c.exception))
            with open(self.record_path(), "wb") as f:
                f.write(data)
            self.assertRefused(self.attest(), "not JSON")

    def test_a_record_of_the_same_kind_but_another_profile_is_refused(self):
        dev = PlainDevice(fleet.DEVICE_PROFILE)
        e = {"name": "rw", "kind": "aegis-device", "profile": fleet.DEVICE_PROFILE, "host": "127.0.0.1",
             "port": dev.port, "pq_pub_file": "keys/rw.pub", "endorsement": "required",
             "allowed": [{"type": "BOOTCHAIN", "measurement_value": th.MEAS}]}
        self.policy["endpoints"].append(e)
        self.enrol("rw")
        self.assertTrue(self.attest("rw")["admitted"])
        asked = dev.asked
        v = self.attest("rw", profile=fleet.DEVICE_TFM_PROFILE)           # the kind is the same
        self.assertRefused(v, "the record endorses family aegis-device/%s, the policy entry is aegis-device/%s"
                           % (fleet.DEVICE_PROFILE, fleet.DEVICE_TFM_PROFILE))
        self.assertEqual(dev.asked, asked)

    def test_a_signer_the_policy_allows_but_the_record_does_not_name_is_refused(self):
        signer_a, signer_b = "a1" * 32, "b2" * 32
        dev = PlainDevice(fleet.TEE_PROFILE, lambda c: c[2399][0].update({5: bytes.fromhex(signer_a)}))
        e = {"name": "zynq", "kind": "aegis-tee", "profile": fleet.TEE_PROFILE, "host": "127.0.0.1",
             "port": dev.port, "pq_pub_file": "keys/zynq.pub", "endorsement": "required",
             "allowed": [{"type": "BOOTCHAIN", "measurement_value": th.MEAS, "signer_id": signer_a}]}
        self.policy["endpoints"].append(e)
        res = self.enrol("zynq")
        self.assertEqual(res["measurements"][0]["signer_id"], signer_a)
        self.assertTrue(self.attest("zynq")["admitted"])
        # the same measurement under another signer, which the policy has been made to allow
        dev.claims_edit = lambda c: c[2399][0].update({5: bytes.fromhex(signer_b)})
        e["allowed"].append({"type": "BOOTCHAIN", "measurement_value": th.MEAS, "signer_id": signer_b})
        v = self.attest("zynq")
        self.assertRefused(v, "endorsement: component BOOTCHAIN is not the endorsed one")
        self.assertEqual(len(v["reasons"]), 1)          # the policy's own list would have admitted it

    def test_a_component_that_is_not_a_map_is_refused_not_dropped(self):
        endorsed = [{"type": "BOOTCHAIN", "measurement_value": th.MEAS}]
        good = {"measurement_type": "BOOTCHAIN", "measurement_value": bytes.fromhex(th.MEAS)}
        self.assertEqual(fleet.endorsed_components({"sw_components": [good]}, endorsed), [])
        for junk in ("x", 1, None, [good]):
            reasons = fleet.endorsed_components({"sw_components": [good, junk]}, endorsed)
            self.assertEqual(reasons, ["endorsement: a software component is not a map"], junk)

    def test_a_stored_session_made_for_another_key_is_dropped(self):
        """A session issued before the key was endorsed (trust on first use, or before a --force re-enrolment) is not
        kept alive by heartbeats once the cycle's quote is by another key."""
        self.dev_a.mode = "kem-good"
        self.enrol()
        self.ep()["provision"] = True
        gw_pk, gw_sk = mldsa.keypair()
        state = tempfile.mkdtemp()
        with open(os.path.join(state, "identity.json"), "w") as f:
            json.dump({"body": {"v": 1, "type": "identity", "pk": gw_pk.hex()}}, f)
        with open(os.path.join(state, "identity.sk"), "wb") as f:
            f.write(gw_sk)
        pol = dict(self.policy, endpoints=[self.ep()])
        v, = fleet.run_once(pol, self.d, VERIFY, state=state)
        self.assertTrue(v["credential"].startswith("issued session"), v["credential"])
        v, = fleet.run_once(pol, self.d, VERIFY, state=state)
        self.assertTrue(v["credential"].startswith("valid, heartbeat"), v["credential"])
        meta = os.path.join(state, "credentials", "dev-a.json")
        with open(meta) as f:
            m = json.load(f)
        m["body"]["endpoint_pq_pk_sha256"] = endorsement.pk_sha256(tf.PQ_KEYS[1][0])
        with open(meta, "w") as f:
            json.dump(m, f)
        v, = fleet.run_once(pol, self.d, VERIFY, state=state)
        self.assertTrue(v["credential"].startswith("issued session"), v["credential"])
        self.assertIn("stored session was made for device key", v["credential"])
        with open(meta) as f:
            self.assertEqual(json.load(f)["body"]["endpoint_pq_pk_sha256"], v["device_pk_sha256"])


class Enrolment(Bench):
    """Partial or failed enrolment leaves no trusted entry."""

    def nothing_trusted(self, name="dev-a"):
        """Neither way of trusting a key has anything for this entry."""
        self.assertFalse(self.attest(name)["admitted"])
        tofu = {k: x for k, x in self.ep(name).items() if k != "endorsement"}
        self.assertFalse(fleet.attest(tofu, VERIFY, self.d, 5)["admitted"])
        self.assertEqual(tmp_files(self.d, self.out), [])

    def test_a_device_that_fails_appraisal_gets_no_record(self):
        for mode, why in (("pq-tampered", "NSPE not allowed"), ("pq-wrongkey", "quote signature invalid")):
            self.dev_a.mode = mode
            res = self.endorse()
            self.assertFalse(res["endorsed"])
            self.assertTrue(any(why in r for r in res["reasons"]), res)
        self.assertEqual(os.listdir(self.out), [])
        self.nothing_trusted()

    def test_a_device_that_does_not_answer_gets_no_record(self):
        self.ep()["port"] = closed_port()
        res = self.endorse(timeout=2)
        self.assertFalse(res["endorsed"])
        self.assertTrue(res["reasons"][0].startswith("no identity key"), res)
        self.assertEqual(os.listdir(self.out), [])

    def test_what_the_tool_will_not_endorse(self):
        for edit, why in (({"allowed": []}, "no reference measurements"),
                          ({"kind": "psa"}, "no post-quantum key"),
                          ({"kind": "aegis-tee", "profile": fleet.TEE_DEVHUK_PROFILE, "allow_dev_profile": True},
                           "one key for every chip")):
            res = prov.endorse(self.endorser, dict(self.ep(), **edit), self.d, self.out, ecdsa_verify=VERIFY)
            self.assertFalse(res["endorsed"])
            self.assertTrue(any(why in r for r in res["reasons"]), res)
        rc, out = run(prov.main, ["endorse", self.pol, "no-such-device", "--state", self.estate, "--out", self.out])
        self.assertEqual(rc, 1)
        self.assertEqual(os.listdir(self.out), [])

    def test_a_record_that_cannot_be_written_is_not_there(self):
        with mock.patch.object(endorsement, "commit", side_effect=OSError("disk full")):
            res = self.endorse()
        self.assertFalse(res["endorsed"])
        self.assertIn("record not written", res["reasons"][0])
        self.assertEqual(os.listdir(self.out), [])
        self.nothing_trusted()

    def test_a_record_the_tool_cannot_verify_is_not_written(self):
        """Verify before commit: a signing key that is not the endorser's public key (a damaged key file) is found
        by the check of the finished record, and nothing is written."""
        broken = prov.Endorser(self.estate)
        broken.sk = mldsa.keypair()[1]
        res = self.endorse(endorser=broken)
        self.assertFalse(res["endorsed"])
        self.assertIn("no record made", res["reasons"][0])
        self.assertEqual(os.listdir(self.out), [])

    def test_a_record_that_would_not_admit_its_own_device_is_not_written(self):
        """Verify before commit, the whole way: the device is asked again and attested with the finished record
        required. Here it reports two components of one type, which no record can name both of."""
        twice = [{1: "APP", 2: b"\x01" * 32}, {1: "APP", 2: b"\x02" * 32}]
        dev = PlainDevice(fleet.TEE_PROFILE, lambda c: c[2399].extend(twice))
        e = {"name": "zynq", "kind": "aegis-tee", "profile": fleet.TEE_PROFILE, "host": "127.0.0.1",
             "port": dev.port, "pq_pub_file": "keys/zynq.pub", "endorsement": "required",
             "allowed": [{"type": "BOOTCHAIN", "measurement_value": th.MEAS},
                         {"type": "APP", "measurement_value": "01" * 32},
                         {"type": "APP", "measurement_value": "02" * 32}]}
        self.policy["endpoints"].append(e)
        tofu = {k: x for k, x in e.items() if k != "endorsement"}
        with open(os.path.join(self.d, "zynq.pub"), "w") as f:
            f.write(th.PK.hex())
        self.assertTrue(fleet.attest(dict(tofu, pq_pub_file="zynq.pub"), VERIFY, self.d, 5)["admitted"])
        res = self.endorse("zynq")
        self.assertFalse(res["endorsed"])
        self.assertIn("would not admit the device", res["reasons"][0])
        self.assertEqual(os.listdir(self.out), [])
        # and a device that changes between the two quotes of one enrolment
        asked = []

        def once(c):
            asked.append(1)
            if len(asked) > 1:
                c[2399][0][2] = b"\x09" * 32
        dev2 = PlainDevice(fleet.TEE_PROFILE, once)
        e.update(port=dev2.port, allowed=[{"type": "BOOTCHAIN", "measurement_value": th.MEAS},
                                          {"type": "BOOTCHAIN", "measurement_value": "09" * 32}])
        res = self.endorse("zynq")
        self.assertFalse(res["endorsed"])
        self.assertIn("is not the endorsed one", res["reasons"][0])
        self.assertEqual(os.listdir(self.out), [])

    def test_install_that_fails_between_its_two_files_leaves_nothing(self):
        res = self.endorse()
        real, calls = endorsement.commit, []

        def second_fails(tmp, path):
            calls.append(path)
            if len(calls) == 2:
                raise OSError("power cut")
            real(tmp, path)
        with mock.patch.object(endorsement, "commit", side_effect=second_fails):
            with self.assertRaises(OSError):
                fleet.install_endorsement(self.policy, self.d, res["record"])
        self.assertEqual(calls, [self.record_path(), self.key_path()])       # the record first, the key last
        self.assertFalse(os.path.exists(self.record_path()) or os.path.exists(self.key_path()))
        self.nothing_trusted()
        with mock.patch.object(endorsement, "commit", side_effect=OSError("first rename")):
            with self.assertRaises(OSError):
                fleet.install_endorsement(self.policy, self.d, res["record"])
        self.nothing_trusted()

    def test_a_process_that_dies_between_the_two_files_leaves_nothing_trusted(self):
        """No clean-up runs: the record is in place and the key is not (or the old key still is)."""
        res = self.endorse()
        code = ("import json, os, sys\n"
                "sys.path[:0] = %r\n"
                "import endorsement, fleet\n"
                "real, calls = endorsement.commit, []\n"
                "def dies(tmp, path):\n"
                "    calls.append(path)\n"
                "    if len(calls) == 2:\n"
                "        os._exit(7)\n"
                "    real(tmp, path)\n"
                "endorsement.commit = dies\n"
                "fleet.install_endorsement(json.load(open(sys.argv[1])), os.path.dirname(sys.argv[1]), sys.argv[2])\n"
                % [os.path.abspath(os.path.join(ROOT, p)) for p in ("common", "gateway/aegisd")])
        import subprocess
        r = subprocess.run([sys.executable, "-c", code, self.pol, res["record"]], capture_output=True, text=True)
        self.assertEqual(r.returncode, 7, r.stderr)
        self.assertTrue(os.path.exists(self.record_path()))
        self.assertFalse(os.path.exists(self.key_path()))
        self.assertFalse(self.attest()["admitted"])
        tofu = {k: x for k, x in self.ep().items() if k != "endorsement"}
        self.assertFalse(fleet.attest(tofu, VERIFY, self.d, 5)["admitted"])
        # the same with another key pinned before: that key is not the endorsed one
        with open(self.key_path(), "w") as f:
            f.write(tf.PQ_KEYS[1][0].hex())
        self.assertRefused(self.attest(), "substituted key")
        # running the install again finishes the enrolment
        fleet.install_endorsement(self.policy, self.d, res["record"], force=True)
        self.assertTrue(self.attest()["admitted"])

    def test_failed_re_enrolment_keeps_the_enrolment_that_was_there(self):
        self.enrol()
        with open(self.record_path()) as f:
            before = f.read()
        self.ep()["port"] = self.dev_b.port             # the board was replaced: a new key under the same name
        res = self.endorse()
        self.assertTrue(res["endorsed"], res)
        with self.assertRaises(endorsement.Refused) as c:       # a pinned key is not replaced without --force
            fleet.install_endorsement(self.policy, self.d, res["record"])
        self.assertIn("another key is already pinned", str(c.exception))
        real, calls = endorsement.commit, []

        def second_fails(tmp, path):
            calls.append(path)
            if len(calls) == 2:
                raise OSError("power cut")
            real(tmp, path)
        with mock.patch.object(endorsement, "commit", side_effect=second_fails):
            with self.assertRaises(OSError):
                fleet.install_endorsement(self.policy, self.d, res["record"], force=True)
        with open(self.record_path()) as f:
            self.assertEqual(f.read(), before)
        self.assertEqual(tmp_files(self.d), [])
        self.assertTrue(self.attest(port=self.dev_a.port)["admitted"])       # the old board, as before
        self.assertFalse(self.attest()["admitted"])                          # the new one: not enrolled
        fleet.install_endorsement(self.policy, self.d, res["record"], force=True)
        self.assertTrue(self.attest()["admitted"])
        self.assertFalse(self.attest(port=self.dev_a.port)["admitted"])

    def test_install_checks_the_record_against_the_policy(self):
        res = self.endorse()
        with open(res["record"]) as f:
            rec = json.load(f)

        def refused(text, edit=None, policy=None):
            path = os.path.join(self.out, "edited.json")
            r = json.loads(json.dumps(rec))
            if edit:
                edit(r)
            with open(path, "w") as f:
                json.dump(r, f)
            with self.assertRaises(endorsement.Refused) as c:
                fleet.install_endorsement(policy or self.policy, self.d, path)
            self.assertIn(text, str(c.exception))
            self.assertFalse(os.path.exists(self.record_path()) or os.path.exists(self.key_path()))
        refused("does not verify", lambda r: r["body"].update(notes="x"))
        refused("carries another key", lambda r: r.update(device_pk=tf.PQ_KEYS[1][0].hex()))
        refused("does not carry the device key", lambda r: r.pop("device_pk"))
        refused("no entry named", policy=dict(self.policy, endpoints=[self.ep("dev-b")]))
        refused("no trusted endorsers", policy=dict(self.policy, endorsers=[]))
        refused("the record endorses family aegis-pq",
                policy=dict(self.policy, endpoints=[dict(self.ep(), kind="aegis-device",
                                                         profile=fleet.DEVICE_TFM_PROFILE)]))
        self.nothing_trusted()

    def test_the_tool_s_command_line(self):
        rc, out = run(prov.main, ["show", "--state", self.estate])
        self.assertEqual((rc, json.loads(out)["policy_entry"]), (0, self.endorser.policy_entry()))
        self.dev_b.mode = "pq-tampered"
        rc, out = run(prov.main, ["endorse", self.pol, "dev-a", "dev-b", "--state", self.estate, "--out", self.out,
                                  "--notes", "bench"])
        self.assertEqual(rc, 1)                         # one of the two failed, and only its record is missing
        self.assertEqual(os.listdir(self.out), ["dev-a.json"])
        with self.assertRaises(SystemExit):
            prov.init(self.estate, "again", key_store="software")     # an existing key is not replaced
        with self.assertRaises(SystemExit):
            prov.main(["show", "--state", tempfile.mkdtemp()])
        os.rename(os.path.join(self.estate, keystore.SK_FILE), os.path.join(self.estate, "away"))
        try:                                            # no key: said before any device is asked
            with self.assertRaises(SystemExit) as c:
                prov.main(["endorse", self.pol, "dev-a", "--state", self.estate, "--out", self.out])
            self.assertIn("cannot be used", str(c.exception))
            self.assertEqual(run(prov.main, ["show", "--state", self.estate])[0], 0)
        finally:
            os.rename(os.path.join(self.estate, "away"), os.path.join(self.estate, keystore.SK_FILE))


class BoardCheck(Bench):
    """tests/board/endorsement_check.py, the check for the real boards, against the simulated devices."""

    CHECK = os.path.join(ROOT, "tests", "board", "endorsement_check.py")

    def check(self, *names):
        import subprocess
        r = subprocess.run([sys.executable, self.CHECK, self.pol, *names, "--timeout", "5"], capture_output=True,
                           text=True)
        self.assertIn(r.returncode, (0, 1, 2), r.stderr)
        return r.returncode, json.loads(r.stdout)

    def test_passes_on_two_enrolled_devices_and_changes_nothing(self):
        self.enrol("dev-a")
        self.enrol("dev-b")
        for e in self.policy["endpoints"]:
            del e["endorsement"]                    # the policy before the switch: the check asks for it itself
        self.save()
        before = snapshot(self.d)
        rc, res = self.check("dev-a", "dev-b")
        self.assertEqual(rc, 0, res)
        self.assertTrue(res["ok"])
        self.assertEqual(res["E1_as_enrolled"]["enrolment"], "endorsed")
        refused = [k for k, v in res.items() if isinstance(v, dict) and v.get("admitted") is False]
        self.assertEqual(len(refused), 11, refused)
        self.assertTrue(all(res[k]["as_expected"] is True for k in refused))
        self.assertFalse(any(res[k]["endpoint_asked"] for k in refused if not k.startswith("E6")))
        control = res["E9_control_trust_on_first_use"]
        self.assertEqual((control["admitted"], control["enrolment"]), (True, "trust-on-first-use"))
        self.assertEqual(before, snapshot(self.d))

    def test_stops_on_a_device_that_was_not_enrolled(self):
        self.enrol("dev-b")
        self.save()
        rc, res = self.check("dev-a", "dev-b")
        self.assertEqual(rc, 2, res)
        self.assertIn("not admitted as enrolled", res["stopped"])

    def test_fails_when_a_substitution_would_be_admitted(self):
        """The check notices a verifier that does not refuse: here one that does not compare the pinned key with
        the endorsed one."""
        self.enrol("dev-a")
        self.enrol("dev-b")
        self.save()
        shim = os.path.join(self.d, "shim")
        os.makedirs(shim)
        with open(os.path.join(shim, "sitecustomize.py"), "w") as f:
            f.write("import sys\nsys.path[:0] = %r\nimport endorsement\n"
                    "real = endorsement.check\n"
                    "def check(record, *a):\n"
                    "    try:\n"
                    "        return real(record, *a)\n"
                    "    except endorsement.Refused as e:\n"
                    "        if 'substituted key' not in str(e):\n"
                    "            raise\n"
                    "        return dict(record['body'], endorser_name='bench')\n"
                    "endorsement.check = check\n" % [os.path.abspath(os.path.join(ROOT, "common"))])
        import subprocess
        r = subprocess.run([sys.executable, self.CHECK, self.pol, "dev-a", "dev-b", "--timeout", "5"],
                           capture_output=True, text=True, env=dict(os.environ, PYTHONPATH=shim))
        self.assertEqual(r.returncode, 1, r.stdout[-400:] + r.stderr[-400:])
        self.assertFalse(json.loads(r.stdout)["E3_substituted_key"]["as_expected"])


@unittest.skipUnless(os.path.isdir(rw.MLDSA) and os.path.isdir(rw.MLKEM), "mldsa-native / mlkem-native not found")
class SdkCore(unittest.TestCase):
    """The Prover SDK's core as it is (sdk/src/aegis_proto.c behind the PC port): the tool enrols it with the two
    commands every image already has, PQKEY and PQCHAL. Two chips: the same image, different device secrets."""

    @classmethod
    def setUpClass(cls):
        import subprocess
        cls.d = tempfile.mkdtemp()
        exe = os.path.join(cls.d, "prover")
        rw.build(exe)
        cls.gw_pk, cls.gw_sk = mldsa.keypair()
        with open(os.path.join(cls.d, "gw.pub"), "w") as f:
            f.write(cls.gw_pk.hex())
        image = os.path.join(cls.d, "image.bin")
        with open(image, "wb") as f:
            f.write(os.urandom(70001))
        import hashlib
        with open(image, "rb") as f:
            cls.good = hashlib.sha256(f.read()).hexdigest()
        cls.procs, cls.ports = [], []
        for _ in range(2):
            port = rw.free_port()
            pr = subprocess.Popen([exe, str(port), os.urandom(32).hex(), os.urandom(32).hex(),
                                   os.path.join(cls.d, "gw.pub"), image], stdout=subprocess.PIPE, text=True)
            cls.procs.append(pr)
            assert pr.stdout.readline().split()[0] == "READY"
            cls.ports.append(port)
        cls.estate = os.path.join(cls.d, "endorser")
        prov.init(cls.estate, "bench", key_store="software")
        cls.endorser = prov.Endorser(cls.estate)
        run(prov.main, ["export", os.path.join(cls.d, "endorsers"), "--state", cls.estate])
        cls.entry = {"name": "frdm-rw612", "kind": "aegis-device", "profile": fleet.DEVICE_PROFILE,
                     "host": "127.0.0.1", "port": cls.ports[0], "pq_pub_file": "keys/frdm-rw612.mldsa65.pub",
                     "allowed": [{"type": "APP", "measurement_value": cls.good}], "endorsement": "required",
                     "transcript": "v2", "provision": True}
        cls.policy = {"endorsers": [cls.endorser.policy_entry()], "endpoints": [cls.entry]}

    @classmethod
    def tearDownClass(cls):
        for pr in cls.procs:
            pr.kill()
            pr.wait()
            pr.stdout.close()

    def test_enrolled_with_the_commands_it_already_has_then_a_bound_session(self):
        res = prov.endorse(self.endorser, self.entry, self.d, os.path.join(self.d, "out"), serial="chip 1")
        self.assertTrue(res["endorsed"], res)
        self.assertLess(res["elapsed_s"], 60)
        self.assertEqual(res["measurements"], [{"type": "APP", "measurement_value": self.good}])
        fleet.install_endorsement(self.policy, self.d, res["record"])
        trust = self.policy["endorsers"]
        v = fleet.attest(self.entry, None, self.d, 10, trust)
        self.assertTrue(v["admitted"], v["reasons"])
        self.assertEqual((v["enrolment"], v["trust"]), ("endorsed", "device-key"))
        r = fleet.provision(self.entry, self.d, self.gw_sk, "gid", v["measurements"], timeout=20, quote=v["quote"],
                            endorsers=trust, expect_pk_sha256=v["device_pk_sha256"])
        self.assertEqual(r["transcript"], "v2")
        status, _ = fleet.heartbeat(self.entry, r["session_key"])
        self.assertIn(b"ttl=", status)
        # the second chip at the first one's address: the same firmware, the same measurements, not the endorsed key
        other = dict(self.entry, port=self.ports[1])
        v = fleet.attest(other, None, self.d, 10, trust)
        self.assertFalse(v["admitted"])
        self.assertIn("does not hold the endorsed key", v["reasons"][0])
        # under trust on first use the second chip, enrolled the old way over the same wire, would be admitted
        tofu = {k: x for k, x in other.items() if k != "endorsement"}
        tofu["pq_pub_file"] = "keys/tofu.pub"
        pol = os.path.join(self.d, "tofu.json")
        with open(pol, "w") as f:
            json.dump({"endpoints": [tofu]}, f)
        run(fleet.main, ["enroll-pq", pol])
        self.assertTrue(fleet.attest(tofu, None, self.d, 10)["admitted"])


class EndorserKey(unittest.TestCase):
    def test_software_key_is_a_private_file(self):
        state = tempfile.mkdtemp()
        body = prov.init(state, "bench", key_store="software")
        self.assertEqual(body["key_store"], keystore.SOFTWARE)
        self.assertEqual(os.stat(os.path.join(state, keystore.SK_FILE)).st_mode & 0o777, 0o600)
        e = prov.Endorser(state)
        self.assertTrue(mldsa.verify(e.pk, b"x", b"m", mldsa.sign(e.sk, b"x", b"m")))
        with open(os.path.join(state, prov.RECORD)) as f:
            rec = json.load(f)
        rec["body"]["name"] = "other"                   # the record is self-signed
        with open(os.path.join(state, prov.RECORD), "w") as f:
            json.dump(rec, f)
        with self.assertRaises(ValueError):
            prov.Endorser(state)

    def test_names_that_are_not_file_names_are_refused(self):
        for bad in ("", "a/b", "..", "a b", "x" * 65):
            with self.assertRaises(SystemExit):
                prov.init(tempfile.mkdtemp(), bad, key_store="software")

    def test_key_sealed_to_a_tpm(self):
        import test_tpm_keystore as tt
        if not tt.HAVE_SWTPM:
            self.skipTest("needs swtpm and tpm2-pytss")
        tpm, other = tt.Swtpm(), tt.Swtpm()
        self.addCleanup(tpm.close)
        self.addCleanup(other.close)
        state = tempfile.mkdtemp()
        body = prov.init(state, "bench", key_store="tpm", tcti=tpm.tcti)
        self.assertEqual(body["key_store"], keystore.TPM)
        e = prov.Endorser(state, tcti=tpm.tcti)
        self.assertTrue(mldsa.verify(e.pk, b"x", b"m", mldsa.sign(e.sk, b"x", b"m")))
        for data in tt.state_files(state).values():     # the key is nowhere on disk in the clear
            self.assertNotIn(e.sk, data)
            self.assertNotIn(e.sk.hex().encode(), data)
        self.assertFalse(os.path.exists(os.path.join(state, keystore.SK_FILE)))
        self.assertEqual(prov.Endorser(state, tcti=other.tcti).pk, e.pk)     # the public half needs no TPM
        with self.assertRaises(keystore.TpmError):       # the state directory on another machine's TPM
            prov.Endorser(state, tcti=other.tcti).sk


if __name__ == "__main__":
    unittest.main()
