# SPDX-License-Identifier: Apache-2.0
"""The verifier's signed audit log and the signed policy (docs/audit-and-policy.md).

Simulated endpoints (no hardware). The numbers and strings of the two formats are written out here as the document
gives them, not taken from common/audit.py or common/signed_policy.py, so that a changed constant there fails here.

  log        a batch record is the document's bytes; nothing written when nothing is said; what cannot be done to a
             log without the key (change, remove, reorder, splice) and what needs an anchor or the promise to be seen
             (cutting off the end, writing it again with the key); a torn end, two writers, another key, damage
  trail      what the fleet verifier logs and when: off by default, nothing in a steady cycle, an entry per change of
             a decision, a session or the policy; an enrolment; a log that cannot be written stops nothing
  policy     the signed policy's bytes; who may have signed it, for which fleet; the version never goes back
  verifier   fleet.py: unsigned as before without policy-signing keys, only a signed policy with them; the loop keeps
             the last accepted policy; the key pin of an entry
  signer     provision/aegis_provision.py policy-init, policy-export, policy-sign
  checker    tools/verify_audit.py, which shares no code with the repository, says the same as the verifier's reader
"""
import ast
import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

os.environ.setdefault("TSS2_LOG", "all+NONE")
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("common", "gateway/aegisd", "provision", "tests/host"):
    sys.path.insert(0, os.path.join(ROOT, p))

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ec  # noqa: E402

import aegis_provision as prov  # noqa: E402
import audit  # noqa: E402
import cbor  # noqa: E402
import cose  # noqa: E402
import eat  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import psa_token  # noqa: E402
import signed_policy  # noqa: E402
import test_endorsement as te  # noqa: E402
import test_fleet as tf  # noqa: E402

CHECKER = os.path.join(ROOT, "tools", "verify_audit.py")
VERIFY = psa_token.verify_with_cryptography
VPK, VSK = mldsa.keypair()          # the verifier's identity
OPK, OSK = mldsa.keypair()          # the operator's policy-signing key
XPK, XSK = mldsa.keypair()          # somebody else's key
AUDIT_TYP = "application/vnd.aegis.audit-batch+cbor"
AUDIT_FORMAT = "tag:github.com,2026:ismailalitech/aegis/audit/v1"
POLICY_TYP = "application/vnd.aegis.fleet-policy+cbor"
POLICY_FORMAT = "tag:github.com,2026:ismailalitech/aegis/policy/v1"
T0 = 1_800_000_000
DEFAULT_AUDIT = dict(fleet.AUDIT_SETTINGS)     # before Fleet.setUp lets every change be written at once


def run(main, argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
        rc = main(argv)
    return rc, out.getvalue()


def checker(*args):
    """tools/verify_audit.py as a program of its own (-I: nothing of this repository on its path)."""
    r = subprocess.run([sys.executable, "-I", CHECKER, *args], capture_output=True, text=True, cwd=tempfile.gettempdir())
    try:
        return r.returncode, json.loads(r.stdout)
    except ValueError:
        return r.returncode, {"verified": False, "reason": r.stdout + r.stderr}


def have_checker_libs():
    import importlib
    try:
        for name in ("cbor2", "pycose", "cryptography.hazmat.primitives.asymmetric.mldsa"):
            importlib.import_module(name)
    except Exception:  # noqa: BLE001
        return False
    return True


NEEDS_LIBS = unittest.skipUnless(have_checker_libs(), "needs pycose, cbor2 and cryptography with ML-DSA")


def make_state(pk=VPK, sk=VSK):
    """A verifier's state directory with an identity."""
    state = tempfile.mkdtemp()
    with open(os.path.join(state, "identity.json"), "w") as f:
        json.dump({"body": {"v": 1, "type": "identity", "pk": pk.hex()}}, f)
    with open(os.path.join(state, "identity.sk"), "wb") as f:
        f.write(sk)
    return state


def hexfile(pk):
    path = os.path.join(tempfile.mkdtemp(), "key.pub")
    with open(path, "w") as f:
        f.write(pk.hex() + "\n")
    return path


def records(directory):
    """Every batch record of a log directory, in order, as bytes."""
    out = []
    for _, path in audit.segments(directory):
        with open(path, "rb") as f:
            out += [raw for _, raw in audit.split(f.read())]
    return out


def write_records(directory, recs):
    """Replace a log directory's segments by one segment holding recs."""
    for _, path in audit.segments(directory):
        os.unlink(path)
    with open(os.path.join(directory, "audit-000001.cbor"), "wb") as f:
        f.write(b"".join(recs))


def events(directory, keys=(VPK,), **kw):
    r = audit.verify(directory, list(keys), with_entries=True, **kw)
    return [(e["event"], e["subject"]) for e in r["entries"]]


class Log(unittest.TestCase):
    """common/audit.py."""

    def setUp(self):
        self.d = os.path.join(tempfile.mkdtemp(), "audit")
        self.loads = 0

    def sk(self):
        self.loads += 1
        return VSK

    def log(self, pk=VPK, sk=None, **kw):
        return audit.Log(self.d, pk, sk or self.sk, **kw)

    def fill(self, n=4, **kw):
        """A log of n batches, one entry each after the first batch's two; returns the writer."""
        lg = self.log(**kw)
        for i in range(n):
            lg.add("admit", "dev%d" % i, {"i": i}, T0 + i)
            self.assertEqual(len(lg.flush(T0 + i)), 1)
        return lg

    def refused(self, text, *args, **kw):
        with self.assertRaises(audit.Refused) as c:
            audit.verify(self.d, [VPK], *args, **kw)
        self.assertIn(text, str(c.exception))

    def test_a_batch_record_is_the_document_s_bytes(self):
        lg = self.log(checkpoint_s=3600, grace_s=100)
        lg.add("admit", "dev", {"kind": "aegis-device", "device_key_sha256": b"\x11" * 32}, T0)
        b1, = lg.flush(T0 + 1)
        lg.add("refuse", "dev", None, T0 + 5)
        b2, = lg.flush(T0 + 6)
        r1, r2 = records(self.d)
        self.assertEqual((r1, r2), (b1.raw, b2.raw))
        # the envelope: an Aegis COSE_Sign1 with its own typ, by the verifier's key
        tag = cbor.loads(r1)
        self.assertEqual(tag.tag, 18)
        protected, unprotected, payload, sig = tag.value
        self.assertEqual(cbor.loads(protected), {1: -49, 4: cose.key_thumbprint(VPK), 16: AUDIT_TYP})
        self.assertEqual((unprotected, len(sig)), ({}, 3309))
        self.assertTrue(mldsa.verify_raw(VPK, cbor.dumps(["Signature1", protected, b"", payload]), sig))
        c = cbor.loads(payload)
        self.assertEqual(sorted(c), [1, 2, 3, 4, 5, 6, 7, 8])
        self.assertEqual((c[1], len(c[2]), c[3], c[4], c[5], c[6], c[8]),
                         (AUDIT_FORMAT, 16, 1, bytes(32), T0 + 1, 1, T0 + 1 + 3600 + 100))
        # the first entry of a log says how it began; then what was added
        self.assertEqual([(e[2], e.get(3)) for e in c[7]], [("log-start", None), ("admit", "dev")])
        self.assertEqual(c[7][1], {1: T0, 2: "admit", 3: "dev",
                                   4: {"kind": "aegis-device", "device_key_sha256": b"\x11" * 32}})
        self.assertEqual(cbor.dumps(c, sort=True), payload)
        # the chain: the next batch names the SHA-256 of this record, its number and where its entries go on
        c2 = cbor.loads(cbor.loads(r2).value[2])
        self.assertEqual((c2[2], c2[3], c2[4], c2[6]), (c[2], 2, hashlib.sha256(r1).digest(), 3))
        self.assertEqual(c2[7], [{1: T0 + 5, 2: "refuse", 3: "dev"}])
        rep = audit.verify(self.d, [VPK], with_entries=True)
        self.assertEqual((rep["logs"][0]["last_batch"], rep["logs"][0]["entries"], rep["logs"][0]["head"]),
                         (2, 3, hashlib.sha256(r2).hexdigest()))
        self.assertEqual([e["entry"] for e in rep["entries"]], [1, 2, 3])

    def test_nothing_to_say_nothing_written_and_the_key_stays_closed(self):
        lg = self.log(checkpoint_s=3600, grace_s=60)
        self.assertEqual(lg.flush(T0, promise=False), [])            # a run with nothing to say
        self.assertEqual((audit.segments(self.d), self.loads), ([], 0))
        lg.add("start", None, {}, T0)
        lg.flush(T0)
        size = os.path.getsize(audit.segments(self.d)[0][1])
        for t in range(T0 + 30, T0 + 3600, 30):                      # an hour of cycles in which nothing changed
            self.assertEqual(lg.flush(t), [])
        self.assertEqual((os.path.getsize(audit.segments(self.d)[0][1]), self.loads), (size, 1))
        b, = lg.flush(T0 + 3600)                                     # the promise is kept: an empty batch
        self.assertEqual((b.batch, b.entries, b.due), (2, [], T0 + 3600 + 3600 + 60))
        self.assertLess(len(b.raw), 3600)                            # one signature and 150 bytes
        self.assertEqual(audit.verify(self.d, [VPK])["logs"][0]["entries"], 2)
        # without checkpoints: no promise and no empty batch, ever
        self.d = os.path.join(tempfile.mkdtemp(), "audit")
        lg = self.log(checkpoint_s=0)
        lg.add("start", None, {}, T0)
        self.assertIsNone(lg.flush(T0)[0].due)
        self.assertEqual(lg.flush(T0 + 10 ** 6), [])

    def test_one_signature_for_a_cycle_s_entries_and_more_batches_only_when_they_do_not_fit(self):
        lg = self.log()
        for i in range(8):
            lg.add("admit", "dev%d" % i, {"measurements": {"SPE": b"\x22" * 32}}, T0)
        b, = lg.flush(T0)
        self.assertEqual((len(b.entries), self.loads), (9, 1))
        self.assertLess(len(b.raw), 3309 + 1400)
        for i in range(60):
            lg.add("refuse", "dev%d" % i, {"reasons": ["x" * 240] * 6}, T0 + 1)
        many = lg.flush(T0 + 1)
        self.assertGreater(len(many), 1)
        self.assertTrue(all(len(b.raw) <= cose.MAX_SIGN1 for b in many))
        self.assertEqual(sum(len(b.entries) for b in many), 60)
        self.assertEqual(audit.verify(self.d, [VPK])["logs"][0]["entries"], 69)

    def test_a_log_is_not_changed_without_the_key(self):
        self.fill(5)
        good = records(self.d)
        audit.verify(self.d, [VPK])
        for name, recs, why in (
                ("a byte of an entry", [good[0], good[1][:200] + bytes([good[1][200] ^ 1]) + good[1][201:]] + good[2:],
                 ""),
                ("a batch removed from the middle", good[:2] + good[3:], "batches are missing"),
                ("two batches in the other order", [good[0], good[2], good[1]] + good[3:], ""),
                ("a batch twice", good[:3] + [good[2]] + good[3:], "out of order, or repeated"),
                ("the first batch removed", good[1:], "what came before is missing"),
                ("bytes after the last record", good + [b"\x00"], ""),
                ("half a record at the end", good + [good[0][:500]], "in the middle of a record")):
            write_records(self.d, recs)
            with self.assertRaises(audit.Refused, msg=name) as c:
                audit.verify(self.d, [VPK])
            self.assertIn(why, str(c.exception), name)
        # an entry changed and the batch signed again, by a key that is not the verifier's
        c = cbor.loads(cose.parse(good[2]).payload)
        c[7][0][3] = "another-device"
        forged = cose.sign1(XSK, XPK, cbor.dumps(c, sort=True), typ=AUDIT_TYP)
        write_records(self.d, good[:2] + [forged] + good[3:])
        self.refused("not trusted here")
        # ... or with the verifier's own signature from the old batch
        tag = cbor.loads(good[2])
        write_records(self.d, good[:2] + [cose.assemble(tag.value[0], cbor.dumps(c, sort=True), tag.value[3])]
                      + good[3:])
        self.refused("signature does not verify")
        # a batch of another log of the same key, with the right number, does not continue this one
        other = os.path.join(tempfile.mkdtemp(), "audit")
        lg = audit.Log(other, VPK, lambda: VSK)
        for i in range(3):
            lg.add("admit", "dev", {}, T0)
            lg.flush(T0)
        write_records(self.d, good[:2] + [records(other)[2]] + good[3:])
        self.refused("another log")
        write_records(self.d, good)
        audit.verify(self.d, [VPK])

    def test_the_end_cut_off_is_seen_by_an_anchor_or_by_the_promise(self):
        lg = self.fill(5, checkpoint_s=3600, grace_s=60)
        good = records(self.d)
        anchor = lg.head().raw                              # what `fleet.py audit --out` keeps
        self.assertEqual(anchor, good[-1])
        write_records(self.d, good[:3])
        # the shorter log is a log: its last batch is signed. That is what an anchor is for
        self.assertEqual(audit.verify(self.d, [VPK])["logs"][0]["last_batch"], 3)
        self.refused("the end was cut off", anchors=[anchor])
        self.refused("the end was cut off", heads=[(5, hashlib.sha256(anchor).hexdigest())])
        # and the promise: the last batch left says when the next one was due
        due = audit.open_batch(good[2]).due
        self.assertEqual(due, T0 + 2 + 3660)
        self.assertFalse(audit.verify(self.d, [VPK], now=due)["stale"])
        self.assertTrue(audit.verify(self.d, [VPK], now=due + 1)["stale"])
        # an anchor from before the cut is still in the log; an anchor of another log is not
        audit.verify(self.d, [VPK], anchors=[good[1]], heads=[(3, hashlib.sha256(good[2]).hexdigest())])
        self.refused("not a batch record of this verifier", anchors=[b"\xd2" + good[1][1:40]])
        self.refused("is not the anchored record", heads=[(2, "00" * 32)])

    def test_a_log_written_again_with_the_key_does_not_hold_the_anchor(self):
        """Whoever holds the verifier's key can write another log. They cannot write one that holds a batch record
        somebody kept."""
        lg = self.fill(4)
        good = records(self.d)
        anchor = good[-1]
        log_id = audit.open_batch(good[0]).log
        # the same log from batch 3 on, with another entry, signed by the real key
        b2 = audit.open_batch(good[1])
        again = audit.make_batch(VSK, VPK, log_id, 3, b2.head, b2.next_entry, [audit.entry("admit", "evil", {}, T0)], T0)
        b3 = audit.open_batch(again)
        last = audit.make_batch(VSK, VPK, log_id, 4, b3.head, b3.next_entry, [], T0)
        write_records(self.d, good[:2] + [again, last])
        audit.verify(self.d, [VPK])                         # whole, in order, signed
        self.refused("is not the anchored record", anchors=[anchor])
        # a new log altogether
        shutil.rmtree(self.d)
        lg = self.log()
        lg.add("start", None, {}, T0)
        lg.flush(T0)
        self.refused("the log was replaced", anchors=[anchor])

    def test_older_segments_archived_away_are_missed_unless_allowed(self):
        lg = self.log(segment_bytes=9000)
        for i in range(8):
            lg.add("admit", "dev", {}, T0 + i)
            lg.flush(T0 + i)
        segs = audit.segments(self.d)
        self.assertEqual(len(segs), 4)                      # two batches to a segment of this size
        self.assertEqual(audit.verify(self.d, [VPK])["logs"][0]["last_batch"], 8)
        self.assertEqual(audit.verify([p for _, p in segs], [VPK])["pruned"], False)
        os.unlink(segs[0][1])
        self.refused("what came before is missing")
        rep = audit.verify(self.d, [VPK], allow_pruned=True)
        self.assertEqual((rep["pruned"], rep["logs"][0]["first_batch"], rep["logs"][0]["last_batch"]), (True, 3, 8))
        os.unlink(segs[2][1])                               # one from the middle is not pruning
        with self.assertRaises(audit.Refused):
            audit.verify(self.d, [VPK], allow_pruned=True)

    def test_a_torn_end_is_cut_off_and_said(self):
        self.fill(2)
        path = audit.segments(self.d)[-1][1]
        good = records(self.d)
        with open(path, "ab") as f:
            f.write(good[0][:1000])                         # the process died in the middle of a write
        self.refused("in the middle of a record")
        lg = self.log()                                     # the next start
        lg.add("start", None, {}, T0 + 9)
        b, = lg.flush(T0 + 9)
        self.assertEqual([e["event"] for e in b.entries], ["recovered", "start"])
        self.assertEqual(b.entries[0]["details"]["dropped_bytes"], 1000)
        self.assertEqual(records(self.d)[:2], good)         # nothing signed was lost
        self.assertEqual(events(self.d)[-2:], [("recovered", None), ("start", None)])

    def test_two_writers_make_one_chain(self):
        loop, cli = self.log(checkpoint_s=3600, grace_s=60), self.log(checkpoint_s=3600, grace_s=60)
        loop.add("start", None, {}, T0)
        b1, = loop.flush(T0)
        cli.add("enrol", "dev", {}, T0 + 5)
        b2, = cli.flush(T0 + 5, promise=False)
        loop.add("admit", "dev", {}, T0 + 9)
        b3, = loop.flush(T0 + 9)
        self.assertEqual([(b.batch, b.first) for b in (b1, b2, b3)], [(1, 1), (2, 3), (3, 4)])
        self.assertEqual((b2.prev, b3.prev), (b1.head, b2.head))
        self.assertEqual(b2.due, b1.due)                    # a command makes no promise: the loop's stands
        self.assertEqual(events(self.d), [("log-start", None), ("start", None), ("enrol", "dev"), ("admit", "dev")])
        # a promise that has lapsed is not made again by a command
        cli.add("enrol", "dev", {}, b3.due + 1)
        self.assertIsNone(cli.flush(b3.due + 1, promise=False)[0].due)

    def test_another_identity_begins_another_log_that_names_the_one_before(self):
        self.fill(2)
        old = records(self.d)
        lg = self.log(XPK, lambda: XSK)
        lg.add("start", None, {}, T0 + 9)
        b, = lg.flush(T0 + 9)
        self.assertEqual((b.batch, b.prev, len(audit.segments(self.d))), (1, bytes(32), 2))
        d = b.entries[0]["details"]
        tail = audit.open_batch(old[-1])
        self.assertEqual((b.entries[0]["event"], d["after_log"], d["after_batch"], d["after_head"],
                          d["verifier_key_sha256"]), ("log-start", tail.log, 2, tail.head, hashlib.sha256(XPK).digest()))
        rep = audit.verify(self.d, [VPK, XPK])
        self.assertEqual([(lg["last_batch"], lg["kid"]) for lg in rep["logs"]],
                         [(2, cose.key_thumbprint(VPK).hex()), (1, cose.key_thumbprint(XPK).hex())])
        self.refused("not trusted here")                    # with the first key alone
        # the new log without the old one: it says itself that something came before
        os.unlink(audit.segments(self.d)[0][1])
        with self.assertRaises(audit.Refused) as c:
            audit.verify(self.d, [VPK, XPK])
        self.assertIn("which is not here whole", str(c.exception))
        self.assertTrue(audit.verify(self.d, [XPK], allow_pruned=True)["pruned"])

    def test_a_damaged_segment_is_left_alone_and_a_new_log_begun(self):
        """The writer continues from the last record, and checks that one: if it is no longer a batch record of this
        verifier, nothing is appended to that segment."""
        self.fill(2)
        path = audit.segments(self.d)[0][1]
        with open(path, "r+b") as f:
            f.seek(len(records(self.d)[0]) + 300)
            f.write(b"\xff" * 8)                            # inside the last record: its signature no longer holds
        with open(path, "rb") as f:
            damaged = f.read()
        lg = self.log()
        lg.add("start", None, {}, T0 + 9)
        b, = lg.flush(T0 + 9)
        self.assertEqual((b.batch, b.entries[0]["details"]["damaged_segment"]), (1, 1))
        with open(path, "rb") as f:
            self.assertEqual(f.read(), damaged)             # evidence is not tidied away
        with self.assertRaises(audit.Refused):
            audit.verify(self.d, [VPK])
        with self.assertRaises(audit.Refused):              # nor is the new log whole on its own
            audit.verify(audit.segments(self.d)[1][1], [VPK])
        self.assertTrue(audit.verify(audit.segments(self.d)[1][1], [VPK], allow_pruned=True)["pruned"])

    def test_whatever_is_put_into_an_entry_the_log_stays_a_log(self):
        lg = self.log()
        tag = cbor.Tag(7, "x")
        lg.add("refuse", "dev\x00\ud800" + "n" * 200, {"reasons": [1.5, tag, {"a": {"b": {"c": {"d": {"e": 1}}}}}],
                                                         3: "int key", "s": "\ud800", "big": 1 << 80,
                                                         "obj": object(), "bytes": bytearray(b"x" * 999)}, T0)
        lg.add("Not An Event", "dev", {}, T0)
        lg.add("refuse", "dev", {"reasons": ["y" * 300] * 16, "more": {str(i): "z" * 300 for i in range(24)}}, T0)
        lg.add("admit", "dev", {"t": 1}, "not a time")
        lg.flush(T0)
        rep = audit.verify(self.d, [VPK], with_entries=True)
        e = rep["entries"]
        self.assertEqual([x["event"] for x in e], ["log-start", "refuse", "unwritable", "refuse", "admit"])
        self.assertLess(abs(e[4]["time"] - time.time()), 60)        # not a time: the time it was written
        self.assertEqual(len(e[1]["subject"]), 64)
        self.assertEqual((e[1]["details"]["3"], e[1]["details"]["s"], len(e[1]["details"]["bytes"])), ("int key", "?", 256))
        self.assertEqual(e[3]["details"]["truncated"], True)        # too long: the entry stays, its details go
        self.assertTrue(all(len(cbor.dumps(x)) < 4200 for x in cbor.loads(cose.parse(records(self.d)[0]).payload)[7]))

    def test_a_log_that_cannot_be_written_keeps_what_it_was_told(self):
        def no_key():
            raise OSError("the key store is not there")
        lg = self.log(sk=no_key)
        lg.add("admit", "dev", {}, T0)
        with self.assertRaises(OSError):
            lg.flush(T0)
        with self.assertRaises(OSError):
            lg.flush(T0 + 30)
        self.assertEqual(audit.segments(self.d), [])
        lg._load_sk = lambda: VSK
        b, = lg.flush(T0 + 60)
        self.assertEqual([(e["event"], e["time"]) for e in b.entries][1:], [("admit", T0)])
        self.assertEqual([e["event"] for e in b.entries].count("log-start"), 1)
        # more than memory holds: counted, and the count is an entry
        lg._load_sk = no_key
        for i in range(audit.MAX_PENDING + 7):
            lg.add("refuse", "dev", {}, T0 + 100 + i)
        with self.assertRaises(OSError):
            lg.flush(T0 + 1000)
        lg._load_sk = lambda: VSK
        lg.flush(T0 + 2000)
        ev = audit.verify(self.d, [VPK], with_entries=True)["entries"]
        self.assertEqual(len([e for e in ev if e["event"] == "refuse"]), audit.MAX_PENDING)
        gap = ev[-1]
        self.assertEqual((gap["event"], gap["details"]["dropped"]), ("gap", 7))

    def test_a_secret_key_that_is_not_the_log_s_key_writes_nothing(self):
        """The identity made again while the loop runs: the writer still holds the old public key and now loads the
        new secret key. No batch is written (a batch whose kid is not its signer's would make every later flush begin
        another log); the entries wait, and the right key writes them."""
        lg = self.fill(2)
        before = [(n, os.path.getsize(p)) for n, p in audit.segments(self.d)]
        lg._load_sk = lambda: XSK
        lg.add("refuse", "dev", {}, T0 + 10)
        for t in (T0 + 10, T0 + 40, T0 + 70):
            with self.assertRaises(audit.KeyMismatch) as c:
                lg.flush(t)
            self.assertIn("identity made again", str(c.exception))
        self.assertEqual([(n, os.path.getsize(p)) for n, p in audit.segments(self.d)], before)   # no new segment
        lg._load_sk = lambda: VSK
        b, = lg.flush(T0 + 100)
        self.assertEqual((b.batch, [e["event"] for e in b.entries]), (3, ["refuse"]))
        self.assertEqual(audit.verify(self.d, [VPK])["logs"][0]["last_batch"], 3)

    def test_entries_wait_for_the_interval_and_are_not_lost(self):
        lg = self.log(min_interval_s=300, checkpoint_s=0)
        lg.add("start", None, {}, T0)
        self.assertEqual(len(lg.flush(T0)), 1)
        for t in (T0 + 30, T0 + 60, T0 + 90):               # an endpoint that changes its mind every cycle
            lg.add("refuse", "dev", {}, t)
            self.assertEqual(lg.flush(t), [])
        b, = lg.flush(T0 + 300)
        self.assertEqual([e["time"] for e in b.entries], [T0 + 30, T0 + 60, T0 + 90])
        lg.add("stop", None, {}, T0 + 301)
        self.assertEqual(len(lg.flush(T0 + 301, force=True)), 1)    # the last word does not wait

    def test_the_default_interval_bounds_a_flapping_endpoint(self):
        """An hour of 30 s cycles in which an endpoint changes its mind every cycle: with the policy's defaults one
        batch per 300 s (and the first at once), not one per cycle; every entry is there."""
        lg = self.log(**DEFAULT_AUDIT)
        n = 0
        for i, t in enumerate(range(T0, T0 + 3600, 30)):
            lg.add("admit" if i % 2 else "refuse", "dev", {}, t)
            n += len(lg.flush(t))
        self.assertLessEqual(n, 13)
        lg.flush(T0 + 3600, force=True)
        ev = audit.verify(self.d, [VPK], with_entries=True)["entries"]
        self.assertEqual(len([e for e in ev if e["event"] in ("admit", "refuse")]), 120)
        self.assertLess(sum(os.path.getsize(p) for _, p in audit.segments(self.d)), 14 * 4500)

    def test_old_segments_are_deleted_past_max_segments_and_the_log_says_which(self):
        lg = self.log(segment_bytes=20000, max_segments=3, checkpoint_s=0)
        heads = {}
        for i in range(40):
            lg.add("admit", "dev%d" % i, {"i": i}, T0 + i)
            b, = [x for x in lg.flush(T0 + i)]
            heads[b.batch] = b.head
            self.assertLessEqual(len(audit.segments(self.d)), 4)     # max_segments, and the one this flush began
        self.assertEqual(audit.segments(self.d)[-1][0], len(audit.segments(self.d)) + audit.segments(self.d)[0][0] - 1)
        self.refused("what came before is missing")
        rep = audit.verify(self.d, [VPK], allow_pruned=True, with_entries=True)
        self.assertTrue(rep["pruned"])
        pruned = [e for e in rep["entries"] if e["event"] == "pruned"]
        self.assertTrue(pruned)
        # each names the segments it deleted and the last batch they held, by number and hash: an anchor from
        # before is accounted for, not silently gone
        last = pruned[-1]["details"]
        self.assertEqual(last["last_head"], heads[last["last_batch"]])
        self.assertEqual(last["max_segments"], 3)
        self.assertLess(last["last_batch"], rep["logs"][0]["first_batch"])
        self.assertEqual(rep["logs"][0]["first_batch"], last["last_batch"] + 1)
        nums = [p["details"]["segments"] for p in pruned]
        self.assertEqual([a for a, _ in nums[1:]], [b + 1 for _, b in nums[:-1]])     # every segment, once
        with self.assertRaises(ValueError):
            self.log(max_segments=1)
        # 0, the default: nothing is ever deleted
        self.d = os.path.join(tempfile.mkdtemp(), "audit")
        lg = self.log(segment_bytes=20000, checkpoint_s=0)
        for i in range(40):
            lg.add("admit", "dev", {}, T0 + i)
            lg.flush(T0 + i)
        self.assertGreater(len(audit.segments(self.d)), 4)
        self.assertNotIn("pruned", [e for e, _ in events(self.d)])

    def test_a_batch_is_not_an_attestation_result_nor_the_other_way(self):
        """One key signs both; the typ in the protected header, under the signature, says which it is."""
        lg = self.log()
        lg.add("start", None, {}, T0)
        batch = lg.flush(T0)[0].raw
        ear = cose.sign1(VSK, VPK, eat.ear_payload({"endpoint": "dev", "admitted": False, "reasons": ["x"]},
                                                   {"stage": "policy"}, eat.policy_id(b"{}"), T0))
        self.assertEqual(eat.read_ear(ear, VPK)["status"], "incomplete")
        with self.assertRaises(cose.Refused):
            eat.read_ear(batch, VPK)
        with self.assertRaises((cose.Refused, audit.Refused)):
            audit.open_batch(ear, VPK)
        # and the batch's claims under the result's typ are not a batch
        payload = cose.parse(batch).payload
        with self.assertRaises((cose.Refused, audit.Refused)):
            audit.open_batch(cose.sign1(VSK, VPK, payload), VPK)
        for junk in (b"", b"\xd2", batch[:-1], batch + b"\x00", cbor.dumps([1, 2, 3]),
                     cose.sign1(VSK, VPK, cbor.dumps({1: AUDIT_FORMAT}, sort=True), typ=AUDIT_TYP),
                     cose.sign1(VSK, VPK, cbor.dumps({**cbor.loads(payload), 9: 1}, sort=True), typ=AUDIT_TYP),
                     cose.sign1(VSK, VPK, cbor.dumps({**cbor.loads(payload), 3: 0}, sort=True), typ=AUDIT_TYP)):
            with self.assertRaises((cose.Refused, audit.Refused)):
                audit.open_batch(junk, VPK)


class Fleet(unittest.TestCase):
    """A verifier's policy directory and state, a classical endpoint that attests and one that does not answer."""

    @classmethod
    def setUpClass(cls):
        cls.iak = ec.generate_private_key(ec.SECP256R1())

    def setUp(self):
        # these tests cycle in milliseconds and look at each cycle's batch: no waiting for min_interval_s (its
        # default is tested by itself)
        patch = mock.patch.dict(fleet.AUDIT_SETTINGS, min_interval_s=0)
        patch.start()
        self.addCleanup(patch.stop)
        self.d, self.state = tempfile.mkdtemp(), make_state()
        with open(os.path.join(self.d, "iak.pem"), "wb") as f:
            f.write(self.iak.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
        with open(os.path.join(self.d, "pq.pub"), "w") as f:
            f.write(tf.PQ_KEYS[0][0].hex() + "\n")
        self.allowed = [{"type": "SPE", "measurement_value": tf.GOOD_S, "signer_id": tf.SIGNER},
                        {"type": "NSPE", "measurement_value": tf.GOOD_NS, "signer_id": tf.SIGNER}]
        self.good = tf.FakeEndpoint(self.iak, "good")
        self.policy = {"timeout_s": 2, "audit_log": True, "endpoints": [
            {"name": "good", "host": "127.0.0.1", "port": self.good.port, "iak_pub_pem": "iak.pem",
             "allowed": self.allowed},
            {"name": "legacy", "host": "127.0.0.1", "port": te.closed_port(), "iak_pub_pem": "iak.pem", "allowed": []}]}
        self.save()
        self.audit_dir = os.path.join(self.state, "audit")

    def save(self, policy=None):
        self.pol = os.path.join(self.d, "fleet.json")
        with open(self.pol, "w") as f:
            json.dump(self.policy if policy is None else policy, f, indent=1)
        with open(self.pol, "rb") as f:
            self.policy_bytes = f.read()

    def pq(self, mode="kem-good", **kw):
        dev = tf.FakeEndpoint(self.iak, mode)
        e = dict({"name": "pq", "kind": "aegis-pq", "host": "127.0.0.1", "port": dev.port, "pq_pub_file": "pq.pub",
                  "allowed": self.allowed}, **kw)
        self.policy["endpoints"].append(e)
        self.save()
        return dev, e

    def trail(self, **kw):
        return fleet.open_audit(self.policy, self.state, start={"cmd": "test"}, **kw)

    def cycle(self, trail, **kw):
        res = fleet.run_once(self.policy, self.d, VERIFY, credentials=kw.pop("credentials", False), state=self.state,
                             policy_bytes=self.policy_bytes, audit=trail, **kw)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            written = trail.flush() if trail is not None else []
        self.said = err.getvalue()
        return res, written

    def fleet(self, *argv):
        return run(fleet.main, [*argv, "--state-dir", self.state, "--platform", "linux", "--verifier", "cryptography"])

    def verdicts(self, *argv):
        """The verdicts a fleet.py command printed (after the lines it wrote to stderr)."""
        out = self.fleet(*argv)[1]
        return json.loads(out[out.index("[\n"):])

    def entries(self, **kw):
        return audit.verify(self.audit_dir, [VPK], with_entries=True, **kw)["entries"]

    def events(self):
        return [(e["event"], e["subject"]) for e in self.entries()]


class Trail(Fleet):
    """fleet.py: what goes into the log, and when."""

    def test_off_by_default_nothing_is_written_and_no_key_is_opened(self):
        del self.policy["audit_log"]
        self.save()
        self.assertIsNone(fleet.audit_settings(self.policy))
        self.assertIsNone(fleet.open_audit(self.policy, self.state))
        before = sorted(os.listdir(self.state))
        with mock.patch.object(fleet, "load_gateway_identity", side_effect=AssertionError("the key was opened")):
            rc, out = self.fleet("once", self.pol)
        self.assertEqual(rc, 0, out)
        v = json.loads(out)
        self.assertEqual([x["admitted"] for x in v], [True, False])
        self.assertEqual(sorted(os.listdir(self.state)), before)     # no audit/, nothing else either
        self.assertNotIn("aegis-audit", out)
        # only the JSON value true, or the settings, turn it on
        for off in (False, None):
            self.assertIsNone(fleet.audit_settings({"audit_log": off}))
        self.assertEqual(DEFAULT_AUDIT, {"checkpoint_s": 3600, "min_interval_s": 300, "segment_bytes": 1 << 20,
                                         "max_segments": 0})
        self.assertEqual(fleet.audit_settings({"audit_log": True}), fleet.AUDIT_SETTINGS)
        self.assertEqual(fleet.audit_settings({"audit_log": {"min_interval_s": 300}})["min_interval_s"], 300)

    def test_a_setting_this_verifier_does_not_know_is_no_log_and_said_loudly(self):
        for bad in ("true", 1, "yes", [], {"checkpoint": 60}, {"checkpoint_s": -1}, {"checkpoint_s": 1.5},
                    {"segment_bytes": 100}, {"min_interval_s": True}, {"max_segments": 1}, {"max_segments": -2}):
            with self.assertRaises(ValueError, msg=repr(bad)):
                fleet.audit_settings({"audit_log": bad})
        self.policy["audit_log"] = "yes"
        self.save()
        said = [None]
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertIsNone(fleet.open_audit(self.policy, self.state, said=said))
            self.assertIsNone(fleet.open_audit(self.policy, self.state, said=said))
        self.assertEqual(err.getvalue().count("NO AUDIT LOG is kept"), 1)     # once, not every cycle
        rc, out = self.fleet("check", self.pol)
        self.assertEqual(rc, 1)
        self.assertIn("audit log: REFUSED", out)
        # asked for, and no identity to sign with
        self.policy["audit_log"] = True
        self.save()
        os.unlink(os.path.join(self.state, "identity.json"))
        with contextlib.redirect_stderr(err):
            self.assertIsNone(fleet.open_audit(self.policy, self.state, said=said))
        self.assertIn("no verifier identity", err.getvalue())
        rc, out = self.fleet("check", self.pol)
        self.assertEqual(rc, 1)
        self.assertIn("NO verifier identity to sign it with", out)

    def test_the_first_cycle_logs_every_decision_and_a_steady_fleet_then_writes_nothing(self):
        trail = self.trail()
        trail.policy({"sha256": hashlib.sha256(self.policy_bytes).hexdigest(), "signed": False}, self.policy)
        loads = []
        real = trail.log._load_sk
        trail.log._load_sk = lambda: loads.append(1) or real()
        res, written = self.cycle(trail)
        self.assertEqual([v["admitted"] for v in res], [True, False])
        self.assertEqual((len(written), len(loads)), (1, 1))         # one batch, one signature, for the whole cycle
        self.assertIn("aegis-audit: batch 1 of log", self.said)
        self.assertIn("sha256 %s" % written[0].head.hex(), self.said)
        self.assertEqual(self.events(), [("log-start", None), ("start", None), ("policy", None), ("admit", "good"),
                                         ("refuse", "legacy")])
        e = self.entries()
        self.assertEqual(e[2]["details"], {"sha256": hashlib.sha256(self.policy_bytes).digest(), "signed": False})
        self.assertEqual(e[3]["details"], {"kind": "psa", "stage": "appraised", "evidence_format": "psa-token",
                                           "address": "127.0.0.1:%d" % self.good.port,
                                           "measurements": {"SPE": bytes.fromhex(tf.GOOD_S),
                                                            "NSPE": bytes.fromhex(tf.GOOD_NS)}})
        self.assertEqual(e[4]["details"]["stage"], "no-evidence")
        self.assertTrue(e[4]["details"]["reasons"][0].startswith("no attestation"))
        # a verdict has nothing of the log in it: the state file and the `once` output are what they were
        self.assertFalse([k for v in res for k in v if "audit" in k])
        size = os.path.getsize(audit.segments(self.audit_dir)[0][1])
        for _ in range(5):
            res, written = self.cycle(trail)
            self.assertEqual(([v["admitted"] for v in res], written, self.said), ([True, False], [], ""))
        self.assertEqual((os.path.getsize(audit.segments(self.audit_dir)[0][1]), len(loads)), (size, 1))
        self.assertLess(size, 4500)

    def test_a_decision_that_changes_is_an_entry_and_one_that_only_words_itself_differently_is_not(self):
        trail = self.trail()
        self.cycle(trail)
        self.good.mode = "tampered"
        res, written = self.cycle(trail)
        self.assertEqual(len(written), 1)
        e = self.entries()[-1]
        self.assertEqual((e["event"], e["subject"], e["details"]["stage"]), ("refuse", "good", "appraised"))
        self.assertEqual(e["details"]["measurements"]["NSPE"], bytes.fromhex("99" * 32))
        self.assertTrue(any("NSPE not allowed" in r for r in e["details"]["reasons"]))
        self.assertEqual(self.cycle(trail)[1], [])           # still tampered: nothing new to say
        self.good.mode = "garbage"                           # now it sends nothing usable: another decision
        self.assertEqual(len(self.cycle(trail)[1]), 1)
        self.assertEqual(self.entries()[-1]["details"]["stage"], "no-evidence")
        # the same refusal in other words (another error text, cycle after cycle) is the same decision
        for mode in ("silent", "garbage"):
            self.good.mode = mode
            with mock.patch.object(fleet, "BUSY_RETRIES", 0):
                self.assertEqual(self.cycle(trail)[1], [], mode)
        self.good.mode = "good"
        self.assertEqual(len(self.cycle(trail)[1]), 1)
        self.assertEqual(self.events()[-4:], [("refuse", "legacy"), ("refuse", "good"), ("refuse", "good"),
                                              ("admit", "good")])

    def test_sessions_issued_revoked_and_ended_are_entries(self):
        dev, entry = self.pq(provision=True)
        trail = self.trail()
        res, _ = self.cycle(trail, credentials=True)
        self.assertTrue(res[2]["credential"].startswith("issued session"), res[2])
        e = self.entries()
        self.assertEqual([(x["event"], x["subject"]) for x in e][-2:], [("issue", "pq"), ("admit", "pq")])
        meta = os.path.join(self.state, "credentials", "pq.json")
        with open(meta) as f:
            first = json.load(f)
        self.assertEqual(e[-2]["details"]["session"], bytes.fromhex(first["session_id"]))
        self.assertEqual((e[-2]["details"]["binding"], e[-2]["details"]["expires"]), ("unbound", first["body"]["expires"]))
        self.assertEqual((e[-1]["details"]["device_key_sha256"], e[-1]["details"]["enrolment"]),
                         (hashlib.sha256(tf.PQ_KEYS[0][0]).digest(), "trust-on-first-use"))
        for _ in range(3):                                   # heartbeats: the session lives, nothing to say
            res, written = self.cycle(trail, credentials=True)
            self.assertTrue(res[2]["credential"].startswith("valid, heartbeat"), res[2])
            self.assertEqual(written, [])
        dev.expired = True                                   # the endpoint dropped it: replaced before its time
        self.cycle(trail, credentials=True)
        e = self.entries()
        self.assertEqual([(x["event"], x["subject"]) for x in e][-2:], [("revoke", "pq"), ("issue", "pq")])
        self.assertEqual((e[-2]["details"]["session"], e[-2]["details"]["replaced"]),
                         (bytes.fromhex(first["session_id"]), True))
        with open(meta) as f:                                # the stored one reaches its renewal window
            m = json.load(f)
        m["body"]["expires"] = int(time.time()) + 100
        with open(meta, "w") as f:
            json.dump(m, f)
        self.cycle(trail, credentials=True)
        e = self.entries()
        self.assertEqual([(x["event"], x["subject"]) for x in e][-2:], [("expiry", "pq"), ("issue", "pq")])
        self.assertEqual(e[-2]["details"], {"session": bytes.fromhex(m["session_id"]), "expires": m["body"]["expires"]})
        dev.mode = "pq-tampered"                             # quarantined: the session goes with the admission
        res, _ = self.cycle(trail, credentials=True)
        self.assertEqual(res[2]["credential"], "revoked")
        e = self.entries()
        self.assertEqual([(x["event"], x["subject"]) for x in e][-2:], [("revoke", "pq"), ("refuse", "pq")])
        self.assertEqual(e[-2]["details"]["replaced"], False)
        self.assertEqual(self.cycle(trail, credentials=True)[1], [])     # "revoked" every cycle is said once

    def test_a_policy_change_and_an_endpoint_that_left_are_entries(self):
        trail = self.trail()
        info = {"sha256": hashlib.sha256(self.policy_bytes).hexdigest(), "signed": False}
        trail.policy(info, self.policy)
        self.cycle(trail)
        trail.policy(info, self.policy)                      # every cycle; said once
        self.assertEqual(self.cycle(trail)[1], [])
        old = self.policy_bytes
        del self.policy["endpoints"][1]
        self.save()
        trail.policy({"sha256": hashlib.sha256(self.policy_bytes).hexdigest(), "signed": True, "version": 7,
                      "signer": "ops", "signer_key_sha256": "ab" * 32, "file_sha256": "cd" * 32}, self.policy)
        trail.policy_refused("x.cose refused: version 3 is older")
        trail.policy_refused("x.cose refused: version 3 is older")
        self.cycle(trail)
        e = self.entries()
        self.assertEqual([(x["event"], x["subject"]) for x in e][-3:], [("policy", None), ("remove", "legacy"),
                                                                        ("policy-refused", None)])
        self.assertEqual(e[-3]["details"], {
            "sha256": hashlib.sha256(self.policy_bytes).digest(), "previous_sha256": hashlib.sha256(old).digest(),
            "signed": True, "version": 7, "signer": "ops", "signer_key_sha256": b"\xab" * 32,
            "file_sha256": b"\xcd" * 32})
        self.assertEqual(e[-1]["details"]["in_use_sha256"], hashlib.sha256(self.policy_bytes).digest())

    def test_two_entries_of_one_name_do_not_take_turns_in_the_log(self):
        """A decision is remembered by the entry's name and address: a policy that names two devices alike (which
        nothing forbids) must not cost a batch every cycle."""
        self.policy["endpoints"][1]["name"] = "good"         # admitted at one address, refused at the other
        self.save()
        trail = self.trail()
        trail.policy({"sha256": "00" * 32, "signed": False}, self.policy)
        self.assertEqual(len(self.cycle(trail)[1]), 1)
        self.assertEqual(self.events()[-2:], [("admit", "good"), ("refuse", "good")])
        for _ in range(3):
            trail.policy({"sha256": "00" * 32, "signed": False}, self.policy)
            self.assertEqual(self.cycle(trail)[1], [])
        gone = self.policy["endpoints"].pop(1)               # one of them leaves: said with its address
        self.save()
        trail.policy({"sha256": "11" * 32, "signed": False}, self.policy)
        self.cycle(trail)
        e = self.entries()
        self.assertEqual([(x["event"], x["subject"]) for x in e][-2:], [("policy", None), ("remove", "good")])
        self.assertEqual(e[-1]["details"]["address"], "127.0.0.1:%d" % gone["port"])

    def test_the_policy_no_longer_asks_and_the_log_says_so(self):
        trail = self.trail()
        self.cycle(trail)
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.assertIs(fleet.open_audit(self.policy, self.state, trail), trail)       # the same settings: the same
            self.assertIsNone(fleet.open_audit({"endpoints": []}, self.state, trail))
        e = self.entries()[-1]
        self.assertEqual((e["event"], e["details"]["why"]), ("stop", "the policy no longer asks for an audit log"))
        self.assertIsNone(audit.verify(self.audit_dir, [VPK])["logs"][0]["due"])     # and promises nothing more

    def test_nothing_a_verdict_holds_stops_the_loop_or_spoils_the_log(self):
        trail = self.trail()
        tag = cbor.Tag(1, 2)
        for v, facts in (({}, {}), ({"endpoint": None, "admitted": "yes", "measurements": {tag: tag, 1: [1.5]}}, {"stage": tag}),
                         ({"endpoint": "x" * 500, "admitted": True, "time": "noon", "reasons": "abc",
                           "endorsement": [], "quote": 5, "attestation_result": "no", "device_pk_sha256": 7}, {}),
                         ({"endpoint": "dev", "admitted": False, "reasons": [object()] * 50, "warning": b"\xff" * 999,
                           "measurements": {"m%d" % i: "zz" for i in range(60)}}, {"format": {}})):
            trail.decision(v, facts)
        trail.session_change({"name": "../../etc"}, {"id": 5, "expires": "soon"}, object())
        trail.session_change({}, None, None)
        trail.policy({"sha256": None}, {"endpoints": 5})
        trail.policy_refused(object())
        self.assertEqual(len(self.cycle(trail)[1]), 1)
        for _ in range(3):                                   # what cannot be noted is said once, not every cycle
            trail.session_change({}, {"id": 5}, None)
            trail.policy({"sha256": None}, {"endpoints": 5})
        self.assertEqual([(e[2], e[4]["what"]) for e in trail.log.pending], [("audit-error", "session")])
        ev = self.events()
        errors = [e for e in self.entries() if e["event"] == "audit-error"]
        self.assertEqual(len(errors), len({(e["details"]["what"], e["details"]["error"]) for e in errors}))
        self.assertGreaterEqual(len(ev), 8)
        self.assertEqual([e for e in ev if e[0] in ("admit", "refuse")][:3], [("refuse", "None"), ("refuse", "None"),
                                                                             ("admit", "x" * 64)])

    def test_a_log_that_cannot_be_written_stops_no_verdict_and_is_said_once(self):
        os.rename(os.path.join(self.state, "identity.sk"), os.path.join(self.state, "identity.sk.away"))
        trail = self.trail()
        res, written = self.cycle(trail)
        self.assertEqual(([v["admitted"] for v in res], written), ([True, False], []))
        self.assertIn("could NOT be written", self.said)
        res, written = self.cycle(trail)
        self.assertEqual(([v["admitted"] for v in res], written, self.said), ([True, False], [], ""))
        os.rename(os.path.join(self.state, "identity.sk.away"), os.path.join(self.state, "identity.sk"))
        self.assertEqual(len(self.cycle(trail)[1]), 1)
        self.assertEqual(self.events()[1:], [("start", None), ("admit", "good"), ("refuse", "legacy")])

    def test_settings_changed_while_the_log_cannot_be_written_lose_nothing_silently(self):
        os.rename(os.path.join(self.state, "identity.sk"), os.path.join(self.state, "identity.sk.away"))
        trail = self.trail()
        self.cycle(trail)
        self.assertIn("could NOT be written", self.said)
        held = len(trail.log.pending)
        self.policy["audit_log"] = {"checkpoint_s": 1800, "min_interval_s": 0}
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            new = fleet.open_audit(self.policy, self.state, trail, start={"cmd": "test"})
        self.assertIsNot(new, trail)
        self.assertIn("3 entries carried over, 0 lost", err.getvalue())     # start, admit, refuse; not log-start
        self.assertEqual(held, 4)
        os.rename(os.path.join(self.state, "identity.sk.away"), os.path.join(self.state, "identity.sk"))
        self.cycle(new)
        self.assertEqual([e for e in self.events() if e[0] != "log-start"][:5],
                         [("start", None), ("admit", "good"), ("refuse", "legacy"), ("gap", None), ("start", None)])
        gap = [e for e in self.entries() if e["event"] == "gap"][0]["details"]
        self.assertEqual((gap["carried"], gap["dropped"]), (3, 0))
        self.assertIn("settings changed", gap["why"])
        # more than memory holds: what does not fit is counted in the gap, not dropped unsaid
        old = fleet.AuditTrail(self.state, fleet.audit_settings(self.policy))
        for i in range(audit.MAX_PENDING + 5):
            old.log.add("refuse", "dev%d" % i)
        old.log._load_sk = mock.Mock(side_effect=OSError("no key"))
        new = fleet.AuditTrail(self.state, dict(fleet.AUDIT_SETTINGS), start={"cmd": "test"})
        with contextlib.redirect_stderr(err):
            fleet._hand_over(old, new)
        g = new.log.pending[audit.MAX_PENDING - 2]
        self.assertEqual((g[audit.E_EVENT], g[audit.E_DETAILS]["carried"], g[audit.E_DETAILS]["dropped"]),
                         ("gap", audit.MAX_PENDING - 2, 3))      # 512 + its own "gap" entry, less what fits

    def test_an_identity_made_again_while_the_loop_runs_writes_nothing_and_is_said(self):
        trail = self.trail()
        self.cycle(trail)
        before = [(n, os.path.getsize(p)) for n, p in audit.segments(self.audit_dir)]
        with open(os.path.join(self.state, "identity.json"), "w") as f:      # aegisd.py init, again
            json.dump({"body": {"v": 1, "type": "identity", "pk": XPK.hex()}}, f)
        with open(os.path.join(self.state, "identity.sk"), "wb") as f:
            f.write(XSK)
        self.good.mode = "tampered"
        res, written = self.cycle(trail)
        self.assertEqual(([v["admitted"] for v in res], written), ([False, False], []))
        self.assertIn("could NOT be written (KeyMismatch", self.said)
        self.assertIn("identity made again", self.said)
        for _ in range(3):
            self.assertEqual(self.cycle(trail)[1], [])
        self.assertEqual([(n, os.path.getsize(p)) for n, p in audit.segments(self.audit_dir)], before)
        self.assertEqual(audit.verify(self.audit_dir, [VPK])["logs"][0]["last_batch"], 1)

    def test_once_logs_a_run_and_the_audit_command_checks_and_anchors_the_log(self):
        rc, out = self.fleet("once", self.pol)
        self.assertEqual(rc, 0, out)
        self.assertIn("aegis-audit: batch 1", out)
        rc, out = self.fleet("once", self.pol)
        self.assertEqual(self.events(), [("log-start", None)] + [("start", None), ("policy", None), ("admit", "good"),
                                                                 ("refuse", "legacy")] * 2)
        anchor = os.path.join(tempfile.mkdtemp(), "anchor.cbor")
        rc, out = self.fleet("audit", self.pol, "--entries", "--out", anchor)
        rep = json.loads(out)
        self.assertEqual((rc, rep["verified"], rep["logs"][0]["last_batch"], rep["logs"][0]["entries"], rep["stale"]),
                         (0, True, 2, 9, False))
        self.assertEqual(rep["entries"][3]["details"]["measurements"]["SPE"], tf.GOOD_S)
        with open(anchor, "rb") as f:
            kept = f.read()
        self.assertEqual((kept, rep["anchor"]["sha256"]), (records(self.audit_dir)[-1], rep["logs"][0]["head"]))
        # the end cut off: the log alone still verifies; with the anchor it does not
        write_records(self.audit_dir, records(self.audit_dir)[:1])
        self.assertEqual(self.fleet("audit", self.pol)[0], 0)
        with self.assertRaises(audit.Refused):
            audit.verify(self.audit_dir, [VPK], anchors=[kept])
        with open(audit.segments(self.audit_dir)[0][1], "r+b") as f:
            f.seek(400)
            f.write(b"\x00")
        rc, out = self.fleet("audit", self.pol)
        self.assertEqual((rc, json.loads(out)["verified"]), (1, False))

    def test_an_enrolment_is_an_entry(self):
        dev, entry = self.pq("pq-good", pq_pub_file="new.pub")
        rc, out = self.fleet("enroll-pq", self.pol)
        self.assertEqual(rc, 0, out)
        self.assertIn("enrolled pq by trust on first use", out)
        e = self.entries()
        self.assertEqual([(x["event"], x["subject"]) for x in e], [("log-start", None), ("policy", None), ("enrol", "pq")])
        self.assertEqual(e[-1]["details"], {"how": "trust-on-first-use", "forced": False,
                                            "device_key_sha256": hashlib.sha256(tf.PQ_KEYS[0][0]).digest(),
                                            "from": "127.0.0.1:%d" % dev.port})
        rc, out = self.fleet("enroll-pq", self.pol)          # kept: nothing enrolled, nothing logged
        self.assertEqual(len(self.entries()), 3)
        del self.policy["audit_log"]                         # and without the key in the policy, as before
        self.save()
        os.unlink(os.path.join(self.d, "new.pub"))
        shutil.rmtree(self.audit_dir)
        self.assertEqual(self.fleet("enroll-pq", self.pol)[0], 0)
        self.assertFalse(os.path.exists(self.audit_dir))


def signers(*keys, audience=None, where=None):
    """A signers file for [(name, pk)] in a new directory (or in where, the verifier's state)."""
    path = os.path.join(where or tempfile.mkdtemp(), "policy-signers.json")
    with open(path, "wb") as f:
        f.write(signed_policy.signers_file(keys or [("ops", OPK)], audience))
    return path


POLICY = b'{"timeout_s": 2, "endpoints": [{"name": "dev", "host": "192.0.2.1", "port": 7444, "allowed": []}]}\n'


class Policy(unittest.TestCase):
    """common/signed_policy.py."""

    def setUp(self):
        self.trust = signed_policy.load_signers(signers())["keys"]

    def refused(self, data, text="", trust=None, audience=None):
        with self.assertRaises((signed_policy.Refused, cose.Refused)) as c:
            signed_policy.open_signed(data, self.trust if trust is None else trust, audience)
        self.assertIn(text, str(c.exception))

    def claims(self, **edit):
        c = {1: POLICY_FORMAT, 2: 3, 3: T0, 4: POLICY, 5: "ops"}
        c.update({int(k[1:]): v for k, v in edit.items()})
        return cbor.dumps({k: v for k, v in c.items() if v is not None}, sort=True)

    def test_a_signed_policy_is_the_document_s_bytes(self):
        data = signed_policy.sign(OSK, OPK, POLICY, 3, "ops", T0, "bench")
        self.assertTrue(signed_policy.is_signed(data))
        self.assertFalse(signed_policy.is_signed(POLICY))
        protected, unprotected, payload, sig = cbor.loads(data).value
        self.assertEqual(cbor.loads(protected), {1: -49, 4: cose.key_thumbprint(OPK), 16: POLICY_TYP})
        self.assertEqual(cbor.loads(payload), {1: POLICY_FORMAT, 2: 3, 3: T0, 4: POLICY, 5: "ops", 6: "bench"})
        self.assertTrue(mldsa.verify_raw(OPK, cbor.dumps(["Signature1", protected, b"", payload]), sig))
        o = signed_policy.open_signed(data, self.trust, "bench")
        self.assertEqual((o["policy_bytes"], o["version"], o["issued"], o["signer_name"], o["audience"]),
                         (POLICY, 3, T0, "ops", "bench"))
        self.assertEqual(o["policy"], json.loads(POLICY))
        # the policy keeps its name: an attestation result names the same policy, signed or not
        self.assertEqual((o["policy_sha256"], o["signed_sha256"], o["signer_key_sha256"]),
                         (hashlib.sha256(POLICY).hexdigest(), hashlib.sha256(data).hexdigest(),
                          hashlib.sha256(OPK).hexdigest()))
        self.assertEqual(signed_policy.open_signed(self.sign(self.claims()), self.trust)["version"], 3)

    def sign(self, payload, sk=OSK, pk=OPK, typ=POLICY_TYP):
        return cose.sign1(sk, pk, payload, typ=typ)

    def test_only_a_policy_signer_s_signature_over_exactly_a_policy_is_accepted(self):
        good = signed_policy.sign(OSK, OPK, POLICY, 3, "ops", T0)
        # another key: the verifier's own identity cannot sign a policy, nor can anyone else
        self.refused(signed_policy.sign(VSK, VPK, POLICY, 3, "ops", T0), "not a policy signer of this verifier")
        self.refused(signed_policy.sign(XSK, XPK, POLICY, 3, "ops", T0), "not a policy signer")
        self.refused(good, "not a policy signer", trust={})
        # the signer's signature on something else is not a policy (typ is under the signature)
        self.refused(cose.sign1(OSK, OPK, self.claims()), "not a signed policy")
        self.refused(self.sign(self.claims(), typ=AUDIT_TYP), "not a signed policy")
        # altered bytes; another encoding of the same object; an older Aegis signature of the same key
        self.refused(good[:300] + bytes([good[300] ^ 1]) + good[301:])
        self.refused(good + b"\x00")
        self.refused(good[:-1])
        tag = cbor.loads(good)
        self.refused(cose.assemble(tag.value[0], self.claims(_2=4), tag.value[3]), "signature does not verify")
        self.refused(cose.assemble(tag.value[0], tag.value[2], mldsa.sign(OSK, b"aegis-policy", tag.value[2])),
                     "signature does not verify")
        self.refused(self.sign(cbor.dumps(dict(reversed(list(cbor.loads(self.claims()).items()))))),
                     "deterministic encoding")              # the same claims, keys not in order
        # signed, and not the claims of a policy
        for name, payload in (("an unknown claim", self.claims(_7=1)), ("no version", self.claims(_2=None)),
                              ("version 0", self.claims(_2=0)), ("a version that is not a number", self.claims(_2="3")),
                              ("a boolean version", self.claims(_2=True)), ("no policy", self.claims(_4=None)),
                              ("another format", self.claims(_1=POLICY_FORMAT[:-1] + "2")),
                              ("a signer that is not text", self.claims(_5=5)),
                              ("an empty audience", self.claims(_6="")), ("not a map", cbor.dumps([1, 2])),
                              ("a policy that is not JSON", self.claims(_4=b"\xff{")),
                              ("a policy that is a list", self.claims(_4=b"[]")),
                              ("a policy without endpoints", self.claims(_4=b"{}")),
                              ("a name twice", self.claims(_4=b'{"endpoints": [], "endpoints": [{"name": "x"}]}')),
                              ("a name twice in an entry",
                               self.claims(_4=b'{"endpoints": [{"name": "a", "allowed": [], "allowed": [1]}]}')),
                              ("deeper than a parser goes", self.claims(_4=b'{"endpoints": ' + b"[" * 100000))):
            with self.assertRaises((signed_policy.Refused, cose.Refused), msg=name):
                signed_policy.open_signed(self.sign(payload), self.trust)
        for junk in (b"", b"{}", POLICY, b"\xd2", b"\xd2\x84", cbor.dumps(cbor.Tag(18, [b"", {}, b"", b""]))):
            with self.assertRaises((signed_policy.Refused, cose.Refused)):
                signed_policy.open_signed(junk, self.trust)

    def test_a_policy_for_another_fleet_is_refused_where_the_verifier_has_a_fleet(self):
        for_bench = signed_policy.sign(OSK, OPK, POLICY, 1, "ops", T0, "bench")
        for_any = signed_policy.sign(OSK, OPK, POLICY, 1, "ops", T0)
        signed_policy.open_signed(for_bench, self.trust, "bench")
        self.refused(for_bench, "this verifier's fleet is 'plant'", audience="plant")
        self.refused(for_any, "no fleet in particular", audience="plant")
        # a verifier without a fleet name takes either: the name is for operators with more than one fleet
        signed_policy.open_signed(for_bench, self.trust)
        signed_policy.open_signed(for_any, self.trust)

    def test_the_version_only_goes_up(self):
        state = tempfile.mkdtemp()

        def opened(version, policy=POLICY):
            return signed_policy.open_signed(signed_policy.sign(OSK, OPK, policy, version, "ops", T0), self.trust)
        other = POLICY.replace(b"192.0.2.1", b"192.0.2.66")
        self.assertIsNone(signed_policy.last_version(state))
        signed_policy.check_version(opened(5), None)                 # a verifier that has seen none takes any
        signed_policy.remember_version(state, opened(5), T0)
        last = signed_policy.last_version(state)
        self.assertEqual((last["version"], last["policy_sha256"], last["accepted"]),
                         (5, hashlib.sha256(POLICY).hexdigest(), T0))
        signed_policy.check_version(opened(5), last)                 # the same policy again: the loop reloads it
        signed_policy.check_version(opened(6, other), last)
        signed_policy.check_version(opened(900), last)               # numbers may be skipped
        for version, policy, why in ((4, POLICY, "rollback refused"), (1, other, "rollback refused"),
                                     (5, other, "already accepted for another policy")):
            with self.assertRaises(signed_policy.Refused) as c:
                signed_policy.check_version(opened(version, policy), last)
            self.assertIn(why, str(c.exception))
        signed_policy.remember_version(state, opened(4), T0)         # remembering an older one changes nothing
        self.assertEqual(signed_policy.last_version(state)["version"], 5)
        signed_policy.remember_version(state, opened(6, other), T0)
        self.assertEqual(signed_policy.last_version(state)["version"], 6)
        self.assertEqual([n for n in os.listdir(state) if ".tmp." in n], [])
        # a record that cannot be read is not a counter at zero
        for junk in (b"", b"{}", b'{"format": "aegis-policy-version-v1", "version": "9"}', b"\xff"):
            with open(os.path.join(state, "policy-version.json"), "wb") as f:
                f.write(junk)
            with self.assertRaises(signed_policy.Refused):
                signed_policy.last_version(state)

    def test_a_signers_file_is_one_or_more_keys_or_it_is_refused(self):
        two = signed_policy.load_signers(signers(("ops", OPK), ("second", XPK), audience="bench"))
        self.assertEqual((sorted(k["name"] for k in two["keys"].values()), two["audience"]), (["ops", "second"], "bench"))
        self.assertEqual(set(two["keys"]), {cose.key_thumbprint(OPK), cose.key_thumbprint(XPK)})
        good = json.loads(signed_policy.signers_file([("ops", OPK)]))
        for name, doc in (("no keys", dict(good, signers=[])), ("another format", dict(good, format="v2")),
                          ("a key twice", dict(good, signers=good["signers"] * 2)),
                          ("a short key", dict(good, signers=[{"name": "ops", "pk": "abcd"}])),
                          ("not hex", dict(good, signers=[{"name": "ops", "pk": "zz" * 1952}])),
                          ("no name", dict(good, signers=[{"pk": OPK.hex()}])),
                          ("an unknown key", dict(good, signers=[{"name": "ops", "pk": OPK.hex(), "admin": True}])),
                          ("an unknown setting", dict(good, require=False)), ("a list", [good]),
                          ("an audience that is not text", dict(good, audience=5))):
            path = os.path.join(tempfile.mkdtemp(), "policy-signers.json")
            with open(path, "w") as f:
                json.dump(doc, f)
            with self.assertRaises(signed_policy.Refused, msg=name):
                signed_policy.load_signers(path)
        # the verifier's own identity key is not a policy signer: the verifier holds no key that can sign a policy
        path = signers(("ops", OPK), ("me", VPK))
        self.assertEqual(len(signed_policy.load_signers(path)["keys"]), 2)
        with self.assertRaises(signed_policy.Refused) as c:
            signed_policy.load_signers(path, VPK)
        self.assertIn("signer me is this verifier's own identity key", str(c.exception))
        self.assertEqual(len(signed_policy.load_signers(path, XPK)["keys"]), 2)
        state = make_state()
        shutil.copy(path, os.path.join(state, "policy-signers.json"))
        with self.assertRaises(fleet.PolicyRefused) as c:
            fleet.policy_signers(state)
        self.assertIn("own identity key", str(c.exception))
        for junk in (b"", b"\xff", b'{"format": "aegis-policy-signers-v1", "signers": [], "signers": []}'):
            path = os.path.join(tempfile.mkdtemp(), "policy-signers.json")
            with open(path, "wb") as f:
                f.write(junk)
            with self.assertRaises(signed_policy.Refused):
                signed_policy.load_signers(path)


class Verifier(Fleet):
    """fleet.py with and without policy-signing keys."""

    def setUp(self):
        Fleet.setUp(self)
        del self.policy["audit_log"]
        self.save()
        self.version = 0

    def sign(self, policy=None, version=None, sk=OSK, pk=OPK, audience=None, name="fleet.cose"):
        """Sign the policy (a dict, bytes, or the one of this test) as the next version; returns the file."""
        data = self.policy_bytes if policy is None else policy if isinstance(policy, bytes) else \
            (json.dumps(policy, indent=1) + "\n").encode()
        self.version = self.version + 1 if version is None else version
        path = os.path.join(self.d, name)
        with open(path, "wb") as f:
            f.write(signed_policy.sign(sk, pk, data, self.version, "ops", T0, audience))
        return path

    def require(self, *keys, audience=None):
        return signers(*keys, audience=audience, where=self.state)

    def load(self, path, **kw):
        return fleet.load_policy(path, self.state, **kw)

    def refused(self, path, text, **kw):
        with self.assertRaises(fleet.PolicyRefused) as c:
            self.load(path, **kw)
        self.assertIn(text, str(c.exception))

    def test_without_policy_signing_keys_the_policy_is_the_json_file_as_before(self):
        before = sorted(os.listdir(self.state))
        policy, data, info = self.load(self.pol, remember=True)
        self.assertEqual((policy, data, info), (json.loads(self.policy_bytes), self.policy_bytes,
                                                {"signed": False, "sha256": hashlib.sha256(self.policy_bytes).hexdigest()}))
        with mock.patch.dict(sys.modules):                   # nothing of the signed policy is even imported
            sys.modules.pop("signed_policy", None)
            sys.modules["signed_policy"] = None
            self.load(self.pol)
        rc, out = self.fleet("once", self.pol)
        self.assertEqual((rc, [v["admitted"] for v in json.loads(out)]), (0, [True, False]))
        rc, out = self.fleet("check", self.pol)
        self.assertEqual(rc, 0, out)
        self.assertNotIn("signed", out)
        self.assertNotIn("audit", out)
        self.assertEqual(sorted(os.listdir(self.state)), before)
        # what was not JSON before is not JSON now, with the same exceptions
        with open(self.pol, "wb") as f:
            f.write(b"{not json")
        with self.assertRaises(ValueError) as c:
            self.load(self.pol)
        self.assertNotIsInstance(c.exception, fleet.PolicyRefused)
        with self.assertRaises(FileNotFoundError):
            self.load(self.pol + ".none")

    def test_a_signed_policy_is_not_read_unchecked(self):
        path = self.sign()
        self.refused(path, "no policy-signing key to check it with")
        rc, out = self.fleet("once", path)
        self.assertEqual(rc, 1)
        self.assertIn("policy REFUSED", out)

    def test_with_policy_signing_keys_only_a_signed_policy_will_do(self):
        self.require()
        self.refused(self.pol, "is not signed, and this verifier runs only from a signed policy")
        for cmd in ("once", "check", "enroll-pq", "audit"):
            rc, out = self.fleet(cmd, self.pol)
            self.assertEqual(rc, 1, cmd)
            self.assertIn("policy REFUSED", out)
        path = self.sign()
        policy, data, info = self.load(path)
        self.assertEqual((policy, data), (json.loads(self.policy_bytes), self.policy_bytes))
        self.assertEqual((info["signed"], info["sha256"], info["version"], info["signer"], info["signer_key_sha256"]),
                         (True, hashlib.sha256(self.policy_bytes).hexdigest(), 1, "ops", hashlib.sha256(OPK).hexdigest()))
        self.refused(self.sign(sk=XSK, pk=XPK), "not a policy signer of this verifier")
        self.refused(self.sign(sk=VSK, pk=VPK), "not a policy signer")        # not even its own identity key
        with open(path, "rb") as f:
            good = f.read()
        with open(path, "wb") as f:
            f.write(good[:500] + bytes([good[500] ^ 0x40]) + good[501:])
        self.refused(path, "refused")
        with open(path, "wb") as f:                          # the JSON under the signed file's name
            f.write(self.policy_bytes)
        self.refused(path, "is not signed")
        # a signers file that cannot be used is not "no signers"
        with open(os.path.join(self.state, "policy-signers.json"), "w") as f:
            f.write("{}")
        self.refused(self.pol, "the policy signers in")
        os.unlink(os.path.join(self.state, "policy-signers.json"))
        self.refused(self.pol, "No such file", signers_path=os.path.join(self.state, "elsewhere.json"))
        elsewhere = signers()
        self.assertTrue(self.load(self.sign(), signers_path=elsewhere)[2]["signed"])
        self.refused(self.pol, "is not signed", signers_path=elsewhere)

    def test_an_older_signed_policy_put_back_is_refused(self):
        self.require()
        v1 = self.sign(name="v1.cose")
        changed = dict(self.policy, endpoints=self.policy["endpoints"][:1])
        v2 = self.sign(changed, name="v2.cose")
        self.assertEqual(self.load(v1)[2]["version"], 1)             # looking (`check`) accepts nothing
        self.assertFalse(os.path.exists(os.path.join(self.state, "policy-version.json")))
        self.assertEqual(self.load(v2, remember=True)[2]["version"], 2)
        self.assertEqual(self.load(v2, remember=True)[2]["version"], 2)
        self.refused(v1, "rollback refused")
        self.refused(self.sign(self.policy, version=2, name="other2.cose"), "already accepted for another policy")
        self.assertEqual(len(self.load(self.sign(self.policy, version=3, name="v3.cose"), remember=True)[0]["endpoints"]), 2)
        self.refused(v2, "rollback refused")
        rc, out = self.fleet("once", v1)
        self.assertEqual(rc, 1)
        self.assertIn("rollback refused", out)
        # the same file is not verified again by the loop (known), another one is
        loaded = self.load(os.path.join(self.d, "v3.cose"))
        with mock.patch.object(signed_policy, "open_signed", side_effect=AssertionError("verified again")):
            again = self.load(os.path.join(self.d, "v3.cose"), known=loaded)
            self.assertEqual(again, loaded)
            self.assertIsNot(again[0], loaded[0])
            with self.assertRaises(AssertionError):
                self.load(v2, known=loaded)
        # a lost counter is not a counter at zero
        with open(os.path.join(self.state, "policy-version.json"), "w") as f:
            f.write("")
        self.refused(os.path.join(self.d, "v3.cose"), "record of the last policy version")

    def test_the_fleet_name_of_the_signers_file_is_required_of_the_policy(self):
        self.require(audience="bench")
        self.refused(self.sign(), "no fleet in particular")
        self.refused(self.sign(audience="plant"), "this verifier's fleet is 'bench'")
        self.assertEqual(self.load(self.sign(audience="bench"))[2]["audience"], "bench")

    def test_a_run_from_a_signed_policy_and_what_the_log_and_the_result_say_of_it(self):
        self.require()
        self.policy.update(audit_log=True, attestation_results=True)
        self.save()
        path = self.sign()
        rc, out = self.fleet("once", path)
        self.assertEqual(rc, 0, out)
        v = json.loads(out[out.index("["):])
        self.assertEqual([x["admitted"] for x in v], [True, False])
        with open(os.path.join(self.state, "policy-version.json")) as f:
            self.assertEqual(json.load(f)["version"], 1)
        e = self.entries()
        self.assertEqual(e[2]["event"], "policy")
        with open(path, "rb") as f:
            file_sha = hashlib.sha256(f.read()).digest()
        self.assertEqual(e[2]["details"], {"sha256": hashlib.sha256(self.policy_bytes).digest(), "signed": True,
                                           "version": 1, "signer": "ops", "file_sha256": file_sha,
                                           "signer_key_sha256": hashlib.sha256(OPK).digest()})
        # the attestation result names the policy by the JSON inside, as it would for the plain file
        with open(os.path.join(self.state, "attestation", "good", "result.cbor"), "rb") as f:
            result = f.read()
        self.assertEqual(eat.read_ear(result, VPK)["policy_ids"], [eat.policy_id(self.policy_bytes)])
        self.assertEqual(e[3]["details"]["result_sha256"], hashlib.sha256(result).digest())
        rc, out = self.fleet("check", path)
        self.assertEqual(rc, 0, out)
        self.assertIn("signed by ops (key sha256 %s...), version 1" % hashlib.sha256(OPK).hexdigest()[:16], out)
        self.assertIn("audit log: in %s" % self.audit_dir, out)

    def test_a_verifier_that_once_ran_signed_says_so_when_it_runs_unsigned(self):
        self.require()
        self.load(self.sign(), remember=True)
        os.unlink(os.path.join(self.state, "policy-signers.json"))
        info = self.load(self.pol)[2]
        self.assertIn("accepted signed policies before", info["warning"])
        rc, out = self.fleet("check", self.pol)
        self.assertIn("WARNING: this verifier accepted signed policies before", out)

    def loop(self, path, steps, *more):
        """`fleet.py watch` for len(steps) cycles; steps[i]() runs in the sleep after cycle i. Returns (what the
        loop returned or None if it was still running, its output, the state file's verdicts after each cycle)."""
        class Done(Exception):
            pass
        seen = []
        state_file = os.path.join(self.state, "fleet-state.json")

        def sleep(_):
            with open(state_file) as f:
                seen.append([(v["endpoint"], v["admitted"]) for v in json.load(f)["verdicts"]])
            if len(seen) > len(steps):
                raise Done()
            steps[len(seen) - 1]()
        rc = None
        out = io.StringIO()
        with mock.patch.object(fleet.time, "sleep", sleep), contextlib.redirect_stdout(out), \
                contextlib.redirect_stderr(out):
            try:
                rc = fleet.main(["watch", path, "--state-dir", self.state, "--platform", "linux", "--verifier",
                                 "cryptography", "--interval", "30", *more])
            except Done:
                pass
        return rc, out.getvalue(), seen

    def test_the_loop_keeps_the_last_accepted_policy_and_says_what_it_refused(self):
        self.require()
        self.policy["audit_log"] = True
        self.save()
        path = self.sign()
        with open(path, "rb") as f:
            v1 = f.read()
        one = dict(self.policy, endpoints=self.policy["endpoints"][:1])

        def put(data):
            with open(path, "wb") as f:
                f.write(data)
        rc, out, seen = self.loop(path, [
            lambda: self.sign(one),                                      # version 2: one endpoint
            lambda: put(v1),                                             # the old one put back
            lambda: put(signed_policy.sign(XSK, XPK, self.policy_bytes, 9, "ops", T0)),     # somebody else's
            lambda: put(self.policy_bytes),                              # not signed at all
            lambda: self.sign(self.policy, version=3)])                  # a new one by the operator
        self.assertIsNone(rc, out)
        both, good = [("good", True), ("legacy", False)], [("good", True)]
        self.assertEqual(seen, [both, good, good, good, good, both])
        self.assertEqual(out.count("policy REFUSED, keeping the previous one"), 3)
        self.assertIn("rollback refused", out)
        self.assertIn("version 2", out)
        e = self.entries()
        self.assertEqual([x["event"] for x in e],
                         ["log-start", "start", "policy", "admit", "refuse", "policy", "remove", "policy-refused",
                          "policy-refused", "policy-refused", "policy", "refuse"])
        self.assertEqual([x["details"]["version"] for x in e if x["event"] == "policy"], [1, 2, 3])
        self.assertIn("rollback refused", e[7]["details"]["why"])
        self.assertIn("not a policy signer", e[8]["details"]["why"])
        self.assertIn("is not signed", e[9]["details"]["why"])
        with open(os.path.join(self.state, "policy-version.json")) as f:
            self.assertEqual(json.load(f)["version"], 3)
        # the loop promised its next batch: read later than that, the log is stale
        rep = audit.verify(self.audit_dir, [VPK], now=time.time())
        self.assertFalse(rep["stale"])
        self.assertTrue(audit.verify(self.audit_dir, [VPK], now=rep["logs"][0]["due"] + 1)["stale"])

    def test_a_loop_that_ran_unsigned_stops_when_it_is_given_policy_signing_keys(self):
        """There is then no accepted policy to keep: running on from the unsigned one would be the downgrade."""
        rc, out, seen = self.loop(self.pol, [lambda: None, self.require, lambda: None])
        self.assertEqual(rc, 1, out)
        self.assertEqual(len(seen), 2)
        self.assertIn("the policy in use is not a signed one: stopping", out)
        # and it does not start again from it
        rc, out, seen = self.loop(self.pol, [lambda: None])
        self.assertEqual((rc, seen), (1, []))

    def test_an_unsigned_loop_reloads_as_before(self):
        def broken():
            with open(self.pol, "w") as f:
                f.write("{")
        one = dict(self.policy, endpoints=self.policy["endpoints"][:1])
        rc, out, seen = self.loop(self.pol, [broken, lambda: self.save(one)])
        self.assertEqual(seen, [[("good", True), ("legacy", False)]] * 2 + [[("good", True)]])
        self.assertEqual(out.count("policy reload failed, keeping the previous one"), 1)
        self.assertNotIn("signed", out)
        self.assertNotIn("audit", out)
        self.assertEqual(sorted(os.listdir(self.state)), ["fleet-state.json", "identity.json", "identity.sk"])

    def test_an_entry_can_pin_the_key_its_key_file_must_hold(self):
        dev, entry = self.pq("pq-good")
        pin = hashlib.sha256(tf.PQ_KEYS[0][0]).hexdigest()
        attest = lambda e: fleet.attest(e, VERIFY, self.d, 2)  # noqa: E731
        self.assertTrue(attest(entry)["admitted"])
        self.assertTrue(attest(dict(entry, pq_pub_sha256=pin))["admitted"])
        # the key file replaced (and a device that holds the new key): admitted without the pin, refused with it
        dev.pq_pk, dev.pq_sk = tf.PQ_KEYS[1]
        with open(os.path.join(self.d, "pq.pub"), "w") as f:
            f.write(tf.PQ_KEYS[1][0].hex())
        self.assertTrue(attest(entry)["admitted"])
        v = attest(dict(entry, pq_pub_sha256=pin))
        self.assertFalse(v["admitted"])
        self.assertIn("is not the key the policy pins (pq_pub_sha256", v["reasons"][0])
        with self.assertRaises(ValueError):                  # and no session goes to it
            fleet.provision(dict(entry, pq_pub_sha256=pin), self.d, VSK, "gid", {}, timeout=2)
        for bad in ("AB" * 32, "ab" * 31, 5, pin.upper()):
            self.assertTrue(fleet.policy_errors(dict(entry, pq_pub_sha256=bad)), bad)
        self.assertEqual(fleet.policy_errors(dict(entry, pq_pub_sha256=pin)), [])
        self.assertIn("needs a post-quantum kind", fleet.policy_errors(dict(self.policy["endpoints"][0],
                                                                            pq_pub_sha256=pin))[0])


class EndorsedUnderASignedPolicy(te.Bench):
    """enroll-endorsed where the policy is signed: the verifier cannot write the record's pin into the policy."""

    def test_the_record_is_installed_and_the_pin_is_left_to_the_next_signed_policy(self):
        res = self.endorse()
        self.assertTrue(res["endorsed"], res)
        state = make_state()
        signers(where=state)
        with open(self.pol, "rb") as f:
            plain = f.read()
        path = os.path.join(self.d, "fleet.cose")
        with open(path, "wb") as f:
            f.write(signed_policy.sign(OSK, OPK, plain, 1, "ops"))
        before = te.snapshot(self.d)
        rc, out = run(fleet.main, ["enroll-endorsed", path, res["record"], "--state-dir", state, "--platform", "linux"])
        self.assertEqual(rc, 0, out)
        self.assertIn("the policy is signed, so the record is NOT pinned by this command", out)
        self.assertIn('"endorsement_sha256": "%s"' % res["record_sha256"], out)
        after = te.snapshot(self.d)
        self.assertEqual({k: v for k, v in after.items() if k in before}, before)      # neither policy file changed
        self.assertEqual(sorted(os.path.relpath(k, self.d) for k in set(after) - set(before)),
                         ["endorsements/dev-a.json", "keys/dev-a.mldsa65.pub"])
        policy = fleet.load_policy(path, state)[0]
        v = fleet.attest(policy["endpoints"][0], VERIFY, self.d, 5, policy["endorsers"])
        self.assertTrue(v["admitted"], v["reasons"])
        # the operator signs the pin: from then on only that record
        policy["endpoints"][0]["endorsement_sha256"] = res["record_sha256"]
        with open(path, "wb") as f:
            f.write(signed_policy.sign(OSK, OPK, json.dumps(policy).encode(), 2, "ops"))
        policy = fleet.load_policy(path, state, remember=True)[0]
        self.assertTrue(fleet.attest(policy["endpoints"][0], VERIFY, self.d, 5, policy["endorsers"])["admitted"])


class Signer(Fleet):
    """provision/aegis_provision.py: the policy signer."""

    @classmethod
    def setUpClass(cls):
        Fleet.setUpClass()
        cls.sstate = tempfile.mkdtemp()
        rc, out = run(prov.main, ["policy-init", "--name", "ops", "--state", cls.sstate, "--key-store", "software"])
        assert rc == 0, out
        cls.signer = prov.PolicySigner(cls.sstate)

    def setUp(self):
        Fleet.setUp(self)
        self.dev, self.entry = self.pq("pq-good")
        self.ledger = os.path.join(self.sstate, prov.POLICY_LEDGER)
        if os.path.exists(self.ledger):
            os.unlink(self.ledger)

    def tool(self, *args):
        return run(prov.main, [*args, "--state", self.sstate])

    def test_the_policy_signer_is_a_key_of_its_own(self):
        rc, out = self.tool("policy-show")
        shown = json.loads(out)
        self.assertEqual((shown["policy_signer"], shown["pk_sha256"], shown["last_signed_version"]),
                         ("ops", hashlib.sha256(self.signer.pk).hexdigest(), 0))
        self.assertEqual(sorted(os.listdir(self.sstate)), ["identity.sk", "policy-signer.json"])
        self.assertEqual(os.stat(os.path.join(self.sstate, "identity.sk")).st_mode & 0o777, 0o600)
        # its record is not an endorser's, nor an endorser's a policy signer's
        with self.assertRaises((OSError, ValueError)):
            prov.Endorser(self.sstate)
        estate = tempfile.mkdtemp()
        prov.init(estate, "bench", key_store="software")
        with self.assertRaises((OSError, ValueError)):
            prov.PolicySigner(estate)
        shutil.copy(os.path.join(estate, "endorser.json"), os.path.join(estate, "policy-signer.json"))
        with self.assertRaises(ValueError):
            prov.PolicySigner(estate)
        with self.assertRaises(SystemExit):                  # a second init does not replace the key
            self.tool("policy-init", "--name", "ops", "--key-store", "software")
        self.assertEqual(prov.PolicySigner(self.sstate).pk, self.signer.pk)

    def test_export_writes_the_file_a_verifier_reads(self):
        rc, out = self.tool("policy-export", self.state, "--audience", "bench")
        self.assertEqual(rc, 0, out)
        s = signed_policy.load_signers(os.path.join(self.state, "policy-signers.json"))
        self.assertEqual((s["audience"], list(s["keys"].values())), ("bench", [{"name": "ops", "pk": self.signer.pk}]))
        with self.assertRaises(SystemExit):
            self.tool("policy-export", self.state)
        self.assertEqual(self.tool("policy-export", self.state, "--force")[0], 0)
        self.assertIsNone(signed_policy.load_signers(os.path.join(self.state, "policy-signers.json"))["audience"])

    def test_sign_then_the_verifier_runs_from_it_and_refuses_the_one_before(self):
        self.tool("policy-export", self.state)
        rc, out = self.tool("policy-sign", self.pol, "--yes")
        res = json.loads(out)
        self.assertEqual((rc, res["signed"], res["version"], res["out"], res["policy_sha256"], res["endpoints"]),
                         (0, True, 1, os.path.join(self.d, "fleet.cose"), hashlib.sha256(self.policy_bytes).hexdigest(), 3))
        self.assertTrue(any("pq: no pq_pub_sha256" in w for w in res["warnings"]), res["warnings"])
        with open(res["out"], "rb") as f:
            first = f.read()
        self.assertEqual(hashlib.sha256(first).hexdigest(), res["signed_sha256"])
        rc, out = self.fleet("once", res["out"])
        self.assertEqual((rc, [v["admitted"] for v in json.loads(out[out.index("["):])]), (0, [True, False, True]))
        # a second policy: one more
        self.policy["endpoints"].pop(1)
        self.save()
        res2 = json.loads(self.tool("policy-sign", self.pol, "--yes", "--out", os.path.join(self.d, "two.cose"))[1])
        self.assertEqual((res2["version"], res2["out"]), (2, os.path.join(self.d, "two.cose")))
        self.assertEqual(self.fleet("once", res2["out"])[0], 0)
        rc, out = self.fleet("once", res["out"])
        self.assertEqual(rc, 1)
        self.assertIn("rollback refused", out)
        with open(self.ledger) as f:
            ledger = [json.loads(line) for line in f]
        self.assertEqual([(e["version"], e["signed_sha256"], e["policy_sha256"]) for e in ledger],
                         [(1, res["signed_sha256"], res["policy_sha256"]), (2, res2["signed_sha256"], res2["policy_sha256"])])
        self.assertEqual(json.loads(self.tool("policy-show")[1])["last_signed_version"], 2)
        # a version that is not higher is not signed, unless forced
        rc, out = self.tool("policy-sign", self.pol, "--yes", "--policy-version", "2")
        self.assertEqual((rc, json.loads(out)["signed"]), (1, False))
        self.assertIn("not higher than the last", out)
        self.assertEqual(json.loads(self.tool("policy-sign", self.pol, "--yes", "--policy-version", "40")[1])["version"], 40)
        self.assertEqual(json.loads(self.tool("policy-sign", self.pol, "--yes")[1])["version"], 41)
        self.assertEqual(json.loads(self.tool("policy-sign", self.pol, "--yes", "--policy-version", "2", "--force")[1])["signed"], True)

    def test_nothing_is_signed_that_the_operator_did_not_confirm(self):
        seen = []
        res = prov.sign_policy(self.signer, self.pol, approve=lambda s: seen.append(s) or False)
        self.assertEqual((res["signed"], res["reasons"]), (False, ["not confirmed by the operator: nothing signed"]))
        self.assertEqual((os.path.exists(os.path.join(self.d, "fleet.cose")), os.path.exists(self.ledger)), (False, False))
        s = seen[0]
        self.assertEqual((s["version"], s["previous_version"], s["policy_sha256"], s["signer"]),
                         (1, 0, hashlib.sha256(self.policy_bytes).hexdigest(), "ops"))
        self.assertEqual([(e["name"], e["kind"]) for e in s["endpoints"]], [("good", "psa"), ("legacy", "psa"),
                                                                          ("pq", "aegis-pq")])
        self.assertEqual(s["endpoints"][2]["key"], "trust on first use, key NOT pinned")
        self.assertEqual((s["audit_log"], s["attestation_results"], s["enforce_cmd"]), (True, False, None))
        # at the terminal: only "yes"; without a terminal, nothing
        out = io.StringIO()
        self.assertFalse(prov.ask_policy(s, out, io.StringIO("yes\n")))
        self.assertIn("no terminal to confirm at", out.getvalue())

        class Tty(io.StringIO):
            def isatty(self):
                return True
        self.assertTrue(prov.ask_policy(s, out, Tty("yes\n")))
        self.assertFalse(prov.ask_policy(s, out, Tty("y\n")))
        text = out.getvalue()
        for shown in ("as version 1", hashlib.sha256(self.policy_bytes).hexdigest(), "pq (aegis-pq) at 127.0.0.1:%d"
                      % self.dev.port, "key NOT pinned", "WARNING", "audit log on"):
            self.assertIn(shown, text)
        rc, out = self.tool("policy-sign", self.pol)         # the command line, no terminal: nothing signed
        self.assertEqual((rc, json.loads(out[out.index("{"):])["signed"]), (1, False))

    def test_pin_keys_puts_the_key_hashes_under_the_signature(self):
        rc, out = self.tool("policy-sign", self.pol, "--yes", "--pin-keys")
        res = json.loads(out)
        self.assertEqual((rc, res["keys_pinned_now"], res["warnings"]), (0, ["pq"], []))
        with open(self.pol, "rb") as f:
            pinned = f.read()
        with open(self.pol + ".bak", "rb") as f:
            self.assertEqual(f.read(), self.policy_bytes)    # the policy as it was is kept
        self.assertEqual(json.loads(pinned)["endpoints"][2]["pq_pub_sha256"], hashlib.sha256(tf.PQ_KEYS[0][0]).hexdigest())
        o = signed_policy.open_signed(open(res["out"], "rb").read(), self.signer.trust())
        self.assertEqual((o["policy_bytes"], o["policy_sha256"]), (pinned, res["policy_sha256"]))
        # the key file replaced on the verifier: the signed policy still means the first key
        self.tool("policy-export", self.state)
        self.assertTrue(self.verdicts("once", res["out"])[2]["admitted"])
        self.dev.pq_pk, self.dev.pq_sk = tf.PQ_KEYS[1]
        with open(os.path.join(self.d, "pq.pub"), "w") as f:
            f.write(tf.PQ_KEYS[1][0].hex())
        v = self.verdicts("once", res["out"])[2]
        self.assertFalse(v["admitted"])
        self.assertIn("pq_pub_sha256", v["reasons"][0])
        # signing again with the other key in the file: the pin and the file disagree, nothing signed
        rc, out = self.tool("policy-sign", self.pol, "--yes", "--pin-keys")
        self.assertEqual(rc, 1)
        self.assertIn("and its key file holds", out)

    def test_what_is_not_a_policy_is_not_signed(self):
        for name, data in (("a name twice", b'{"endpoints": [], "endpoints": []}'), ("not JSON", b"{"),
                           ("no endpoints", b"{}"), ("a signed policy", signed_policy.sign(OSK, OPK, POLICY, 1, "ops"))):
            with open(self.pol, "wb") as f:
                f.write(data)
            rc, out = self.tool("policy-sign", self.pol, "--yes")
            self.assertEqual((rc, json.loads(out)["signed"]), (1, False), name)
        self.assertEqual(self.tool("policy-sign", self.pol + ".none", "--yes")[0], 1)
        self.assertFalse(os.path.exists(self.ledger))
        with self.assertRaises(SystemExit):                  # no signer in that state
            run(prov.main, ["policy-sign", self.pol, "--yes", "--state", tempfile.mkdtemp()])


@NEEDS_LIBS
class Checker(Fleet):
    """tools/verify_audit.py: third-party libraries only."""

    def setUp(self):
        Fleet.setUp(self)
        self.key = os.path.join(self.state, "identity.json")
        trail = fleet.open_audit(dict(self.policy, audit_log={"checkpoint_s": 3600}), self.state, grace_s=60,
                                 start={"cmd": "test"})
        self.cycle(trail)
        for mode in ("tampered", "good", "garbage"):
            self.good.mode = mode
            self.cycle(trail)
        self.good = records(self.audit_dir)
        self.assertEqual(len(self.good), 4)

    def log(self, *args, recs=None):
        if recs is not None:
            write_records(self.audit_dir, recs)
        return checker("log", self.audit_dir, "--key", self.key, *args)

    def test_the_checker_shares_no_code_with_the_repository(self):
        with open(CHECKER) as f:
            tree = ast.parse(f.read())
        mods = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom):
                mods.add(node.module.split(".")[0])
        self.assertEqual(mods - set(sys.stdlib_module_names), {"cbor2", "cryptography", "pycose"})
        ours = {os.path.splitext(n)[0] for d in ("common", "gateway/aegisd", "provision", "tools")
                for n in os.listdir(os.path.join(ROOT, d))}
        self.assertEqual(mods & ours, set())

    def test_a_log_the_verifier_wrote_verifies_and_reads_the_same(self):
        rc, rep = self.log("--entries")
        self.assertEqual((rc, rep["verified"]), (0, True), rep)
        ours = audit.verify(self.audit_dir, [VPK], with_entries=True)
        lg = rep["logs"][0]
        self.assertEqual({k: lg[k] for k in ours["logs"][0]}, ours["logs"][0])
        self.assertEqual((lg["last_batch"], lg["entries"], rep["pruned"]), (4, 7, False))
        self.assertEqual(rep["entries"], json.loads(json.dumps(fleet._jsonable(ours["entries"]))))
        self.assertEqual([(e["event"], e["subject"]) for e in rep["entries"]],
                         [("log-start", None), ("start", None), ("admit", "good"), ("refuse", "legacy"),
                          ("refuse", "good"), ("admit", "good"), ("refuse", "good")])
        self.assertEqual(rep["entries"][4]["details"]["measurements"]["NSPE"], "99" * 32)
        # the key in any of the forms it comes in
        cosekey = os.path.join(tempfile.mkdtemp(), "verifier.cosekey")
        with open(cosekey, "wb") as f:
            f.write(fleet.cbor_key(VPK))
        for key in (hexfile(VPK), cosekey):
            self.assertEqual(checker("log", self.audit_dir, "--key", key)[0], 0)
        self.assertEqual(checker("log", *[p for _, p in audit.segments(self.audit_dir)], "--key", self.key)[0], 0)
        rc, rep = checker("log", self.audit_dir, "--key", hexfile(XPK))
        self.assertEqual(rc, 1)
        self.assertIn("signed by a key that was not given", rep["reason"])

    def test_what_the_verifier_s_reader_refuses_the_checker_refuses(self):
        g = self.good
        c = cbor.loads(cose.parse(g[2]).payload)
        c[7][0][2] = "refuse"
        tag = cbor.loads(g[2])
        other = os.path.join(tempfile.mkdtemp(), "audit")
        lg = audit.Log(other, VPK, lambda: VSK)
        for i in range(3):
            lg.add("admit", "dev", {}, T0)
            lg.flush(T0)
        loose = cbor.loads(g[1])
        loose.value[1] = {}
        for name, recs in (("a byte changed", [g[0], g[1][:150] + bytes([g[1][150] ^ 4]) + g[1][151:]] + g[2:]),
                           ("a batch removed", [g[0], g[1], g[3]]), ("reordered", [g[0], g[2], g[1], g[3]]),
                           ("repeated", g + [g[3]]), ("the beginning removed", g[1:]),
                           ("re-signed by another key", g[:2] + [cose.sign1(XSK, XPK, cbor.dumps(c, sort=True),
                                                                            typ=AUDIT_TYP)] + g[3:]),
                           ("the old signature on new claims",
                            g[:2] + [cose.assemble(tag.value[0], cbor.dumps(c, sort=True), tag.value[3])] + g[3:]),
                           ("a batch of another log", g[:2] + [records(other)[2]] + g[3:]),
                           ("torn", g + [g[0][:700]]), ("trailing bytes", g + [b"\x00"]),
                           ("a longer encoding of a length", [b"\xd2\x84\x59\x00" + g[0][3:]] + g[1:]),
                           ("an attestation result in the log",
                            g + [cose.sign1(VSK, VPK, cose.parse(g[0]).payload)]),
                           ("nothing", [])):
            write_records(self.audit_dir, recs)
            with self.assertRaises(audit.Refused, msg=name):
                audit.verify(self.audit_dir, [VPK])
            rc, rep = self.log()
            self.assertEqual((rc, rep["verified"]), (1, False), name)
        self.assertEqual(self.log(recs=g)[0], 0)

    def test_the_end_cut_off_needs_the_anchor_the_head_or_the_time(self):
        anchor = os.path.join(tempfile.mkdtemp(), "anchor.cbor")
        with open(anchor, "wb") as f:
            f.write(self.good[-1])
        head = "4:" + hashlib.sha256(self.good[-1]).hexdigest()
        self.assertEqual(self.log("--anchor", anchor, "--head", head)[0], 0)
        rc, rep = self.log(recs=self.good[:2])
        self.assertEqual((rc, rep["logs"][0]["last_batch"]), (0, 2))     # a shorter log is a log
        for args in (["--anchor", anchor], ["--head", head]):
            rc, rep = self.log(*args)
            self.assertEqual(rc, 1)
            self.assertIn("the end was cut off", rep["reason"])
        due = audit.open_batch(self.good[1]).due
        self.assertEqual(self.log("--at", str(due))[0], 0)
        rc, rep = self.log("--at", str(due + 1))
        self.assertEqual(rc, 1)
        self.assertIn("stale", rep["reason"])
        self.assertEqual(self.log("--at", str(due + 1), "--no-freshness")[0], 0)
        self.assertEqual(self.log("--head", "2:" + "00" * 32)[0], 1)
        with open(anchor, "wb") as f:                        # an anchor that is no batch record of this verifier
            f.write(cose.sign1(XSK, XPK, cose.parse(self.good[-1]).payload, typ=AUDIT_TYP))
        self.assertEqual(self.log("--anchor", anchor)[0], 1)
        # pruned
        rc, rep = self.log(recs=self.good[2:])
        self.assertEqual(rc, 1)
        rc, rep = self.log("--allow-pruned")
        self.assertEqual((rc, rep["pruned"], rep["logs"][0]["first_batch"]), (0, True, 3))

    def test_a_signed_policy(self):
        path = os.path.join(self.d, "fleet.cose")
        with open(path, "wb") as f:
            f.write(signed_policy.sign(OSK, OPK, self.policy_bytes, 7, "ops", T0, "bench"))
        key = signers(("ops", OPK), ("second", XPK))
        out = os.path.join(tempfile.mkdtemp(), "inside.json")
        rc, rep = checker("policy", path, "--key", key, "--audience", "bench", "--min-version", "7", "--extract", out)
        self.assertEqual((rc, rep["verified"], rep["version"], rep["signer"], rep["audience"], rep["issued"]),
                         (0, True, 7, "ops", "bench", T0), rep)
        self.assertEqual((rep["policy_sha256"], rep["policy_id"], rep["endpoints"], rep["audit_log"]),
                         (hashlib.sha256(self.policy_bytes).hexdigest(), eat.policy_id(self.policy_bytes),
                          ["good", "legacy"], True))
        with open(out, "rb") as f:
            self.assertEqual(f.read(), self.policy_bytes)
        for args, why in ((["--key", hexfile(XPK)], "not given"), (["--key", key, "--audience", "plant"], "is for"),
                          (["--key", key, "--min-version", "8"], "older than 8")):
            rc, rep = checker("policy", path, *args)
            self.assertEqual(rc, 1)
            self.assertIn(why, rep["reason"])
        with open(path, "rb") as f:
            good = f.read()
        for name, data in (("altered", good[:400] + bytes([good[400] ^ 1]) + good[401:]), ("extended", good + b"\x00"),
                           ("a name twice", cose.sign1(OSK, OPK, cbor.dumps(
                               {1: POLICY_FORMAT, 2: 1, 3: T0, 4: b'{"endpoints": [], "endpoints": []}', 5: "ops"},
                               sort=True), typ=POLICY_TYP)),
                           ("an unknown claim", cose.sign1(OSK, OPK, cbor.dumps(
                               {1: POLICY_FORMAT, 2: 1, 3: T0, 4: self.policy_bytes, 5: "ops", 7: 1}, sort=True),
                               typ=POLICY_TYP)),
                           ("an audit batch", cose.sign1(OSK, OPK, cose.parse(self.good[0]).payload, typ=AUDIT_TYP)),
                           ("the JSON itself", self.policy_bytes)):
            with open(path, "wb") as f:
                f.write(data)
            with self.assertRaises((signed_policy.Refused, cose.Refused), msg=name):
                signed_policy.open_signed(data, signed_policy.load_signers(key)["keys"])
            self.assertEqual(checker("policy", path, "--key", key)[0], 1, name)


if __name__ == "__main__":
    unittest.main()
