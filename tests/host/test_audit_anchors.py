# SPDX-License-Identifier: Apache-2.0
"""tools/audit_anchors.py: anchors of the verifier's audit log kept off the gateway (docs/audit-and-policy.md,
"Anchors off the gateway").

Logs are written by the verifier's own writer (common/audit.py) and its own export (fleet.py audit --out); the
"gateway" is a shell command template that runs here. Hostile input: garbled anchors, an anchor of another key, a
replayed older anchor, a forked log, a truncated log, a gap, a hostile log archive, a store changed on the PC.
"""
import hashlib
import io
import json
import os
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
for p in ("common", "gateway/aegisd", "tests/host"):
    sys.path.insert(0, os.path.join(ROOT, p))

import audit  # noqa: E402
import cbor  # noqa: E402
import cose  # noqa: E402
import mldsa  # noqa: E402
sys.path.insert(0, os.path.join(ROOT, "tools"))
import audit_anchors as aa  # noqa: E402
from test_audit_policy import NEEDS_LIBS, VPK, VSK, XPK, XSK, T0, make_state, records  # noqa: E402

TOOL = os.path.join(ROOT, "tools", "audit_anchors.py")
FLEET = os.path.join(ROOT, "gateway", "aegisd", "fleet.py")


def q(path):
    return shlex.quote(path)


@NEEDS_LIBS
class Anchors(unittest.TestCase):

    def setUp(self):
        self.state = make_state()
        self.audit_dir = os.path.join(self.state, "audit")
        self.store = tempfile.mkdtemp()
        self.key = os.path.join(self.state, "identity.json")
        self.anchor = os.path.join(tempfile.mkdtemp(), "anchor.cbor")
        self.log = audit.Log(self.audit_dir, VPK, lambda: VSK, checkpoint_s=3600)
        self.write(4)

    def write(self, n, t=T0, log=None):
        lg = log or self.log
        for i in range(n):
            lg.add("admit", "dev", {"i": i}, t)
            lg.flush(t, promise=False)

    def serve(self, raw):
        """The record the 'gateway' prints next."""
        if os.path.exists(self.anchor):
            os.unlink(self.anchor)
        with open(self.anchor, "wb") as f:
            f.write(raw)

    def tool(self, *args, at=T0 + 60):
        r = subprocess.run([sys.executable, "-I", TOOL, *args, "--key", self.key, "--store", self.store,
                            "--gateway", "gw.test", "--at", str(at)], capture_output=True, text=True)
        try:
            return r.returncode, json.loads(r.stdout)
        except ValueError:
            self.fail("not JSON: %s %s" % (r.stdout, r.stderr))

    def fetch(self, raw=None):
        if raw is not None:
            self.serve(raw)
        return self.tool("fetch", "--fetch-cmd", "cat %s" % q(self.anchor))

    def log_cmd(self):
        """The default template's remote part: the segment files only."""
        return "cd %s && tar -cf - audit-*.cbor" % q(self.audit_dir)

    def check(self, *extra, at=T0 + 60):
        return self.tool("check", "--log-cmd", self.log_cmd(), *extra, at=at)

    def kinds(self, rep):
        return sorted({f["kind"] for f in rep["findings"]})

    def kept(self):
        d = os.path.join(self.store, hashlib.sha256(VPK).hexdigest())
        with open(os.path.join(d, "manifest.jsonl")) as f:
            lines = [json.loads(x) for x in f]
        return d, lines

    def snapshot(self):
        d = os.path.join(self.store, hashlib.sha256(VPK).hexdigest(), "anchors")
        out = {}
        for n in os.listdir(d):
            with open(os.path.join(d, n), "rb") as f:
                out[n] = f.read()
        return out

    # ---- fetch ----

    def test_the_verifier_s_own_export_is_fetched_kept_and_checked(self):
        policy = os.path.join(tempfile.mkdtemp(), "fleet.json")
        with open(policy, "w") as f:
            json.dump({"endpoints": [], "audit_log": True}, f)
        # the default template's remote part, run here instead of over ssh
        cmd = ('f=$(mktemp) || exit 1; %s %s audit %s --state-dir %s --platform linux --out "$f" >&2; rc=$?; '
               'cat "$f"; rm -f "$f"; exit $rc' % (q(sys.executable), q(FLEET), q(policy), q(self.state)))
        r = subprocess.run([sys.executable, "-I", TOOL, "fetch", "--key", self.key, "--store", self.store,
                            "--gateway", "gw.test", "--fetch-cmd", cmd], capture_output=True, text=True)
        rep = json.loads(r.stdout)
        self.assertEqual((r.returncode, rep["ok"], rep["batch"]), (0, True, 4), rep)
        d, lines = self.kept()
        self.assertEqual(os.path.basename(d), hashlib.sha256(VPK).hexdigest())
        self.assertEqual([(m["batch"], m["sha256"]) for m in lines],
                         [(4, hashlib.sha256(records(self.audit_dir)[-1]).hexdigest())])
        f = os.path.join(d, "anchors", lines[0]["file"])
        self.assertFalse(os.stat(f).st_mode & 0o222)                 # read-only
        rc, rep = self.tool("check", "--log-dir", self.audit_dir, "--no-freshness")
        self.assertEqual((rc, rep["anchors_matched"]), (0, 1), rep)

    def test_fetch_keeps_each_new_anchor_once_and_the_log_checks_against_all(self):
        self.assertEqual(self.fetch(records(self.audit_dir)[-1])[0], 0)
        self.assertEqual(self.fetch()[1]["stored"], "already kept")
        self.write(3)
        self.assertEqual(self.fetch(records(self.audit_dir)[-1])[0], 0)
        self.assertEqual([m["batch"] for m in self.kept()[1]], [4, 7])
        rc, rep = self.check()
        self.assertEqual((rc, rep["anchors_matched"], rep["findings"]), (0, 2, []), rep)

    def test_garbled_anchors_are_refused_and_nothing_is_kept(self):
        good = records(self.audit_dir)[-1]
        other = os.path.join(tempfile.mkdtemp(), "audit")
        olog = audit.Log(other, XPK, lambda: XSK)
        olog.add("admit", "dev", {}, T0)
        olog.flush(T0)
        msg = cbor.loads(good)
        msg.value[1] = {4: b"x"}                                       # an unprotected header
        cases = {
            "random bytes": os.urandom(300),
            "half a record": good[:len(good) // 2],
            "a record and more": good + b"\x00",
            "two records": records(self.audit_dir)[-2] + good,
            "a byte changed": good[:200] + bytes([good[200] ^ 1]) + good[201:],
            "another key": records(other)[-1],
            "another typ": cose.sign1(VSK, VPK, cose.parse(good).payload, typ="application/eat+cwt"),
            "an unprotected header": cbor.dumps(msg),
            "too large": b"\x00" * (1 << 21),
        }
        for name, raw in cases.items():
            rc, rep = self.fetch(raw)
            self.assertEqual((rc, rep["stored"]), (1, None), name)
            self.assertIn(self.kinds(rep)[0], ("garbled",), (name, rep))
        self.assertEqual(self.snapshot(), {})
        rc, rep = self.tool("fetch", "--fetch-cmd", "true")
        self.assertEqual((rc, self.kinds(rep)), (1, ["unreachable"]))

    def test_a_replayed_older_anchor_is_a_rollback_and_is_not_kept(self):
        recs = records(self.audit_dir)
        self.fetch(recs[-1])
        rc, rep = self.fetch(recs[1])
        self.assertEqual((rc, self.kinds(rep), rep["stored"]), (1, ["rollback"], None), rep)
        self.assertEqual([m["batch"] for m in self.kept()[1]], [4])
        d = self.kept()[0]
        self.assertEqual(len(os.listdir(os.path.join(d, "conflicts"))), 1)
        with open(os.path.join(d, "events.log")) as f:
            self.assertIn("ALERT fetch rollback", f.read())

    def fork(self, keep):
        """The log written again (with the verifier's key) from batch keep+1 on."""
        recs = records(self.audit_dir)[:keep]
        for _, p in audit.segments(self.audit_dir):
            os.unlink(p)
        with open(os.path.join(self.audit_dir, "audit-000001.cbor"), "wb") as f:
            f.write(b"".join(recs))
        lg = audit.Log(self.audit_dir, VPK, lambda: VSK)
        lg.add("refuse", "dev", {"other": True}, T0 + 5)
        lg.flush(T0 + 5, promise=False)
        self.write(4, T0 + 6, lg)

    def test_a_forked_log_is_found_by_fetch_and_by_check(self):
        self.fetch(records(self.audit_dir)[-1])                       # batch 4
        before = self.snapshot()
        self.fork(2)
        recs = records(self.audit_dir)
        rc, rep = self.fetch(recs[3])                                  # another batch 4
        self.assertEqual((rc, self.kinds(rep)), (1, ["rewritten"]), rep)
        rc, rep = self.fetch(recs[4])                                  # batch 5 does not follow the kept 4
        self.assertEqual((rc, self.kinds(rep)), (1, ["rewritten"]), rep)
        self.assertEqual(self.snapshot(), before)                       # never overwritten, nothing added
        rc, rep = self.check()
        self.assertEqual((rc, self.kinds(rep)), (1, ["rewritten"]), rep)

    def test_a_truncated_log_and_a_gap_are_found(self):
        self.fetch(records(self.audit_dir)[-1])
        recs = records(self.audit_dir)
        with open(os.path.join(self.audit_dir, "audit-000001.cbor"), "wb") as f:
            f.write(b"".join(recs[:3]))                                 # a whole, signed, shorter log
        rc, rep = self.check()
        self.assertEqual((rc, self.kinds(rep)), (1, ["truncated"]), rep)
        self.assertIn("cut off", rep["findings"][0]["detail"])
        with open(os.path.join(self.audit_dir, "audit-000001.cbor"), "wb") as f:
            f.write(b"".join(recs[:2] + recs[3:]))
        self.assertEqual(self.kinds(self.check()[1]), ["gap"])
        with open(os.path.join(self.audit_dir, "audit-000001.cbor"), "wb") as f:
            f.write(b"".join(recs) + recs[-1][:100])                    # a torn end, twice in a row
        self.assertEqual(self.kinds(self.check()[1]), ["truncated"])

    def test_a_replaced_log_is_found(self):
        self.fetch(records(self.audit_dir)[-1])
        for _, p in audit.segments(self.audit_dir):
            os.unlink(p)
        self.write(2, log=audit.Log(self.audit_dir, VPK, lambda: VSK))
        rc, rep = self.fetch(records(self.audit_dir)[-1])
        self.assertEqual((rc, self.kinds(rep)), (1, ["replaced"]), rep)  # kept: the new log is the gateway's now
        rc, rep = self.check()
        self.assertEqual((rc, self.kinds(rep)), (1, ["replaced"]), rep)  # the old log's anchor is still missing

    def test_a_stale_log_is_found(self):
        lg = audit.Log(self.audit_dir, VPK, lambda: VSK, checkpoint_s=3600)
        lg.add("admit", "dev", {}, T0)
        lg.flush(T0)                                                    # the loop's batch: promises the next
        self.assertEqual(self.kinds(self.fetch(records(self.audit_dir)[-1])[1]), [])
        self.assertEqual(self.kinds(self.check(at=T0 + 86400)[1]), ["stale"])
        self.assertEqual(self.check("--no-freshness", at=T0 + 86400)[0], 0)

    def test_a_hostile_log_archive_is_refused(self):
        self.fetch(records(self.audit_dir)[-1])

        def tar_of(*members):
            buf = io.BytesIO()
            with tarfile.open(fileobj=buf, mode="w") as t:
                for name, data, kind in members:
                    ti = tarfile.TarInfo(name)
                    ti.type, ti.size = kind, len(data)
                    if kind == tarfile.SYMTYPE:
                        ti.linkname, ti.size = "/etc/passwd", 0
                    t.addfile(ti, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
            path = os.path.join(tempfile.mkdtemp(), "x.tar")
            with open(path, "wb") as f:
                f.write(buf.getvalue())
            return path
        with open(audit.segments(self.audit_dir)[0][1], "rb") as f:
            seg = f.read()
        for name, path in (("../escape", tar_of(("../audit-000001.cbor", seg, tarfile.REGTYPE))),
                           ("a symlink", tar_of(("audit-000001.cbor", b"", tarfile.SYMTYPE))),
                           ("another file", tar_of(("audit-000001.cbor", seg, tarfile.REGTYPE),
                                                   ("evil.py", b"x", tarfile.REGTYPE))),
                           ("twice", tar_of(("audit-000001.cbor", seg, tarfile.REGTYPE),
                                            ("audit-000001.cbor", seg, tarfile.REGTYPE))),
                           ("not a tar", None)):
            cmd = "cat %s" % q(path) if path else "head -c 3000 /dev/urandom"
            rc, rep = self.tool("check", "--log-cmd", cmd)
            self.assertEqual((rc, self.kinds(rep)), (1, ["garbled"]), (name, rep))
        rc, rep = self.tool("check", "--log-cmd", self.log_cmd(), "--max-log-bytes", "100")
        self.assertEqual(self.kinds(rep), ["garbled"])

    def test_a_store_changed_on_the_pc_is_found(self):
        self.fetch(records(self.audit_dir)[-1])
        d, lines = self.kept()
        f = os.path.join(d, "anchors", lines[0]["file"])
        aa.flip(f, 0)
        rc, rep = self.check()
        self.assertEqual((rc, self.kinds(rep)), (1, ["store"]), rep)
        os.unlink(f)
        self.assertEqual(self.kinds(self.check()[1]), ["store"])
        rc, rep = self.fetch(records(self.audit_dir)[-1])                 # a fetch does not repair it either
        self.assertEqual(self.kinds(rep), ["store"])

    def test_any_one_bit_changed_in_a_kept_anchor_is_found_whatever_its_mode_size_and_time(self):
        # regression (CI run 44845868657): the selftest overwrote byte 40, inside the random kid, with 0xff, which it
        # sometimes already was. Every byte position is changed here (XOR), as root would (mode ignored), with the
        # size and mtime kept: only the content against the manifest and the signature can find it
        self.fetch(records(self.audit_dir)[-1])
        d, lines = self.kept()
        f = os.path.join(d, "anchors", lines[0]["file"])
        st = os.stat(f)
        size = st.st_size
        for offset in sorted({0, 1, 11, 40, 100, size // 2, size - 1}):
            aa.flip(f, offset)
            st2 = os.stat(f)
            self.assertEqual((st2.st_size, st2.st_mtime_ns, st2.st_mode), (st.st_size, st.st_mtime_ns, st.st_mode))
            store = aa.Store(self.store, [VPK])
            try:
                with self.assertRaises(aa.Found) as cm:
                    store.load()
                self.assertEqual(cm.exception.kind, "store")
            finally:
                store.close()
            aa.flip(f, offset)                                            # back as it was
            store = aa.Store(self.store, [VPK])
            try:
                self.assertEqual(len(store.load()), 1)
            finally:
                store.close()

    def test_watch_alerts_on_changes_only(self):
        self.fetch(records(self.audit_dir)[-1])
        out = os.path.join(tempfile.mkdtemp(), "alerts")
        self.serve(records(self.audit_dir)[1])                           # an older batch, every cycle
        r = subprocess.run([sys.executable, "-I", TOOL, "watch", "--key", self.key, "--store", self.store,
                            "--gateway", "gw.test", "--at", str(T0 + 60), "--fetch-cmd", "cat %s" % q(self.anchor),
                            "--log-cmd", self.log_cmd(), "--interval", "1",
                            "--check-every", "2", "--max-cycles", "3", "--alert-cmd", "echo >>%s" % q(out)],
                           capture_output=True, text=True, timeout=60)
        self.assertEqual(r.returncode, 0, r.stderr)
        with open(out) as f:
            lines = f.read().splitlines()
        self.assertEqual([ln.split(":")[0] for ln in lines], ["ALERT fetch rollback", "OK check"], lines)

    def test_template_values_are_plain(self):
        r = subprocess.run([sys.executable, "-I", TOOL, "fetch", "--key", self.key, "--store", self.store,
                            "--gateway", "gw; touch /tmp/x"], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("not a plain host name", r.stderr)
        with open(TOOL) as f:
            self.assertIn("BatchMode=yes", f.read())

    def test_selftest(self):
        r = subprocess.run([sys.executable, "-I", TOOL, "--selftest"], capture_output=True, text=True, timeout=120)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("all cases as expected", r.stdout)


if __name__ == "__main__":
    unittest.main()
