#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Keep the gateway's audit-log anchors OFF the gateway, and check the log against all of them (docs/audit-and-policy.md,
"Anchors off the gateway").

An anchor is the last batch record of the verifier's audit log: a signed statement "log L had N batches, and this is
the last one". Only someone who kept it elsewhere can later see that the log was cut off at a record boundary, rolled
back or written again. This tool is that someone, on the bench PC:

  audit_anchors.py fetch --key KEY [--gateway ADDR]       run `fleet.py audit --out` on the gateway, verify the record
                                                          it returns, and keep it (append-only) in the store
  audit_anchors.py check --key KEY [--gateway ADDR | --log-dir DIR]
                                                          copy the whole log and verify it against EVERY kept anchor
  audit_anchors.py watch --key KEY [--gateway ADDR] [--interval 300] [--check-every 12] [--alert-cmd CMD]
  audit_anchors.py --selftest                             canned logs and anchors, no network

KEY: the verifier's ML-DSA-65 public key as tools/verify_audit.py reads it (hex, COSE_Key, identity.json). The store
is STORE/<sha256 of that key>/ (STORE default ~/aegis-tools/audit-anchors): anchors/ (one read-only file per kept
record, created with O_EXCL: never overwritten), manifest.jsonl (one appended line per anchor with its SHA-256),
conflicts/ (records the gateway sent that contradict a kept one, kept as evidence), events.log.

The commands run on the gateway are shell templates (--fetch-cmd, --log-cmd) with {gateway}, {fleet}, {policy} and
{state_dir}; the values are refused unless they are plain host names or paths. A fetch command prints the record's
bytes on stdout and nothing else; a log command prints a tar archive of the segment files.

Verification is tools/verify_audit.py's (third-party libraries only: pycose 1.1.0, cbor2 5.x, cryptography with
ML-DSA). Prints a JSON report; exit status 0 only if nothing was found.
"""
import argparse
import datetime
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))     # verify_audit.py beside this file, also under -I
import cbor2  # noqa: E402
import verify_audit as va  # noqa: E402

STORE = os.path.expanduser("~/aegis-tools/audit-anchors")
FLEET = "/root/aegis/gateway/aegisd/fleet.py"
POLICY = "/root/aegis/gateway/policy/fleet.json"
STATE_DIR = "/var/lib/aegis"
SSH = "ssh -n -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2 root@{gateway} "
# fleet.py audit writes the record to a file; only that file reaches stdout (its JSON report goes to stderr)
FETCH_CMD = SSH + ("'f=$(mktemp) || exit 1; python3 {fleet} audit {policy}{signers_opt} --state-dir {state_dir} --out \"$f\" >&2; "
                   "rc=$?; cat \"$f\"; rm -f \"$f\"; exit $rc'")
# the segment files, under the writers' lock where flock exists (no torn end in the copy)
LOG_CMD = SSH + ("'cd {state_dir}/audit && if command -v flock >/dev/null 2>&1; then flock -s lock tar -cf - "
                 "audit-*.cbor; else tar -cf - audit-*.cbor; fi'")
SAFE = re.compile(r"[A-Za-z0-9._:/@%+=-]{1,255}\Z")
ANCHOR_NAME = re.compile(r"([0-9a-f]{32})-b(\d{12})-([0-9a-f]{64})\.cbor\Z")
MAX_OUTPUT = 1 << 20                 # what a fetch command may print before it is refused unread
MAX_LOG = 1 << 30                    # bytes of a log copy (default; --max-log-bytes)
CMD_TIMEOUT = 120


class Found(Exception):
    """Something the operator must look at; kind is one word."""

    def __init__(self, kind, text):
        Exception.__init__(self, text)
        self.kind = kind


def now_iso():
    return datetime.datetime.now().astimezone().isoformat(timespec="seconds")


def render(template, values):
    for k, v in values.items():
        if k == "signers_opt":      # "" or " --policy-signers PATH": the one place a space is allowed
            if v and not (v.startswith(" --policy-signers ") and SAFE.match(v[len(" --policy-signers "):])):
                raise SystemExit("audit_anchors: --policy-signers %r is not a plain path" % v)
            continue
        if not SAFE.match(str(v)):
            raise SystemExit("audit_anchors: %s %r is not a plain host name or path" % (k, v))
    try:
        return template.format(**values)
    except (KeyError, IndexError, ValueError) as e:
        raise SystemExit("audit_anchors: the command template is not usable: %s" % e)


def run_cmd(cmd, limit):
    """stdout of a shell command (bytes, at most limit), its exit status and the tail of its stderr."""
    try:
        p = subprocess.run(["sh", "-c", cmd], stdin=subprocess.DEVNULL, capture_output=True, timeout=CMD_TIMEOUT)
    except subprocess.TimeoutExpired:
        raise Found("unreachable", "the command timed out after %d s" % CMD_TIMEOUT) from None
    if len(p.stdout) > limit:
        raise Found("garbled", "the command printed %d bytes, more than %d" % (len(p.stdout), limit))
    return p.stdout, p.returncode, p.stderr.decode("utf-8", "replace").strip()[-300:]


# ---- the store --------------------------------------------------------------------------------------------------------

class Store:
    """STORE/<key sha256>/: append-only. Nothing in it is ever rewritten or deleted by this tool."""

    def __init__(self, root, pubs):
        self.pubs = pubs
        self.keys = {va.thumbprint(p): p for p in pubs}
        self.id = hashlib.sha256(pubs[0]).hexdigest()
        self.dir = os.path.join(root, self.id)
        self.anchors = os.path.join(self.dir, "anchors")
        self.conflicts = os.path.join(self.dir, "conflicts")
        self.manifest = os.path.join(self.dir, "manifest.jsonl")
        for d in (self.dir, self.anchors, self.conflicts):
            os.makedirs(d, mode=0o700, exist_ok=True)
        self.lockfd = os.open(os.path.join(self.dir, "lock"), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.lockfd, fcntl.LOCK_EX)
        keyfile = os.path.join(self.dir, "key.pub")
        try:
            write_once(keyfile, (pubs[0].hex() + "\n").encode())
        except FileExistsError:
            with open(keyfile) as f:
                if f.read().strip() != pubs[0].hex():
                    raise Found("store", "%s holds another key than the one given" % keyfile) from None

    def close(self):
        os.close(self.lockfd)

    def load(self):
        """The kept anchors in the order they were kept, each verified again: [dict]. Found("store") if the store is
        not what its manifest says (a file changed, missing, or not listed)."""
        out, listed = [], set()
        try:
            with open(self.manifest) as f:
                lines = f.read().splitlines()
        except FileNotFoundError:
            lines = []
        for n, line in enumerate(lines, 1):
            try:
                m = json.loads(line)
                name, digest = m["file"], m["sha256"]
                assert isinstance(name, str) and ANCHOR_NAME.match(name) and isinstance(digest, str)
            except (ValueError, KeyError, TypeError, AssertionError):
                raise Found("store", "manifest line %d is not an anchor line" % n) from None
            try:
                with open(os.path.join(self.anchors, name), "rb") as f:
                    raw = f.read()
            except FileNotFoundError:
                raise Found("store", "anchor %s of the manifest is missing" % name) from None
            if hashlib.sha256(raw).hexdigest() != digest or digest != ANCHOR_NAME.match(name).group(3):
                raise Found("store", "anchor %s is not the file the manifest names (sha256 differs)" % name)
            try:
                b = va.read_batch(raw, self.keys, "kept anchor %s" % name)
            except va.Failed as e:
                raise Found("store", str(e)) from None
            listed.add(name)
            out.append(dict(b, raw=raw, file=name))
        extra = sorted(set(os.listdir(self.anchors)) - listed)
        if extra:
            raise Found("store", "files in anchors/ that the manifest does not list: %s" % ", ".join(extra[:5]))
        return out

    def keep(self, b, raw):
        name = "%s-b%012d-%s.cbor" % (b["log"].hex(), b["batch"], b["head"].hex())
        write_once(os.path.join(self.anchors, name), raw)
        line = {"file": name, "sha256": b["head"].hex(), "log": b["log"].hex(), "batch": b["batch"],
                "time": b["time"], "due": b["due"], "kept": now_iso(), "kept_unix": int(time.time())}
        append(self.manifest, json.dumps(line, sort_keys=True) + "\n")
        return name

    def conflict(self, raw, why):
        name = "%d-%s.cbor" % (int(time.time()), hashlib.sha256(raw).hexdigest())
        try:
            write_once(os.path.join(self.conflicts, name), raw)
        except FileExistsError:
            pass
        return "conflicts/" + name

    def event(self, line):
        append(os.path.join(self.dir, "events.log"), "%s %s\n" % (now_iso(), line))


def write_once(path, data):
    """Create path with data; FileExistsError if it is there. Read-only once written, flushed with its directory."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o400)
    try:
        if os.write(fd, data) != len(data):
            raise OSError("short write to %s" % path)
        os.fsync(fd)
    finally:
        os.close(fd)
    dfd = os.open(os.path.dirname(path), os.O_RDONLY)
    try:
        os.fsync(dfd)
    finally:
        os.close(dfd)


def flip(path, offset):
    """Change one bit of a file in place, its size and times kept (selftest, tests: a store changed behind the tool's
    back, by someone the read-only mode does not stop)."""
    st = os.stat(path)
    os.chmod(path, st.st_mode | 0o200)
    with open(path, "r+b") as f:
        f.seek(offset)
        b = f.read(1)
        f.seek(offset)
        f.write(bytes([b[0] ^ 0x01]))
    os.chmod(path, st.st_mode)
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns))


def append(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, text.encode())
        os.fsync(fd)
    finally:
        os.close(fd)


# ---- fetch ------------------------------------------------------------------------------------------------------------

def fetch(store, raw, now):
    """Judge one record the gateway sent against the store, and keep it if it is new and consistent.
    Returns (report, findings)."""
    try:
        b = va.read_batch(raw, store.keys, "the gateway's anchor")
    except va.Failed as e:
        return {"stored": None}, [("garbled", "refused, nothing kept: %s" % e)]
    kept = store.load()
    rep = {"log": b["log"].hex(), "batch": b["batch"], "sha256": b["head"].hex(), "time": b["time"], "due": b["due"],
           "stored": None}
    findings = []
    same = [a for a in kept if a["log"] == b["log"]]
    logs = []
    for a in kept:
        if a["log"] not in logs:
            logs.append(a["log"])
    at = [a for a in same if a["batch"] == b["batch"]]
    if at and at[0]["head"] != b["head"]:
        findings.append(("rewritten", "the gateway's batch %d is not the batch %d kept in %s: the log was written "
                                      "again (evidence: %s)" % (b["batch"], b["batch"], at[0]["file"],
                                                                store.conflict(raw, "rewritten"))))
    elif at:
        rep["stored"] = "already kept"
    elif same and b["batch"] < max(a["batch"] for a in same):
        top = max(same, key=lambda a: a["batch"])
        findings.append(("rollback", "the gateway's log ends at batch %d, and batch %d of it was kept (%s): cut off "
                                     "or rolled back (evidence: %s)" % (b["batch"], top["batch"], top["file"],
                                                                        store.conflict(raw, "rollback"))))
    elif logs and b["log"] in logs[:-1]:
        findings.append(("rollback", "the gateway is back on log %s, which was followed by log %s (evidence: %s)" % (
            b["log"].hex(), logs[-1].hex(), store.conflict(raw, "rollback"))))
    else:
        prev = [a for a in same if a["batch"] == b["batch"] - 1]
        if prev and prev[0]["head"] != b["prev"]:
            findings.append(("rewritten", "the gateway's batch %d does not continue the kept batch %d (%s): the log "
                                          "was written again (evidence: %s)" % (b["batch"], b["batch"] - 1,
                                                                                prev[0]["file"],
                                                                                store.conflict(raw, "rewritten"))))
        else:
            if logs and b["log"] not in logs:
                findings.append(("replaced", "a new log %s, after log %s: the old one was deleted, damaged or "
                                             "replaced; kept, and the old log's anchors stay" % (
                                                 b["log"].hex(), logs[-1].hex())))
            rep["stored"] = store.keep(b, raw)
    if b["due"] is not None and now > b["due"]:
        findings.append(("stale", "the last batch promised the next one by %d and it is %d: the verifier stopped, or "
                                  "the end was cut off" % (b["due"], int(now))))
    return rep, findings


def cmd_fetch(a, store):
    cmd = render(a.fetch_cmd, values(a))
    try:
        raw, rc, err = run_cmd(cmd, MAX_OUTPUT)
    except Found as e:
        return {"stored": None}, [(e.kind, str(e))]
    if not raw:
        return {"stored": None, "exit": rc}, [("unreachable", "no record came back (exit %d): %s" % (rc, err))]
    rep, findings = fetch(store, raw, a.at or time.time())
    rep["exit"] = rc
    return rep, findings


# ---- check ------------------------------------------------------------------------------------------------------------

def untar(data, into, limit):
    """The segment files of a tar archive, written into an empty directory: regular files named audit-NNNNNN.cbor at
    the top only. Anything else in the archive is refused, not skipped (except the directory entry ".")."""
    total = 0
    try:
        tf = tarfile.open(fileobj=io.BytesIO(data), mode="r:")
        members = tf.getmembers()
    except (tarfile.TarError, EOFError, ValueError) as e:
        raise Found("garbled", "the log copy is not a tar archive: %s" % e) from None
    seen = set()
    for m in members:
        name = m.name[2:] if m.name.startswith("./") else m.name
        if m.isdir() and name in ("", ".", "./"):
            continue
        if not (m.isreg() and va.SEGMENT.match(name)) or name in seen:
            raise Found("garbled", "the log copy holds %r, which is not one segment file" % m.name[:80])
        total += m.size
        if total > limit:
            raise Found("garbled", "the log copy is larger than %d bytes" % limit)
        seen.add(name)
        with open(os.path.join(into, name), "xb") as f:
            f.write(tf.extractfile(m).read())
    if not seen:
        raise Found("garbled", "the log copy holds no segment file")


def classify(text):
    if text.startswith("stale"):
        return "stale"
    if "cut off" in text or "ends in the middle" in text:
        return "truncated"
    if "batches are missing" in text or "begins at batch" in text or "not here whole" in text:
        return "gap"
    if "out of order, or repeated" in text:
        return "reordered"
    if "does not continue" in text or "does not begin at the entry" in text or "signature does not verify" in text:
        return "rewritten"
    return "broken"


def chain_index(paths):
    """{(log, batch): sha256} of every record of a log copy (already verified by check_log)."""
    seen = {}
    for path in paths:
        with open(path, "rb") as f:
            for _, raw in va.records(f.read(), os.path.basename(path)):
                c = cbor2.loads(cbor2.loads(raw).value[2])
                seen[(c[2], c[3])] = hashlib.sha256(raw).digest()
    return seen


def check(store, log_dir, now, allow_pruned=False):
    """The log copy in log_dir against every kept anchor. Returns (report, findings)."""
    kept = store.load()
    paths = [os.path.join(log_dir, n) for _, n in sorted(
        (int(va.SEGMENT.match(n).group(1)), n) for n in os.listdir(log_dir) if va.SEGMENT.match(n))]
    try:
        rep = va.check_log(paths, store.pubs, now=now, allow_pruned=allow_pruned)
    except va.Failed as e:
        return {"anchors": len(kept)}, [(classify(str(e)), str(e))]
    except Exception as e:  # noqa: BLE001 - whatever hostile bytes provoke in cbor2 or pycose: not verified
        return {"anchors": len(kept)}, [("broken", "not readable: %s: %s" % (type(e).__name__, str(e)[:200]))]
    seen = chain_index(paths)
    logs = {bytes.fromhex(lg["log"]): lg for lg in rep["logs"]}
    findings, ok, skipped = [], 0, 0
    for a in kept:
        lg = logs.get(a["log"])
        what = "anchor %s (batch %d of log %s)" % (a["file"], a["batch"], a["log"].hex()[:8])
        if lg is None:
            findings.append(("replaced", "%s: that log is not in the copy: it was deleted or replaced" % what))
        elif a["batch"] > lg["last_batch"]:
            findings.append(("truncated", "%s: the log ends at batch %d: the end was cut off" % (what, lg["last_batch"])))
        elif a["batch"] < lg["first_batch"]:
            if allow_pruned:
                skipped += 1
            else:
                findings.append(("gap", "%s: the copy begins at batch %d (pruned? --allow-pruned)" % (
                    what, lg["first_batch"])))
        elif seen[(a["log"], a["batch"])] != a["head"]:
            findings.append(("rewritten", "%s: batch %d of the copy is another record: the log was written again "
                                          "from there or before" % (what, a["batch"])))
        else:
            ok += 1
    if kept and kept[-1]["log"].hex() != rep["logs"][-1]["log"] and kept[-1]["log"] in logs:
        findings.append(("rollback", "the copy ends in log %s, but log %s was kept after it" % (
            rep["logs"][-1]["log"][:8], kept[-1]["log"].hex()[:8])))
    return {"anchors": len(kept), "anchors_matched": ok, "anchors_before_copy": skipped, "logs": rep["logs"],
            "pruned": rep["pruned"], "freshness": rep["freshness"]}, findings


def cmd_check(a, store):
    now = None if a.no_freshness else (a.at or int(time.time()))
    if a.log_dir:
        return check(store, a.log_dir, now, a.allow_pruned)
    cmd = render(a.log_cmd, values(a))
    for attempt in (1, 2):                  # a copy taken while a batch was written may end in half of it: once more
        tmp = tempfile.mkdtemp(prefix="aegis-audit-copy-")
        try:
            try:
                data, rc, err = run_cmd(cmd, a.max_log_bytes + (1 << 20))
                if not data:
                    raise Found("unreachable", "no log copy came back (exit %d): %s" % (rc, err))
                untar(data, tmp, a.max_log_bytes)
            except Found as e:
                return {"stored": None}, [(e.kind, str(e))]
            rep, findings = check(store, tmp, now, a.allow_pruned)
            if attempt == 1 and any("ends in the middle" in t for _, t in findings):
                continue
            rep["copy_sha256"] = hashlib.sha256(data).hexdigest()
            return rep, findings
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


# ---- watch ------------------------------------------------------------------------------------------------------------

def alert(cmd, line):
    """--alert-cmd: run with the event line as its one argument (as tools/bench_watch.py); never raises."""
    if not cmd:
        return
    try:
        subprocess.run(["sh", "-c", cmd + ' "$1"', "alert", line], timeout=30, capture_output=True)
    except (OSError, subprocess.TimeoutExpired):
        pass


def report(store, what, findings, alert_cmd=None, said=None):
    """Write findings to events.log and alert; with said (watch), only when the set of kinds changes."""
    kinds = sorted({k for k, _ in findings})
    if said is not None:
        if said.get(what) == kinds:
            return
        said[what] = kinds
    lines = ["ALERT %s %s: %s" % (what, k, t) for k, t in findings] or (["OK %s" % what] if said is not None else [])
    for line in lines:
        store.event(line)
        alert(alert_cmd, line)


def cmd_watch(a, pubs):
    said, n = {}, 0
    while True:
        t0 = time.monotonic()
        for what, run in (("fetch", cmd_fetch), ("check", cmd_check)):
            if what == "check" and (not a.check_every or n % a.check_every):
                continue
            store = Store(a.store, pubs)
            try:
                try:
                    _, findings = run(a, store)
                except Found as e:
                    findings = [(e.kind, str(e))]
                report(store, what, findings, a.alert_cmd, said)
            finally:
                store.close()
        n += 1
        if a.max_cycles and n >= a.max_cycles:
            return 0
        time.sleep(max(1.0, a.interval - (time.monotonic() - t0)))


# ---- selftest ---------------------------------------------------------------------------------------------------------

def selftest():
    """Canned logs and anchors (signed here with a fresh ML-DSA-65 key), no network: every case the tool must see."""
    from cryptography.hazmat.primitives.asymmetric import mldsa
    from cryptography.hazmat.primitives import serialization
    sk = mldsa.MLDSA65PrivateKey.generate()
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    other = mldsa.MLDSA65PrivateKey.generate()
    kid = va.thumbprint(pk)

    def sign(payload, key=sk, k=kid):
        prot = cbor2.dumps({1: va.ALG_ML_DSA_65, 4: k, 16: va.AUDIT_TYP}, canonical=True)
        sig = key.sign(cbor2.dumps(["Signature1", prot, b"", payload]))
        return cbor2.dumps(cbor2.CBORTag(18, [prot, {}, payload, sig]))

    def chain(n, log=b"L" * 16, base=None, t=1_800_000_000, key=sk):
        recs = list(base or [])
        for i in range(len(recs) + 1, n + 1):
            prev = hashlib.sha256(recs[-1]).digest() if recs else bytes(32)
            ev = "log-start" if i == 1 else "admit"
            recs.append(sign(cbor2.dumps({1: va.AUDIT_FORMAT, 2: log, 3: i, 4: prev, 5: t + 60 * i, 6: i,
                                          7: [{1: t + 60 * i, 2: ev, 3: "dev"}], 8: t + 60 * i + 3700},
                                         canonical=True), key))
        return recs

    good = chain(6)
    fork = chain(6, base=good[:3], t=1_800_000_007)
    now = 1_800_000_400
    tmp = tempfile.mkdtemp(prefix="aegis-anchors-selftest-")
    bad = 0

    def expect(name, findings, kinds):
        nonlocal bad
        got = sorted({k for k, _ in findings})
        ok = got == sorted(kinds)
        bad += not ok
        print("%-52s %s%s" % (name, "ok" if ok else "WRONG", "" if ok else " (found %s, wanted %s)" % (got, kinds)))

    def logdir(recs, name):
        d = os.path.join(tmp, name)
        os.makedirs(d)
        with open(os.path.join(d, "audit-000001.cbor"), "wb") as f:
            f.write(b"".join(recs))
        return d

    try:
        store = Store(os.path.join(tmp, "store"), [pk])
        expect("a garbled anchor is refused", fetch(store, b"\xd2\x84garbage", now)[1], ["garbled"])
        expect("an anchor with bytes after it is refused", fetch(store, good[1] + b"\x00", now)[1], ["garbled"])
        expect("an anchor of another key is refused",
               fetch(store, chain(2, key=other)[1], now)[1], ["garbled"])
        expect("batch 2 is kept", fetch(store, good[1], now)[1], [])
        expect("batch 2 again: already kept", fetch(store, good[1], now)[1], [])
        expect("batch 4 is kept", fetch(store, good[3], now)[1], [])
        expect("a replayed older anchor (batch 3) is a rollback", fetch(store, good[2], now)[1], ["rollback"])
        expect("a forked batch 4 is a rewrite", fetch(store, fork[3], now)[1], ["rewritten"])
        expect("a forked batch 5 does not continue the kept batch 4", fetch(store, fork[4], now)[1], ["rewritten"])
        expect("the whole log verifies against both anchors", check(store, logdir(good, "whole"), now)[1], [])
        expect("the log cut off after batch 3", check(store, logdir(good[:3], "cut"), now)[1], ["truncated"])
        expect("the log written again from batch 4", check(store, logdir(fork, "forked"), now)[1], ["rewritten"])
        expect("batch 3 removed from the middle", check(store, logdir(good[:2] + good[3:], "gap"), now)[1], ["gap"])
        expect("another log in its place", check(store, logdir(chain(5, log=b"M" * 16), "other"), now)[1],
               ["replaced"])
        expect("stale when read long after the last promise",
               check(store, logdir(good, "stale"), now + 10 ** 6)[1], ["stale"])
        expect("kept anchors are read-only and listed", [] if all(
            not os.access(os.path.join(store.anchors, f), os.W_OK) for f in os.listdir(store.anchors))
            and len(store.load()) == 2 else [("store", "")], [])
        store.close()
        # one bit flipped (XOR: a byte is never "changed" to the value it had), same size, same mtime, written as
        # root could: what is found is the content against the manifest, not the mode or the time
        flip(os.path.join(store.anchors, sorted(os.listdir(store.anchors))[0]), 40)
        store = Store(os.path.join(tmp, "store"), [pk])
        try:
            store.load()
            found = []
        except Found as e:
            found = [(e.kind, str(e))]
        expect("a kept anchor changed on the PC is found", found, ["store"])
        store.close()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    print("selftest: %s" % ("all cases as expected" if not bad else "%d case(s) wrong" % bad))
    return 1 if bad else 0


# ---- main -------------------------------------------------------------------------------------------------------------

def values(a):
    if not a.gateway:
        raise SystemExit("audit_anchors: no gateway: give --gateway or set AEGIS_GATEWAY")
    return {"gateway": a.gateway, "fleet": a.fleet, "policy": a.policy, "state_dir": a.state_dir,
            "signers_opt": (" --policy-signers " + a.policy_signers) if a.policy_signers else ""}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv == ["--selftest"]:
        return selftest()
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("cmd", choices=["fetch", "check", "watch"])
    ap.add_argument("--key", action="append", required=True,
                    help="the verifier's public key (hex, COSE_Key, identity.json); the first names the store")
    ap.add_argument("--gateway", default=os.environ.get("AEGIS_GATEWAY"), help="address (or env AEGIS_GATEWAY)")
    ap.add_argument("--store", default=STORE, help="default %(default)s")
    ap.add_argument("--fleet", default=FLEET, help="fleet.py on the gateway (default %(default)s)")
    ap.add_argument("--policy", default=POLICY, help="the policy on the gateway (default %(default)s)")
    ap.add_argument("--policy-signers", help="the policy signers file on the gateway, when it runs a signed policy "
                    "(then --policy names the signed file)")
    ap.add_argument("--state-dir", default=STATE_DIR, help="the verifier's state on the gateway (default %(default)s)")
    ap.add_argument("--fetch-cmd", default=FETCH_CMD, help="shell template printing one batch record")
    ap.add_argument("--log-cmd", default=LOG_CMD, help="shell template printing a tar of the segment files")
    ap.add_argument("--log-dir", help="check: a local copy of the log directory instead of --log-cmd")
    ap.add_argument("--max-log-bytes", type=int, default=MAX_LOG)
    ap.add_argument("--allow-pruned", action="store_true", help="check: the copy may begin after batch 1")
    ap.add_argument("--no-freshness", action="store_true", help="check: do not fail a log whose promise lapsed")
    ap.add_argument("--at", type=int, help="judge freshness as of this Unix time (default now)")
    ap.add_argument("--interval", type=int, default=300, help="watch: seconds between fetches (default 300)")
    ap.add_argument("--check-every", type=int, default=12, help="watch: a full check every N fetches (0: never)")
    ap.add_argument("--max-cycles", type=int, default=0, help="watch: stop after N cycles (0: never)")
    ap.add_argument("--alert-cmd", help="shell command run with each ALERT/OK line as its argument")
    a = ap.parse_args(argv)
    try:
        pubs = [p for path in a.key for p in va.load_keys(path)]
    except Exception as e:  # noqa: BLE001 - a key file that is not one
        ap.error("--key: %s" % e)
    if a.cmd == "watch":
        return cmd_watch(a, pubs)
    store = Store(a.store, pubs)
    try:
        try:
            rep, findings = (cmd_fetch if a.cmd == "fetch" else cmd_check)(a, store)
        except Found as e:
            rep, findings = {}, [(e.kind, str(e))]
        report(store, a.cmd, findings)
    finally:
        store.close()
    print(json.dumps(dict(va.printable(rep), store=store.dir, findings=[{"kind": k, "detail": t} for k, t in findings],
                          ok=not findings), indent=1))
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main())
