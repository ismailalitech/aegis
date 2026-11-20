# SPDX-License-Identifier: Apache-2.0
"""The verifier's signed audit log (docs/audit-and-policy.md): what it decided, in order, signed by its identity key.

The log is a directory of segment files, audit-000001.cbor, audit-000002.cbor, ... Each file is a CBOR sequence
(RFC 8742) of batch records, and every byte of it is inside one. A batch record is an Aegis COSE_Sign1 (common/cose.py:
ML-DSA-65, RFC 9964) with typ "application/vnd.aegis.audit-batch+cbor", signed by the verifier's identity key, whose
payload is

  { 1: "tag:github.com,2026:ismailalitech/aegis/audit/v1",
    2: log        bstr .size 16     made at random when the log begins: batches of two logs never join
    3: batch      uint              1, 2, 3, ... through every segment of the log
    4: prev       bstr .size 32     SHA-256 of the batch record before this one (the whole COSE_Sign1); 32 zero bytes
                                    for batch 1
    5: time       uint              the verifier's clock when it signed
    6: first      uint              the number of this batch's first entry; entries count 1, 2, 3, ... through the log
    7: entries    [* entry]         may be empty: "nothing to report up to this time"
    ? 8: due      uint              the verifier promises the next batch by this time (absent: no promise)
  }
  entry = { 1: time uint, 2: event tstr, ? 3: subject tstr, ? 4: details { * tstr => any } }

So an entry cannot be changed, removed or moved without the key (each batch is signed), a batch cannot be removed
from the middle or put elsewhere (each names the hash of the one before and its own number), and the end cannot be
cut off unnoticed by someone who holds a later batch record or its hash (an anchor: any batch record is one, being a
signed statement of where the log stood), or who reads the log after the time the last batch promised the next one
by. What the chain cannot show is said in the document: whoever holds the verifier's key can write another log.

One signature per batch, not per entry, and a batch only when there is something to say: the fleet loop adds an entry
when a decision changes, not every cycle, so a steady fleet costs one empty batch per "checkpoint_s" and nothing else.

Standard library only; ML-DSA through common/mldsa.py.
"""
import fcntl
import hashlib
import os
import re
import secrets
import time

import cbor
import cose

FORMAT = "tag:github.com,2026:ismailalitech/aegis/audit/v1"
TYP = "application/vnd.aegis.audit-batch+cbor"
B_FORMAT, B_LOG, B_BATCH, B_PREV, B_TIME, B_FIRST, B_ENTRIES, B_DUE = 1, 2, 3, 4, 5, 6, 7, 8
E_TIME, E_EVENT, E_SUBJECT, E_DETAILS = 1, 2, 3, 4
LOG_ID_LEN = 16
GENESIS = bytes(32)
MAX_ENTRY = 4096                # bytes of one encoded entry; a longer one loses its details and says so
MAX_BATCH_PAYLOAD = 10240       # so a record stays under cose.MAX_SIGN1 with its 3309-byte signature
MAX_ENTRIES = 256               # in one batch
MAX_PENDING = 512               # entries held in memory while the log cannot be written; later ones are counted
MAX_TIME = 1 << 40
SEGMENT = re.compile(r"audit-(\d{6})\.cbor\Z")
EVENT = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
LOCK = "lock"


class Refused(ValueError):
    """The bytes are not this log, whole and in order. The text says why."""


class _Torn(Exception):
    """A segment ends in the middle of a record (the process died while it wrote): offset of the last whole one."""

    def __init__(self, offset):
        Exception.__init__(self, "torn at %d" % offset)
        self.offset = offset


# ---- entries --------------------------------------------------------------------------------------------------------

def clean(v, depth=0):
    """v as something the log can carry: integers, text, byte strings, booleans, null, lists and maps with text keys,
    all bounded. Whatever else an endpoint or a policy managed to put into a verdict becomes its repr, cut short: an
    entry is always written, and nothing in it can make the batch unreadable."""
    if v is None or isinstance(v, bool):
        return v
    if isinstance(v, int):
        return v if -(1 << 63) <= v < (1 << 64) else str(v)[:80]
    if isinstance(v, str):
        return v[:300].encode("utf-8", "replace").decode("utf-8")       # a lone surrogate is not UTF-8
    if isinstance(v, (bytes, bytearray)):
        return bytes(v[:256])
    if depth >= 4:
        return "..."
    if isinstance(v, (list, tuple)):
        return [clean(x, depth + 1) for x in v[:16]]
    if isinstance(v, dict):
        out = {}
        for k, x in list(v.items())[:24]:
            out[clean(k if isinstance(k, str) else repr(k))[:64]] = clean(x, depth + 1)
        return out
    return repr(v)[:80]


def entry(event, subject=None, details=None, now=None):
    """One entry as the map a batch carries. event: a short lower-case word ("admit", "refuse", ...)."""
    if not (isinstance(event, str) and EVENT.match(event)):
        raise ValueError("an event is a short lower-case word, not %r" % (event,))
    try:
        when = int(time.time() if now is None else now)
    except (TypeError, ValueError, OverflowError):
        when = -1
    e = {E_TIME: when if 0 <= when < MAX_TIME else int(time.time()), E_EVENT: event}     # not a time: the time it is
    if subject is not None:
        e[E_SUBJECT] = clean(str(subject))[:64]
    if details:
        e[E_DETAILS] = clean(dict(details))
        size = len(cbor.dumps(e, sort=True))
        if size > MAX_ENTRY:
            e[E_DETAILS] = {"truncated": True, "bytes": size}
    return e


def _read_entry(e):
    if not (isinstance(e, dict) and {E_TIME, E_EVENT} <= set(e) <= {E_TIME, E_EVENT, E_SUBJECT, E_DETAILS}):
        raise Refused("an entry is not {time, event[, subject][, details]}")
    if not (type(e[E_TIME]) is int and 0 <= e[E_TIME] < MAX_TIME and isinstance(e[E_EVENT], str)
            and EVENT.match(e[E_EVENT])):
        raise Refused("an entry's time or event is not a time or an event")
    if E_SUBJECT in e and not (isinstance(e[E_SUBJECT], str) and len(e[E_SUBJECT]) <= 64):
        raise Refused("an entry's subject is not a short text")
    if E_DETAILS in e and not (isinstance(e[E_DETAILS], dict) and all(isinstance(k, str) for k in e[E_DETAILS])):
        raise Refused("an entry's details are not a map with text keys")
    return {"time": e[E_TIME], "event": e[E_EVENT], "subject": e.get(E_SUBJECT), "details": e.get(E_DETAILS) or {}}


# ---- batch records --------------------------------------------------------------------------------------------------

class Batch:
    """A decoded batch record. Until its signature was checked (open_batch with a key), nothing in it is
    authenticated."""

    def __init__(self, raw, kid, log, batch, prev, when, first, entries, due):
        self.raw, self.kid, self.log, self.batch, self.prev = raw, kid, log, batch, prev
        self.time, self.first, self.entries, self.due = when, first, entries, due
        self.head = hashlib.sha256(raw).digest()        # what the next batch names, and what an anchor is compared by

    @property
    def next_entry(self):
        return self.first + len(self.entries)


def _uint(v, limit=1 << 53):
    return type(v) is int and 0 <= v < limit


def _open_batch(raw, pk):
    s = cose.parse(raw) if pk is None else cose.verify1(raw, pk, typ=TYP)
    if s.typ != TYP:
        raise Refused("typ is %r, not %r" % (s.typ[:48], TYP))
    c = cbor.loads(s.payload)
    if not isinstance(c, dict) or cbor.dumps(c, sort=True) != s.payload:
        raise Refused("the batch is not a map in deterministic encoding")
    keys = {B_FORMAT, B_LOG, B_BATCH, B_PREV, B_TIME, B_FIRST, B_ENTRIES}
    if not keys <= set(c) <= keys | {B_DUE}:
        raise Refused("the batch is not {format, log, batch, prev, time, first, entries[, due]}")
    if c[B_FORMAT] != FORMAT:
        raise Refused("the batch's format is not %s" % FORMAT)
    if not (isinstance(c[B_LOG], bytes) and len(c[B_LOG]) == LOG_ID_LEN and isinstance(c[B_PREV], bytes)
            and len(c[B_PREV]) == 32):
        raise Refused("the batch's log or prev is not a byte string of its length")
    if not (_uint(c[B_BATCH]) and c[B_BATCH] >= 1 and _uint(c[B_FIRST]) and c[B_FIRST] >= 1
            and _uint(c[B_TIME], MAX_TIME) and (B_DUE not in c or _uint(c[B_DUE], MAX_TIME))):
        raise Refused("the batch's number, first entry, time or due is not one")
    if not (isinstance(c[B_ENTRIES], list) and len(c[B_ENTRIES]) <= MAX_ENTRIES):
        raise Refused("the batch's entries are not a list of at most %d" % MAX_ENTRIES)
    return Batch(bytes(raw), s.kid, c[B_LOG], c[B_BATCH], c[B_PREV], c[B_TIME], c[B_FIRST],
                 [_read_entry(e) for e in c[B_ENTRIES]], c.get(B_DUE))


def open_batch(raw, pk=None):
    """The Batch of one record; with pk only if it is signed by that key. Refused (this module's, or cose.Refused)
    and nothing else, whatever the bytes are."""
    try:
        return _open_batch(raw, pk)
    except (Refused, cose.Refused):
        raise
    except Exception as e:  # noqa: BLE001 - CBORError, RecursionError, a type the checks above did not expect
        raise Refused("not a batch record: %s: %s" % (type(e).__name__, e)) from None


def make_batch(sk, pk, log, batch, prev, first, entries, now, due=None):
    """One signed batch record."""
    c = {B_FORMAT: FORMAT, B_LOG: bytes(log), B_BATCH: batch, B_PREV: bytes(prev), B_TIME: int(now), B_FIRST: first,
         B_ENTRIES: list(entries)}
    if due is not None:
        c[B_DUE] = int(due)
    return cose.sign1(sk, pk, cbor.dumps(c, sort=True), typ=TYP)


def split(data):
    """The records of one segment's bytes, as [(offset, bytes)]. _Torn if the data ends inside a record; Refused if
    it is not a sequence of CBOR items at all."""
    out, i = [], 0
    while i < len(data):
        try:
            _, end = cbor.loads_prefix(data, i)
        except cbor.CBORError as e:
            if str(e).startswith("truncated"):
                raise _Torn(i) from None
            raise Refused("not a record at offset %d: %s" % (i, e)) from None
        except Exception as e:  # noqa: BLE001 - RecursionError, UnicodeDecodeError
            raise Refused("not a record at offset %d: %s: %s" % (i, type(e).__name__, e)) from None
        out.append((i, bytes(data[i:end])))
        i = end
    return out


class reading:
    """with reading(directory): the log does not change underneath (a writer appends under the same lock). For a
    reader beside a running verifier; a copy of the log needs none."""

    def __init__(self, directory):
        self.dir = directory

    def __enter__(self):
        self.fd = os.open(os.path.join(self.dir, LOCK), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(self.fd, fcntl.LOCK_SH)
        return self

    def __exit__(self, *exc):
        os.close(self.fd)


def segments(directory):
    """The log's segment files in order: [(number, path)]."""
    try:
        names = os.listdir(directory)
    except FileNotFoundError:
        return []
    found = sorted((int(m.group(1)), n) for n in names for m in [SEGMENT.match(n)] if m)
    return [(num, os.path.join(directory, n)) for num, n in found]


# ---- reading a log: the check a relying party makes -------------------------------------------------------------------

def verify(paths, keys, anchors=(), heads=(), now=None, allow_pruned=False, with_entries=False):
    """Check a log and return what it says. Refused if it is not whole, in order and signed.

    paths: segment files in order, or one directory. keys: the ML-DSA-65 public keys the reader trusts as this
    verifier's (a log is one key's; a verifier whose identity was made again starts another log, in a new segment).
    anchors: batch records (bytes) kept from an earlier look at the log; each must be in it, byte for byte. heads:
    (batch number, SHA-256 hex of that record), the same from a journal line. now: with it a log whose last batch
    promised the next one before now is reported "stale": True (the verifier stopped, or the end was cut off); the
    caller decides what that means. allow_pruned: accept a log whose first batch is not number 1 (older segments
    archived), and say so.

    Returns {"logs": [{"log", "kid", "first_batch", "last_batch", "first_entry", "entries", "from", "to", "head",
    "due"}], "pruned", "stale", "time_goes_back": [batch numbers], "entries": [...] with with_entries}."""
    if isinstance(paths, str):
        paths = [p for _, p in segments(paths)] if os.path.isdir(paths) else [paths]
    by_kid = {cose.key_thumbprint(pk): pk for pk in keys}
    logs, seen, entries, back = [], {}, [], []
    cur = last = None
    pruned = False
    for path in paths:
        with open(path, "rb") as f:
            data = f.read()
        name = os.path.basename(path)
        try:
            recs = split(data)
        except _Torn as t:
            raise Refused("%s ends in the middle of a record (at byte %d of %d)" % (name, t.offset, len(data))) from None
        for n, (offset, raw) in enumerate(recs):
            where = "%s, record at byte %d" % (name, offset)
            try:
                kid = open_batch(raw).kid
                if kid not in by_kid:
                    raise Refused("signed by a key that is not trusted here (kid %s...)" % kid.hex()[:16])
                b = open_batch(raw, by_kid[kid])
            except (Refused, cose.Refused) as e:
                raise Refused("%s: %s" % (where, e)) from None
            if last is None or b.log != last.log:
                if last is not None and (n != 0 or b.batch != 1):
                    raise Refused("%s: a batch of another log (%s) in the middle of log %s" % (
                        where, b.log.hex(), last.log.hex()))
                if b.batch != 1:
                    if not allow_pruned:
                        raise Refused("%s: the log begins at batch %d: what came before is missing" % (where, b.batch))
                    pruned = True
                elif b.prev != GENESIS or b.first != 1 or not b.entries or b.entries[0]["event"] != "log-start":
                    raise Refused("%s: batch 1 does not begin a log" % where)
                else:
                    # a log that says it follows another one (another key's, or a damaged segment): that one must
                    # be here and end where this one says, or what came before is missing
                    d = b.entries[0]["details"]
                    follows = "after_log" in d or "damaged_segment" in d
                    joined = bool(logs) and (d.get("after_log"), d.get("after_batch"), d.get("after_head")) == (
                        logs[-1]["log"], logs[-1]["last_batch"], logs[-1]["head"])
                    if (follows or logs) and not joined:
                        if not allow_pruned:
                            raise Refused("%s: this log follows %s, which is not here whole" % (where, (
                                "log %s" % d["after_log"].hex() if isinstance(d.get("after_log"), bytes) else
                                "a damaged segment" if "damaged_segment" in d else "another log")))
                        pruned = True
                if b.log in {lg["log"] for lg in logs}:
                    raise Refused("%s: log %s begins twice" % (where, b.log.hex()))
                cur = {"log": b.log, "kid": b.kid, "first_batch": b.batch, "first_entry": b.first, "from": b.time}
                logs.append(cur)
            else:
                if b.kid != last.kid:
                    raise Refused("%s: batch %d is signed by another key than the log's" % (where, b.batch))
                if b.batch != last.batch + 1:
                    raise Refused("%s: batch %d follows batch %d: %s" % (where, b.batch, last.batch, (
                        "batches are missing" if b.batch > last.batch + 1 else "out of order, or repeated")))
                if b.prev != last.head:
                    raise Refused("%s: batch %d does not continue the batch before it (prev is not its hash)"
                                  % (where, b.batch))
                if b.first != last.next_entry:
                    raise Refused("%s: batch %d begins at entry %d, the one before ended at %d" % (
                        where, b.batch, b.first, last.next_entry - 1))
                if b.time < last.time:
                    back.append(b.batch)        # a clock set back is not a broken log; the report says where
            cur.update(last_batch=b.batch, to=b.time, head=b.head, due=b.due,
                       entries=b.next_entry - cur["first_entry"])
            seen[(b.log, b.batch)] = b.head
            if with_entries:
                entries += [dict(e, entry=b.first + i, batch=b.batch, log=b.log.hex(), signed=b.time)
                            for i, e in enumerate(b.entries)]
            last = b
    if not logs:
        raise Refused("no batch record")
    for raw in anchors:
        try:
            kid = open_batch(raw).kid
            if kid not in by_kid:
                raise Refused("signed by a key that is not trusted here (kid %s...)" % kid.hex()[:16])
            a = open_batch(raw, by_kid[kid])
        except (Refused, cose.Refused) as e:
            raise Refused("the anchor is not a batch record of this verifier: %s" % e) from None
        _anchored(logs, seen, a.log, a.batch, a.head)
    for batch, digest in heads:
        try:
            batch, digest = int(batch), bytes.fromhex(digest)
        except (TypeError, ValueError):
            raise Refused("a head is not BATCH:SHA-256 in hex") from None
        _anchored(logs, seen, None, batch, digest)
    for lg in logs:
        lg["log"], lg["kid"], lg["head"] = lg["log"].hex(), lg["kid"].hex(), lg["head"].hex()
    report = {"logs": logs, "pruned": pruned, "time_goes_back": back,
              "stale": bool(now is not None and last.due is not None and now > last.due)}
    if with_entries:
        report["entries"] = entries
    return report


def _anchored(logs, seen, log, batch, head):
    """Refused unless the log holds batch number batch with exactly this hash (of log, or of the last log if None)."""
    if log is None:
        log = logs[-1]["log"]
    mine = [lg for lg in logs if lg["log"] == log]
    if not mine:
        raise Refused("the anchor is batch %d of log %s, which is not here: the log was replaced" % (batch, log.hex()))
    if batch > mine[0]["last_batch"]:
        raise Refused("the log ends at batch %d and the anchor is batch %d: the end was cut off" % (
            mine[0]["last_batch"], batch))
    if batch < mine[0]["first_batch"]:
        raise Refused("the anchor is batch %d, before the first batch here (%d): it cannot be compared" % (
            batch, mine[0]["first_batch"]))
    if seen[(log, batch)] != head:
        raise Refused("batch %d of the log is not the anchored record: the log was written again from there or before"
                      % batch)


# ---- writing --------------------------------------------------------------------------------------------------------

class Log:
    """The writer. add() queues an entry in memory; flush() signs what is queued as one batch (or several, if it is
    much) and appends it, flushed to disk before it returns.

    The writer continues the log from its last record, which it checks (a batch record, signed by this key). It
    does not read the whole log each time: damage further back is found by whoever checks the log.

    directory: where the segments live (made 0700). pk: the verifier's public key. load_sk: called when a batch is
    about to be signed, and only then, so a verifier with nothing to log never opens its key. checkpoint_s: a batch
    is written at least this often even with nothing to say, and every batch promises the next one within
    checkpoint_s + grace_s ("due"); 0: no promise, no empty batches. min_interval_s: entries wait in memory until
    this long after the last batch (a bound on what a flapping endpoint can make the verifier write). segment_bytes:
    a new segment file is begun when the current one would grow past it.

    Several processes may write one log (the loop, and an enrolment command beside it): every append is made under a
    lock on the directory, on the log as it is on disk at that moment."""

    def __init__(self, directory, pk, load_sk, checkpoint_s=3600, grace_s=120, min_interval_s=0,
                 segment_bytes=1 << 20):
        self.dir, self.pk, self._load_sk = directory, bytes(pk), load_sk
        self.kid = cose.key_thumbprint(self.pk)
        self.checkpoint_s, self.grace_s = int(checkpoint_s), int(grace_s)
        self.min_interval_s, self.segment_bytes = int(min_interval_s), int(segment_bytes)
        self.pending = []
        self.dropped, self.dropped_from, self.dropped_to = 0, None, None
        self._seen = None           # (segment number, size) of the tail this object last saw
        self._tail = None           # the log's last Batch, or None before the first
        self._log_id = None
        self._segment = 0           # number of the segment the next record goes to
        self._size = 0
        self._last_write = None

    def add(self, event, subject=None, details=None, now=None):
        """Queue one entry. Never raises for what the details contain."""
        try:
            e = entry(event, subject, details, now)
        except Exception as err:  # noqa: BLE001 - an entry that cannot be made is still an entry
            e = entry("unwritable", None, {"event": repr(event)[:40], "error": "%s: %s" % (type(err).__name__, err)})
        if len(self.pending) >= MAX_PENDING:
            self.dropped += 1
            self.dropped_from = self.dropped_from if self.dropped_from is not None else e[E_TIME]
            self.dropped_to = e[E_TIME]
            return
        self.pending.append(e)

    # -- the log on disk --

    def _lock(self):
        os.makedirs(self.dir, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(self.dir, LOCK), os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        return fd

    def _begin_log(self, why, after=None, damaged=None):
        """Nothing usable to continue: the next batch is batch 1 of a new log, in a new segment, and its first entry
        says why. after: the last batch of the log before, if that one is whole (another key's); damaged: the number
        of a segment that is not."""
        d = {"why": why, "verifier_key_sha256": hashlib.sha256(self.pk).digest()}
        if after is not None:
            d.update(after_log=after.log, after_batch=after.batch, after_head=after.head)
        if damaged is not None:
            d["damaged_segment"] = damaged
        self.pending = [e for e in self.pending if e[E_EVENT] != "log-start"]   # one, however often this is found
        self.pending.insert(0, entry("log-start", None, d))
        self._tail, self._log_id = None, secrets.token_bytes(LOG_ID_LEN)

    def _sync(self):
        """Make this object agree with the directory: find the last batch record, cut off a torn end."""
        segs = segments(self.dir)
        while segs:
            num, path = segs[-1]
            size = os.path.getsize(path)
            if size == 0 and len(segs) > 1:
                segs.pop()                      # begun and never written: the log ends in the segment before
                continue
            if self._seen == (num, size) and self._segment == num:
                return                          # nobody else wrote since this object did
            with open(path, "rb") as f:
                data = f.read()
            try:
                recs = split(data)
            except _Torn as t:
                with open(path, "r+b") as f:    # the bytes of a record that was never finished, so never signed
                    f.truncate(t.offset)
                    os.fsync(f.fileno())
                self.pending.insert(0, entry("recovered", None, {
                    "segment": num, "dropped_bytes": len(data) - t.offset,
                    "why": "the segment ended in the middle of a record"}))
                continue
            except Refused as e:
                self._segment, self._size = num + 1, 0
                return self._begin_log("segment %d is damaged: %s" % (num, e), damaged=num)
            self._segment, self._size = num, size
            if not recs:
                self._segment = num             # one empty segment and nothing else
                break
            try:
                tail = open_batch(recs[-1][1])
                if tail.kid != self.kid:
                    self._segment, self._size = num + 1, 0
                    return self._begin_log("the log before this one is signed by another key", tail)
                self._tail = open_batch(recs[-1][1], self.pk)
            except (Refused, cose.Refused) as e:
                self._segment, self._size = num + 1, 0
                return self._begin_log("segment %d is damaged: %s" % (num, e), damaged=num)
            self._log_id = self._tail.log
            self._seen = (num, size)
            return
        if not segs:
            self._segment, self._size = 1, 0
        self._begin_log("no log in this directory yet")

    def _append(self, rec):
        if self._size and self._size + len(rec) > self.segment_bytes:
            self._segment, self._size = self._segment + 1, 0
        path = os.path.join(self.dir, "audit-%06d.cbor" % self._segment)
        new = not os.path.exists(path)
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            before = os.fstat(fd).st_size
            n = os.write(fd, rec)
            if n != len(rec):
                os.ftruncate(fd, before)        # half a record is not left for the next writer to find
                raise OSError("short write to %s (%d of %d bytes)" % (path, n, len(rec)))
            os.fsync(fd)
        finally:
            os.close(fd)
        if new:
            dfd = os.open(self.dir, os.O_RDONLY)
            try:
                os.fsync(dfd)
            finally:
                os.close(dfd)
        self._size = before + len(rec)
        self._seen = (self._segment, self._size)

    def flush(self, now=None, promise=True, force=False, last=False):
        """Sign and append what is queued; returns the batches written, as [Batch] (empty: nothing was due).

        promise: this writer will write again (the loop): the batch says by when ("due"), and a batch is written
        when the last promise is about to lapse even with nothing queued. Without it (one run, a command) the last
        promise in the log is repeated unchanged, and nothing is written with nothing queued. last: the writer that
        promised ends its log here; the batch promises nothing. force: do not wait for min_interval_s. Raises
        OSError, RuntimeError or ValueError if the key cannot be used or the directory written; what was queued
        stays queued."""
        now = int(time.time() if now is None else now)
        promise = promise and not last
        heartbeat = promise and self.checkpoint_s > 0
        fd = self._lock()
        try:
            queued = bool(self.pending or self.dropped)     # before _sync, which may add what it found on the way
            self._sync()
            tail = self._tail
            lapsing = heartbeat and (tail is None or tail.due is None or now >= tail.due - self.grace_s)
            waiting = (not force and self.min_interval_s > 0 and self._last_write is not None
                       and 0 <= now - self._last_write < self.min_interval_s)
            if not (lapsing or (queued and not waiting)):
                return []
            if self.dropped:
                self.pending.append(entry("gap", None, {"dropped": self.dropped, "from": self.dropped_from,
                                                        "to": self.dropped_to,
                                                        "why": "more entries than memory holds while the log could "
                                                               "not be written"}, now))
                self.dropped = 0
            sk = self._load_sk()
            written = []
            while True:
                take, size = [], 0
                for e in self.pending:
                    n = len(cbor.dumps(e, sort=True))
                    if take and (size + n > MAX_BATCH_PAYLOAD - 256 or len(take) >= MAX_ENTRIES):
                        break
                    take.append(e)
                    size += n
                tail = self._tail
                if heartbeat:
                    due = now + self.checkpoint_s + self.grace_s
                else:
                    # another writer's promise stands as it was; one that has lapsed is not made again
                    due = tail.due if tail is not None and tail.due is not None and tail.due > now and not last \
                        else None
                rec = make_batch(sk, self.pk, self._log_id, tail.batch + 1 if tail else 1,
                                 tail.head if tail else GENESIS, tail.next_entry if tail else 1, take, now, due)
                self._append(rec)
                self._tail = open_batch(rec)
                del self.pending[:len(take)]
                written.append(self._tail)
                if not self.pending:
                    break
            self._last_write = now
            return written
        finally:
            os.close(fd)                        # closing the descriptor releases the lock

    def head(self):
        """The log's last batch record as it is on disk now (a Batch; its .raw is an anchor), or None."""
        fd = self._lock()
        try:
            held = list(self.pending)
            self._sync()
            self.pending = held                 # looking is not writing: a "log-start" for a log never begun is dropped
            return self._tail
        finally:
            os.close(fd)
