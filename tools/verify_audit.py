#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check an Aegis verifier's audit log, or a signed fleet policy, WITHOUT any Aegis code.

This file imports nothing from the Aegis repository. Like tools/verify_evidence.py it uses three third-party
packages: pycose 1.1.0 (the COSE_Sign1 decoder and the Sig_structure), cbor2 5.x, and cryptography (>= 47, with
OpenSSL >= 3.5) for ML-DSA-65, which it registers with pycose as COSE algorithm -49 (RFC 9964).

It is a second, independent reading of docs/audit-and-policy.md: the numbers and rules below were written from that
document, not from common/audit.py or common/signed_policy.py.

  verify_audit.py log PATH... --key KEY [--key KEY...] [--anchor FILE...] [--head BATCH:SHA256...]
                               [--at TIME | --no-freshness] [--allow-pruned] [--entries]
        PATH: the audit directory, or its segment files in order. Every batch record must be signed by one of the
        keys, continue the record before it (number, hash, entry count), and begin at batch 1 unless --allow-pruned.
        --anchor: a batch record kept from an earlier look at the log (fleet.py audit --out); it must be in the log,
        byte for byte: a log cut off before it, or written again, fails. --head: the same from a journal line
        ("aegis-audit: batch N ... sha256 H"). Unless --no-freshness, a log whose last batch promised the next one
        before now (or before --at, Unix time) fails as stale: the verifier stopped, or the end was cut off.
  verify_audit.py policy FILE --key KEY [--audience FLEET] [--min-version N] [--extract OUT.json]
        a signed policy: the signature, the claims, and that the policy inside is JSON with no name twice.

KEY: a file with the ML-DSA-65 public key in hex, a COSE_Key file, the verifier's identity.json, or a
policy-signers.json (every key in it).

Prints a JSON report; exit status 0 only if everything asked for verified.
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import time

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from pycose import headers
from pycose.algorithms import CoseAlgorithm
from pycose.messages import Sign1Message

ALG_ML_DSA_65 = -49         # RFC 9964
KTY_AKP = 7
HDR_TYP = 16                # RFC 9596
PK_LEN, SIG_LEN = 1952, 3309
AUDIT_TYP = "application/vnd.aegis.audit-batch+cbor"
AUDIT_FORMAT = "tag:github.com,2026:ismailalitech/aegis/audit/v1"
POLICY_TYP = "application/vnd.aegis.fleet-policy+cbor"
POLICY_FORMAT = "tag:github.com,2026:ismailalitech/aegis/policy/v1"
MAX_RECORD = 16384
MAX_POLICY = 1 << 20
SEGMENT = re.compile(r"audit-(\d{6,12})\.cbor\Z")
EVENT = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")


def mldsa_verify(key, data, signature):
    """ML-DSA-65 for COSE (RFC 9964): pure ML-DSA, empty context, over the Sig_structure."""
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(key).verify(signature, data)
        return True
    except (InvalidSignature, ValueError):
        return False


try:
    CoseAlgorithm.from_id(ALG_ML_DSA_65)    # another checker in this process (verify_evidence.py) registered it
except Exception:  # noqa: BLE001 - pycose 1.1.0 has no ML-DSA: -49 is registered through its extension point
    @CoseAlgorithm.register_attribute()
    class MlDsa65(CoseAlgorithm):
        identifier = ALG_ML_DSA_65
        fullname = "ML_DSA_65"


class Failed(Exception):
    pass


def need(cond, text):
    if not cond:
        raise Failed(text)


def thumbprint(pub):
    """COSE Key Thumbprint (RFC 9679, SHA-256) of an AKP key (RFC 9964 section 6)."""
    return hashlib.sha256(cbor2.dumps({1: KTY_AKP, 3: ALG_ML_DSA_65, -1: pub}, canonical=True)).digest()


def load_keys(path):
    """The ML-DSA-65 public keys in a file: hex, a COSE_Key, an identity.json or a policy-signers.json."""
    with open(path, "rb") as f:
        data = f.read()
    pubs = []
    try:
        text = data.decode().strip()
        if text.startswith("{"):
            doc = json.loads(text)
            found = [s.get("pk") for s in doc.get("signers", []) if isinstance(s, dict)] if "signers" in doc else \
                [doc.get("body", {}).get("pk")]
            pubs = [bytes.fromhex(p) for p in found]
        else:
            pubs = [bytes.fromhex(text)]
    except (UnicodeDecodeError, ValueError, TypeError, AttributeError):
        key = cbor2.loads(data)
        need(isinstance(key, dict) and key.get(1) == KTY_AKP and key.get(3) == ALG_ML_DSA_65,
             "%s: not an AKP COSE_Key for ML-DSA-65" % path)
        need(key.get(2) in (None, thumbprint(key.get(-1))), "%s: the key's kid is not its thumbprint" % path)
        pubs = [key.get(-1)]
    need(pubs and all(isinstance(p, bytes) and len(p) == PK_LEN for p in pubs), "%s: no ML-DSA-65 public key" % path)
    return pubs


def is_uint(v, limit=1 << 53):
    return type(v) is int and 0 <= v < limit


def open_sign1(data, keys, typ, what, limit):
    """Verify one Aegis COSE_Sign1 of that typ under the key of keys ({kid: public key}) it names; returns (claims,
    kid)."""
    need(len(data) <= limit, "%s: larger than %d bytes" % (what, limit))
    try:
        raw = cbor2.loads(data)
        msg = Sign1Message.decode(data, allow_unknown_attributes=True)
    except Exception as e:  # noqa: BLE001 - whatever pycose or cbor2 make of bytes that are not a COSE_Sign1
        raise Failed("%s: not a COSE_Sign1: %s: %s" % (what, type(e).__name__, e)) from None
    # one object, one byte string: cbor2 reads past a complete item, and accepts lengths longer than they need be
    need(cbor2.dumps(raw) == data, "%s: not in deterministic encoding, or followed by other bytes" % what)
    prot = raw.value[0]
    need(isinstance(prot, bytes) and cbor2.dumps(cbor2.loads(prot), canonical=True) == prot,
         "%s: the protected header is not in deterministic encoding" % what)
    need(getattr(msg.phdr.get(headers.Algorithm), "identifier", None) == ALG_ML_DSA_65,
         "%s: the protected algorithm is not ML-DSA-65 (-49)" % what)
    need(msg.uhdr == {}, "%s: the unprotected header is not empty" % what)
    need(set(msg.phdr) == {headers.Algorithm, headers.KID, HDR_TYP}, "%s: protected header is not {alg, kid, typ}" % what)
    need(msg.phdr[HDR_TYP] == typ, "%s: typ is not %s" % (what, typ))
    kid = msg.phdr[headers.KID]
    need(isinstance(kid, bytes) and kid in keys, "%s: signed by a key that was not given (kid %s)" % (
        what, kid.hex()[:16] if isinstance(kid, bytes) else "?"))
    need(isinstance(msg.payload, bytes), "%s: no attached payload" % what)
    need(len(msg.signature) == SIG_LEN, "%s: the signature is not %d bytes" % (what, SIG_LEN))
    tbs = msg._create_sig_structure()       # pycose's Sig_structure: ["Signature1", protected, h'', payload]
    need(mldsa_verify(keys[kid], tbs, msg.signature), "%s: the ML-DSA-65 signature does not verify" % what)
    try:
        claims = cbor2.loads(msg.payload)
    except Exception as e:  # noqa: BLE001 - signed bytes that are not CBOR
        raise Failed("%s: the payload is not CBOR: %s: %s" % (what, type(e).__name__, e)) from None
    need(isinstance(claims, dict), "%s: the payload is not a map" % what)
    need(cbor2.dumps(claims, canonical=True) == msg.payload, "%s: the payload is not in deterministic encoding" % what)
    return claims, kid


# ---- the audit log --------------------------------------------------------------------------------------------------

def records(data, name):
    """The records of one segment (a CBOR sequence, RFC 8742) as [(offset, bytes)]."""
    out, i = [], 0
    while i < len(data):
        try:
            item = cbor2.CBORDecoder(io.BytesIO(data[i:i + MAX_RECORD + 64])).decode()
            raw = cbor2.dumps(item)
        except cbor2.CBORDecodeEOF:
            raise Failed("%s ends in the middle of a record (at byte %d of %d)" % (name, i, len(data))) from None
        except Exception as e:  # noqa: BLE001
            raise Failed("%s: not a record at byte %d: %s" % (name, i, type(e).__name__)) from None
        # the record is what its re-encoding says it is: anything else is another encoding of it, or not a record
        need(data[i:i + len(raw)] == raw, "%s: the record at byte %d is not in deterministic encoding" % (name, i))
        out.append((i, raw))
        i += len(raw)
    return out


def read_batch(raw, keys, where):
    c, kid = open_sign1(raw, keys, AUDIT_TYP, where, MAX_RECORD)
    need({1, 2, 3, 4, 5, 6, 7} <= set(c) <= {1, 2, 3, 4, 5, 6, 7, 8}, "%s: not a batch {1..7[, 8]}" % where)
    need(c[1] == AUDIT_FORMAT, "%s: the format is not %s" % (where, AUDIT_FORMAT))
    need(isinstance(c[2], bytes) and len(c[2]) == 16 and isinstance(c[4], bytes) and len(c[4]) == 32,
         "%s: log is not 16 bytes, or prev not 32" % where)
    need(is_uint(c[3]) and c[3] >= 1 and is_uint(c[6]) and c[6] >= 1 and is_uint(c[5], 1 << 40)
         and (8 not in c or is_uint(c[8], 1 << 40)), "%s: batch, first, time or due is not a number in range" % where)
    need(isinstance(c[7], list) and len(c[7]) <= 256, "%s: entries is not a list of at most 256" % where)
    entries = []
    for e in c[7]:
        need(isinstance(e, dict) and {1, 2} <= set(e) <= {1, 2, 3, 4}, "%s: an entry is not {1, 2[, 3][, 4]}" % where)
        need(is_uint(e[1], 1 << 40) and isinstance(e[2], str) and EVENT.match(e[2]) is not None,
             "%s: an entry's time or event is not one" % where)
        need(3 not in e or (isinstance(e[3], str) and len(e[3]) <= 64), "%s: an entry's subject is not a short text" % where)
        need(4 not in e or (isinstance(e[4], dict) and all(isinstance(k, str) for k in e[4])),
             "%s: an entry's details are not a map with text keys" % where)
        entries.append({"time": e[1], "event": e[2], "subject": e.get(3), "details": e.get(4) or {}})
    return {"kid": kid, "log": c[2], "batch": c[3], "prev": c[4], "time": c[5], "first": c[6], "entries": entries,
            "due": c.get(8), "head": hashlib.sha256(raw).digest()}


def printable(v):
    if isinstance(v, bytes):
        return v.hex()
    if isinstance(v, dict):
        return {str(k): printable(x) for k, x in v.items()}
    if isinstance(v, (list, tuple)):
        return [printable(x) for x in v]
    return v if isinstance(v, (str, int, bool)) or v is None else repr(v)


def check_log(paths, pubs, anchors=(), heads=(), now=None, allow_pruned=False, with_entries=False):
    if len(paths) == 1 and os.path.isdir(paths[0]):
        found = sorted((int(SEGMENT.match(n).group(1)), n) for n in os.listdir(paths[0]) if SEGMENT.match(n))
        paths = [os.path.join(paths[0], n) for _, n in found]
    keys = {thumbprint(p): p for p in pubs}
    logs, seen, entries, back = [], {}, [], []
    cur = last = None
    pruned = False
    for path in paths:
        name = os.path.basename(path)
        with open(path, "rb") as f:
            data = f.read()
        for n, (offset, raw) in enumerate(records(data, name)):
            where = "%s, record at byte %d" % (name, offset)
            b = read_batch(raw, keys, where)
            if last is None or b["log"] != last["log"]:
                need(last is None or (n == 0 and b["batch"] == 1),
                     "%s: a batch of another log in the middle of log %s" % (where, last and last["log"].hex()))
                if b["batch"] != 1:
                    need(allow_pruned, "%s: the log begins at batch %d: what came before is missing" % (where, b["batch"]))
                    pruned = True
                else:
                    need(b["prev"] == bytes(32) and b["first"] == 1 and b["entries"]
                         and b["entries"][0]["event"] == "log-start", "%s: batch 1 does not begin a log" % where)
                    # a log that says it follows another (another key's, or a damaged segment) needs that one here,
                    # ending where it says; and a log after another one must say that it follows it
                    d = b["entries"][0]["details"]
                    joined = bool(logs) and (d.get("after_log"), d.get("after_batch"), d.get("after_head")) == (
                        logs[-1]["log"], logs[-1]["last_batch"], logs[-1]["head"])
                    if ("after_log" in d or "damaged_segment" in d or logs) and not joined:
                        need(allow_pruned, "%s: this log follows another one that is not here whole" % where)
                        pruned = True
                need(b["log"] not in [lg["log"] for lg in logs], "%s: log %s begins twice" % (where, b["log"].hex()))
                cur = {"log": b["log"], "kid": b["kid"], "first_batch": b["batch"], "first_entry": b["first"],
                       "from": b["time"]}
                logs.append(cur)
            else:
                need(b["kid"] == last["kid"], "%s: batch %d is signed by another key than the log's" % (where, b["batch"]))
                need(b["batch"] == last["batch"] + 1, "%s: batch %d follows batch %d: %s" % (
                    where, b["batch"], last["batch"],
                    "batches are missing" if b["batch"] > last["batch"] + 1 else "out of order, or repeated"))
                need(b["prev"] == last["head"], "%s: batch %d does not continue the batch before it" % (where, b["batch"]))
                need(b["first"] == last["first"] + len(last["entries"]),
                     "%s: batch %d does not begin at the entry after the last one" % (where, b["batch"]))
                if b["time"] < last["time"]:
                    back.append(b["batch"])
            cur.update(last_batch=b["batch"], to=b["time"], head=b["head"], due=b["due"],
                       entries=b["first"] + len(b["entries"]) - cur["first_entry"])
            seen[(b["log"], b["batch"])] = b["head"]
            if with_entries:
                entries += [dict(e, entry=b["first"] + i, batch=b["batch"], log=b["log"], signed=b["time"])
                            for i, e in enumerate(b["entries"])]
            last = b
    need(logs, "no batch record")

    def anchored(log, batch, head, what):
        log = logs[-1]["log"] if log is None else log
        mine = [lg for lg in logs if lg["log"] == log]
        need(mine, "%s is batch %d of log %s, which is not here: the log was replaced" % (what, batch, log.hex()))
        need(batch <= mine[0]["last_batch"], "the log ends at batch %d and %s is batch %d: the end was cut off" % (
            mine[0]["last_batch"], what, batch))
        need(batch >= mine[0]["first_batch"], "%s is batch %d, before the first batch here: it cannot be compared" % (
            what, batch))
        need(seen[(log, batch)] == head, "batch %d of the log is not %s: the log was written again from there or "
                                         "before" % (batch, what))
    checked = []
    for path in anchors:
        with open(path, "rb") as f:
            a = read_batch(f.read(), keys, "the anchor %s" % os.path.basename(path))
        anchored(a["log"], a["batch"], a["head"], "the anchor")
        checked.append({"anchor": os.path.basename(path), "batch": a["batch"], "log": a["log"].hex()})
    for text in heads:
        batch, _, digest = text.partition(":")
        try:
            batch, digest = int(batch), bytes.fromhex(digest)
        except ValueError:
            raise Failed("--head is BATCH:SHA256, not %r" % text[:40]) from None
        anchored(None, batch, digest, "the given head")
        checked.append({"head": digest.hex(), "batch": batch})
    report = {"logs": printable(logs), "pruned": pruned, "anchors": checked, "time_goes_back_at_batch": back,
              "freshness": "not checked"}
    if now is not None:
        due = last["due"]
        need(due is None or now <= due, "stale: the last batch (%d, signed at %d) promised the next one by %d and it "
                                        "is %d: the verifier stopped, or the end of the log was cut off" % (
                                            last["batch"], last["time"], due or 0, now))
        report["freshness"] = ("the last batch promises no next one (one run, or a stopped log): how long ago the "
                               "log ended is not known from it" if due is None else
                               "the next batch is promised by %d" % due)
    if with_entries:
        report["entries"] = printable(entries)
    return report


# ---- the signed policy ----------------------------------------------------------------------------------------------

def no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        need(k not in out, "policy: the JSON names %r twice in one object" % (k[:40],))
        out[k] = v
    return out


def check_policy(data, pubs, audience=None, min_version=None):
    c, kid = open_sign1(data, {thumbprint(p): p for p in pubs}, POLICY_TYP, "policy", MAX_POLICY)
    need({1, 2, 3, 4, 5} <= set(c) <= {1, 2, 3, 4, 5, 6}, "policy: not {1..5[, 6]}")
    need(c[1] == POLICY_FORMAT, "policy: the format is not %s" % POLICY_FORMAT)
    need(is_uint(c[2]) and c[2] >= 1 and is_uint(c[3], 1 << 40), "policy: the version or the time is not one")
    need(isinstance(c[4], bytes) and isinstance(c[5], str) and 0 < len(c[5]) <= 64
         and (6 not in c or (isinstance(c[6], str) and 0 < len(c[6]) <= 64)),
         "policy: the policy, the signer or the audience is not one")
    try:
        policy = json.loads(c[4].decode("utf-8"), object_pairs_hook=no_duplicates)
    except Failed:
        raise
    except Exception as e:  # noqa: BLE001
        raise Failed("policy: the policy inside is not JSON: %s" % type(e).__name__) from None
    need(isinstance(policy, dict) and isinstance(policy.get("endpoints"), list), "policy: no \"endpoints\" list inside")
    if audience is not None:
        need(c.get(6) == audience, "policy: it is for %r, not for %r" % (c.get(6), audience))
    if min_version is not None:
        need(c[2] >= min_version, "policy: version %d is older than %d" % (c[2], min_version))
    digest = hashlib.sha256(c[4]).digest()
    return {"format": c[1], "version": c[2], "issued": c[3], "signer": c[5], "audience": c.get(6),
            "signer_key_sha256": hashlib.sha256({thumbprint(p): p for p in pubs}[kid]).hexdigest(), "kid": kid.hex(),
            "signature": "ML-DSA-65 valid (COSE alg -49, RFC 9964)",
            "policy_sha256": digest.hex(), "signed_sha256": hashlib.sha256(data).hexdigest(),
            # the name an attestation result gives the policy it was reached under (ear.appraisal-policy-id)
            "policy_id": "ni:///sha-256;" + base64.urlsafe_b64encode(digest).rstrip(b"=").decode(),
            "endpoints": [e.get("name") if isinstance(e, dict) else None for e in policy["endpoints"]],
            "audit_log": policy.get("audit_log") not in (None, False), "_policy": c[4]}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("what", choices=["log", "policy"])
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--key", action="append", required=True, help="a public key the signer may have (see the text)")
    ap.add_argument("--anchor", action="append", default=[], help="log: a batch record kept earlier")
    ap.add_argument("--head", action="append", default=[], help="log: BATCH:SHA256 of a batch record, from the journal")
    ap.add_argument("--at", type=int, help="log: check freshness as of this Unix time (default: now)")
    ap.add_argument("--no-freshness", action="store_true", help="log: do not fail a log whose last promise has lapsed")
    ap.add_argument("--allow-pruned", action="store_true", help="log: accept a log that does not begin at batch 1")
    ap.add_argument("--entries", action="store_true", help="log: print every entry")
    ap.add_argument("--audience", help="policy: the fleet it must be for")
    ap.add_argument("--min-version", type=int, help="policy: the lowest version accepted")
    ap.add_argument("--extract", help="policy: write the policy inside to this file")
    a = ap.parse_args(argv)
    try:
        pubs = [p for path in a.key for p in load_keys(path)]
        if a.what == "log":
            now = None if a.no_freshness else (a.at if a.at is not None else int(time.time()))
            report = check_log(a.paths, pubs, a.anchor, a.head, now, a.allow_pruned, a.entries)
        else:
            if len(a.paths) != 1:
                ap.error("policy takes one file")
            with open(a.paths[0], "rb") as f:
                report = check_policy(f.read(), pubs, a.audience, a.min_version)
            inside = report.pop("_policy")
            if a.extract:
                with open(a.extract, "wb") as f:
                    f.write(inside)
    except Failed as e:
        print(json.dumps({"verified": False, "reason": str(e)}, indent=1))
        return 1
    except Exception as e:  # noqa: BLE001 - whatever hostile bytes provoke in this file, cbor2 or pycose: not verified
        print(json.dumps({"verified": False, "reason": "not readable: %s: %s" % (type(e).__name__, str(e)[:200])}, indent=1))
        return 1
    print(json.dumps(dict(report, verified=True), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
