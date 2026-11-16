#!/usr/bin/env python3
"""PC-side verifier for the Aegis gateway (Phase 1).

  aegis_verify.py enroll HOST [--port 7443]   trust-on-first-use enrolment
  aegis_verify.py quote  HOST [--port 7443]   challenge, verify, compare

Enrolment fetches the identity record, checks its self-signature (proof that
the gateway holds the private key), takes one quote as the reference
measurements, and stores both under host/enrolled/<dsn>.json. It is only as
trustworthy as the network at enrolment time; do it on a bench you control.

A quote is accepted only if: the ML-DSA-65 signature verifies with the
enrolled key, the nonce is the one just sent, the identity hash matches the
enrolled record, the answer arrived within the time limit, and every
measurement equals the reference (except boot_id, which changes per boot).
"""
import argparse
import json
import os
import secrets
import socket
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "common"))
import mldsa  # noqa: E402
import wire  # noqa: E402

ENROLLED = os.path.join(HERE, "enrolled")
VOLATILE = {"boot_id"}
MAX_SECONDS = 5.0


def request(host, port, obj, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as s:
        wire.send(s, obj)
        return wire.recv(s)


def check_identity(rec):
    body = rec["body"]
    if body.get("type") != "identity" or body.get("pk_alg") != "ML-DSA-65":
        return False, "not an ML-DSA-65 identity record"
    pk = bytes.fromhex(body["pk"])
    if not mldsa.verify(pk, wire.LABEL_IDENTITY, wire.canonical(body), bytes.fromhex(rec["sig"])):
        return False, "identity self-signature invalid"
    return True, "ok"


def check_quote(enrolled, resp, nonce_hex, elapsed):
    """Return (accepted, list of reasons)."""
    reasons = []
    if "error" in resp:
        return False, ["gateway error: %s" % resp["error"]]
    body = resp.get("body", {})
    pk = bytes.fromhex(enrolled["identity"]["body"]["pk"])
    sig = bytes.fromhex(resp.get("sig", ""))
    if not mldsa.verify(pk, wire.LABEL_QUOTE, wire.canonical(body), sig):
        reasons.append("signature invalid")
    if body.get("type") != "quote":
        reasons.append("not a quote")
    if body.get("nonce") != nonce_hex:
        reasons.append("nonce mismatch (stale or replayed answer)")
    if body.get("identity_sha256") != wire.digest(enrolled["identity"]["body"]):
        reasons.append("identity differs from enrolment")
    if elapsed > MAX_SECONDS:
        reasons.append("answer took %.1f s (limit %.1f s)" % (elapsed, MAX_SECONDS))
    ref = enrolled["reference"]
    got = body.get("measurements", {})
    for k in sorted(set(ref) | set(got)):
        if k in VOLATILE:
            continue
        if ref.get(k) != got.get(k):
            reasons.append("measurement changed: %s" % k)
    return not reasons, reasons


def fresh_quote(host, port):
    nonce = secrets.token_hex(32)
    t0 = time.monotonic()
    resp = request(host, port, {"type": "quote", "nonce": nonce})
    return resp, nonce, time.monotonic() - t0


def enroll(host, port, store=ENROLLED):
    rec = request(host, port, {"type": "identity"})
    ok, why = check_identity(rec)
    if not ok:
        raise SystemExit("enrolment refused: " + why)
    resp, nonce, elapsed = fresh_quote(host, port)
    tmp = {"identity": rec, "reference": {}}
    ok, reasons = check_quote(tmp, resp, nonce, elapsed)
    sig_problems = [r for r in reasons if not r.startswith("measurement changed")]
    if sig_problems:
        raise SystemExit("enrolment refused: " + "; ".join(sig_problems))
    entry = {"identity": rec, "reference": {k: v for k, v in resp["body"]["measurements"].items() if k not in VOLATILE},
             "enrolled_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": host}
    os.makedirs(store, exist_ok=True)
    path = os.path.join(store, rec["body"]["dsn"] + ".json")
    with open(path, "w") as f:
        json.dump(entry, f, indent=1)
    return path, entry


def load_enrolled(dsn=None, store=ENROLLED):
    files = sorted(f for f in os.listdir(store) if f.endswith(".json"))
    if dsn:
        files = [f for f in files if f.startswith(dsn)]
    if len(files) != 1:
        raise SystemExit("expected exactly one enrolled gateway, found %d" % len(files))
    with open(os.path.join(store, files[0])) as f:
        return json.load(f)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["enroll", "quote"])
    ap.add_argument("host")
    ap.add_argument("--port", type=int, default=7443)
    ap.add_argument("--dsn")
    a = ap.parse_args(argv)
    if a.cmd == "enroll":
        path, entry = enroll(a.host, a.port)
        print(json.dumps({"enrolled": path, "dsn": entry["identity"]["body"]["dsn"][:8] + "...",
                          "reference": entry["reference"]}, indent=1))
        return 0
    enrolled = load_enrolled(a.dsn)
    resp, nonce, elapsed = fresh_quote(a.host, a.port)
    ok, reasons = check_quote(enrolled, resp, nonce, elapsed)
    print(json.dumps({"accepted": ok, "reasons": reasons, "elapsed_s": round(elapsed, 3),
                      "sig_bytes": len(resp.get("sig", "")) // 2}, indent=1))
    return 0 if ok else 2


if __name__ == "__main__":
    sys.exit(main())
