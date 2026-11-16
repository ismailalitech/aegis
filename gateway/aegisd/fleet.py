#!/usr/bin/env python3
"""Aegis fleet verifier (gateway side, Phase 3/4): attest endpoints, decide admission.

  fleet.py once  POLICY.json             attest every endpoint once, print verdicts
  fleet.py watch POLICY.json [--interval 30]   re-attest forever, write the state file

For each endpoint the gateway sends a fresh 32-byte challenge and expects a PSA
attestation token (COSE_Sign1, ES256) from the endpoint's TF-M secure world. An
endpoint is ADMITTED only if all of these hold:
  - it answered in time with a well-formed token,
  - the token signature verifies with the endpoint's enrolled attestation key,
  - the token's challenge is the one just sent (no replay),
  - every reported software component (SPE, NSPE, ...) matches one allowed
    measurement and signer in the policy.
Anything else, including no answer at all (a node that cannot attest), is
QUARANTINED with the reasons listed. Standard library only, plus the openssl tool.

Enforcement is a hook: if the policy names "enforce_cmd", it is run with the
endpoint name and verdict after every decision (for example to add or remove a
firewall rule). Without it the gateway only decides and records.
"""
import argparse
import json
import os
import secrets
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "common")))
import psa_token  # noqa: E402


def request_token(host, port, challenge, timeout):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"CHAL " + challenge.hex().encode() + b"\n")
        buf = b""
        while b"\n" not in buf and len(buf) < 4096:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    line = buf.split(b"\n")[0].strip().decode(errors="replace")
    parts = line.split()
    if len(parts) != 4 or parts[0] != "TOKEN" or parts[3] != "END":
        raise ValueError("no token in reply: %r" % line[:40])
    tok = bytes.fromhex(parts[2])
    if len(tok) != int(parts[1]):
        raise ValueError("token length mismatch")
    return tok


def check_components(claims, allowed):
    """allowed: list of {type, measurement_value, signer_id}. Returns list of reasons."""
    reasons = []
    comps = claims.get("sw_components", [])
    if not comps:
        return ["token has no software components"]
    for c in comps:
        typ = c.get("measurement_type")
        mv = c.get("measurement_value", b"")
        sid = c.get("signer_id", b"")
        mv = mv.hex() if isinstance(mv, bytes) else mv
        sid = sid.hex() if isinstance(sid, bytes) else sid
        ok = any(a["type"] == typ and a["measurement_value"] == mv and a.get("signer_id", sid) == sid
                 for a in allowed)
        if not ok:
            reasons.append("component %s not allowed (measurement %s...)" % (typ, mv[:12]))
    return reasons


def attest(ep, ecdsa_verify, base_dir, timeout=10.0):
    verdict = {"endpoint": ep["name"], "time": int(time.time()), "admitted": False, "reasons": []}
    challenge = secrets.token_bytes(32)
    t0 = time.monotonic()
    try:
        tok = request_token(ep["host"], int(ep["port"]), challenge, timeout)
    except (OSError, ValueError) as e:
        verdict["reasons"].append("no attestation: %s" % e)
        verdict["elapsed_s"] = round(time.monotonic() - t0, 3)
        return verdict
    verdict["elapsed_s"] = round(time.monotonic() - t0, 3)
    pem_path = ep["iak_pub_pem"]
    if not os.path.isabs(pem_path):
        pem_path = os.path.join(base_dir, pem_path)
    with open(pem_path, "rb") as f:
        pub = f.read()
    try:
        claims = psa_token.verify(tok, pub, ecdsa_verify)
    except (psa_token.TokenError, ValueError) as e:
        verdict["reasons"].append(str(e))
        return verdict
    if claims.get("challenge") != challenge:
        verdict["reasons"].append("challenge mismatch (replayed or stale token)")
    verdict["reasons"] += check_components(claims, ep.get("allowed", []))
    s = psa_token.summary(claims)
    verdict["measurements"] = {c.get("measurement_type"): c.get("measurement_value") for c in s["sw_components"]}
    verdict["instance_id"] = s.get("instance_id")
    verdict["admitted"] = not verdict["reasons"]
    return verdict


def enforce(policy, verdict):
    cmd = policy.get("enforce_cmd")
    if not cmd:
        return None
    r = subprocess.run(cmd + [verdict["endpoint"], "admit" if verdict["admitted"] else "quarantine"],
                       capture_output=True, text=True)
    return r.returncode


def run_once(policy, base_dir, ecdsa_verify):
    out = []
    for ep in policy["endpoints"]:
        v = attest(ep, ecdsa_verify, base_dir, float(policy.get("timeout_s", 10)))
        v["enforce_rc"] = enforce(policy, v)
        out.append(v)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Aegis fleet verifier")
    ap.add_argument("cmd", choices=["once", "watch"])
    ap.add_argument("policy")
    ap.add_argument("--interval", type=float, default=30)
    ap.add_argument("--state", default="/var/lib/aegis/fleet-state.json")
    ap.add_argument("--verifier", choices=["openssl", "cryptography"], default="openssl")
    a = ap.parse_args(argv)
    with open(a.policy) as f:
        policy = json.load(f)
    base = os.path.dirname(os.path.abspath(a.policy))
    ev = psa_token.verify_with_openssl_cli if a.verifier == "openssl" else psa_token.verify_with_cryptography
    if a.cmd == "once":
        print(json.dumps(run_once(policy, base, ev), indent=1))
        return 0
    while True:
        res = run_once(policy, base, ev)
        tmp = a.state + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"updated": int(time.time()), "verdicts": res}, f, indent=1)
        os.replace(tmp, a.state)
        for v in res:
            print("%s %s %s %s" % (time.strftime("%H:%M:%S"), v["endpoint"],
                                   "ADMITTED" if v["admitted"] else "QUARANTINED", "; ".join(v["reasons"])),
                  flush=True)
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
