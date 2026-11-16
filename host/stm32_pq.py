#!/usr/bin/env python3
"""PC-side checks of the STM32's post-quantum quote over the console.

  stm32_pq.py key   [--out FILE]      print/save the chip's ML-DSA-65 public key
  stm32_pq.py quote [--out FILE]      fresh challenge -> PSA token + ML-DSA-65 signature, verified
"""
import argparse
import hashlib
import json
import os
import secrets
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "common"))
import mldsa  # noqa: E402
import psa_token  # noqa: E402
import stm32_console as sc  # noqa: E402

LABEL = b"aegis-endpoint-quote-v1"


def parse_pq_line(line):
    p = line.split()
    if p[0] == "PQKEY" and len(p) == 4 and p[3] == "END":
        b = bytes.fromhex(p[2])
        assert len(b) == int(p[1])
        return b
    if p[0] == "PQTOKEN" and len(p) == 6 and p[5] == "END":
        tok, sig = bytes.fromhex(p[2]), bytes.fromhex(p[4])
        assert len(tok) == int(p[1]) and len(sig) == int(p[3])
        return tok, sig
    raise ValueError("unexpected reply %r" % line[:40])


def get_key(con):
    con.read_for(0.2)
    con.buf = b""
    con.send("PQKEY")
    return parse_pq_line(con.wait_for(b"PQKEY ", 10))


def get_quote(con, challenge):
    con.read_for(0.2)
    con.buf = b""
    t0 = time.monotonic()
    con.send("PQCHAL " + challenge.hex())
    line = con.wait_for(b"PQTOKEN ", 20)
    return parse_pq_line(line), time.monotonic() - t0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["key", "quote"])
    ap.add_argument("--out")
    ap.add_argument("--key", help="file with the enrolled public key (hex); default: ask the device")
    a = ap.parse_args()
    con = sc.Console()
    if a.cmd == "key":
        pk = get_key(con)
        rec = {"pk_alg": "ML-DSA-65", "pk": pk.hex(), "pk_sha256": hashlib.sha256(pk).hexdigest()}
        if a.out:
            json.dump(rec, open(a.out, "w"), indent=1)
        print(json.dumps({"pk_sha256": rec["pk_sha256"], "bytes": len(pk)}))
        return 0
    pk = bytes.fromhex(json.load(open(a.key))["pk"]) if a.key else get_key(con)
    ch = secrets.token_bytes(32)
    (tok, sig), el = get_quote(con, ch)
    ok_sig = mldsa.verify(pk, LABEL, tok, sig)
    claims = psa_token.parse(tok)[3]
    res = {"elapsed_s": round(el, 3), "token_bytes": len(tok), "sig_bytes": len(sig),
           "mldsa65_signature_valid": ok_sig, "challenge_matches": claims.get("challenge") == ch,
           "measurements": {c.get("measurement_type"): c.get("measurement_value", b"").hex()
                            for c in claims.get("sw_components", [])}}
    if a.out:
        json.dump(dict(res, token=tok.hex(), sig=sig.hex(), challenge=ch.hex(), pk_sha256=hashlib.sha256(pk).hexdigest()),
                  open(a.out, "w"), indent=1)
    print(json.dumps(res, indent=1))
    return 0 if ok_sig and res["challenge_matches"] else 1


if __name__ == "__main__":
    sys.exit(main())
