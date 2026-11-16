#!/usr/bin/env python3
"""Run the NIST ACVP ML-KEM-768 / ML-DSA-65 vectors (same groups liboqs' test uses) against the
Aegis KAT core (endpoints/stm32h573/kat-ns), either the PC harness or the STM32 over its console.

  acvp_device.py pc  PATH_TO_kat_pc
  acvp_device.py stm32
Prints a JSON summary; exit 0 only if every case matches.

ML-DSA requests follow FIPS 204: internal interface signs M' = message (or the given mu when
externalMu); external "pure" uses M' = 0 || |ctx| || ctx || M; external "preHash" uses
M' = 1 || |ctx| || ctx || OID(hash) || PH(M). Deterministic groups use rnd = 0^32.
"""
import collections
import hashlib
import json
import os
import subprocess
import sys
import time

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
VEC = os.path.join(REPO, "vectors", "acvp")
OID_ARC = {"SHA2-256": 1, "SHA2-384": 2, "SHA2-512": 3, "SHA2-224": 4, "SHA2-512/224": 5, "SHA2-512/256": 6,
           "SHA3-224": 7, "SHA3-256": 8, "SHA3-384": 9, "SHA3-512": 10, "SHAKE-128": 11, "SHAKE-256": 12}


def ph(alg, m):
    if alg == "SHAKE-128":
        return hashlib.shake_128(m).digest(32)
    if alg == "SHAKE-256":
        return hashlib.shake_256(m).digest(64)
    name = {"SHA2-224": "sha224", "SHA2-256": "sha256", "SHA2-384": "sha384", "SHA2-512": "sha512",
            "SHA2-512/224": "sha512_224", "SHA2-512/256": "sha512_256", "SHA3-224": "sha3_224",
            "SHA3-256": "sha3_256", "SHA3-384": "sha3_384", "SHA3-512": "sha3_512"}[alg]
    return hashlib.new(name, m).digest()


def load(name):
    with open(os.path.join(VEC, name + "-internalProjection.json")) as f:
        return json.load(f)


def pre_and_msg(g, t):
    iface, prehash = g["signatureInterface"], g.get("preHash", "none")
    if iface == "internal":
        if g.get("externalMu"):
            return b"", bytes.fromhex(t["mu"]), 1
        return b"", bytes.fromhex(t["message"]), 0
    ctx = bytes.fromhex(t.get("context", ""))
    msg = bytes.fromhex(t["message"])
    if prehash == "pure":
        return bytes([0, len(ctx)]) + ctx, msg, 0
    oid = bytes([0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, OID_ARC[t["hashAlg"]]])
    return bytes([1, len(ctx)]) + ctx + oid, ph(t["hashAlg"], msg), 0


def cases():
    h = lambda b: b.hex() if b else "-"  # noqa: E731
    for g in load("ML-KEM-keyGen-FIPS203")["testGroups"]:
        if g["parameterSet"] == "ML-KEM-768":
            for t in g["tests"]:
                yield "kem_keyGen", "KEMKG " + t["d"] + t["z"], ["OK", t["ek"].lower(), t["dk"].lower()]
    for g in load("ML-KEM-encapDecap-FIPS203")["testGroups"]:
        if g["parameterSet"] != "ML-KEM-768":
            continue
        for t in g["tests"]:
            if g["function"] == "encapsulation":
                yield "kem_encaps", "KEMENC %s %s" % (t["ek"], t["m"]), ["OK", t["c"].lower(), t["k"].lower()]
            elif g["function"] == "decapsulation":
                yield "kem_decaps", "KEMDEC %s %s" % (t["dk"], t["c"]), ["OK", t["k"].lower()]
    for g in load("ML-DSA-keyGen-FIPS204")["testGroups"]:
        if g["parameterSet"] == "ML-DSA-65":
            for t in g["tests"]:
                yield "dsa_keyGen", "DSAKG " + t["seed"], ["OK", t["pk"].lower(), t["sk"].lower()]
    for g in load("ML-DSA-sigGen-FIPS204")["testGroups"]:
        if g["parameterSet"] != "ML-DSA-65":
            continue
        for t in g["tests"]:
            pre, m, ext = pre_and_msg(g, t)
            rnd = "00" * 32 if g["deterministic"] else t["rnd"]
            name = "dsa_sigGen_%s_%s%s" % (g["signatureInterface"], g.get("preHash", "none"),
                                            "_extmu" if g.get("externalMu") else "")
            yield name, "DSASIG %s %s %02x %s %s" % (t["sk"], rnd, ext, h(pre), h(m)), ["OK", t["signature"].lower()]
    for g in load("ML-DSA-sigVer-FIPS204")["testGroups"]:
        if g["parameterSet"] != "ML-DSA-65":
            continue
        for t in g["tests"]:
            pre, m, ext = pre_and_msg(g, t)
            name = "dsa_sigVer_%s_%s%s" % (g["signatureInterface"], g.get("preHash", "none"),
                                            "_extmu" if g.get("externalMu") else "")
            yield name, "DSAVER %s %s %02x %s %s" % (t["pk"], t["signature"], ext, h(pre), h(m)), \
                ["OK", "1" if t["testPassed"] else "0"]


class PcTarget:
    def __init__(self, exe):
        self.p = subprocess.Popen([exe], stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)

    def ask(self, line):
        self.p.stdin.write(line + "\n")
        self.p.stdin.flush()
        return self.p.stdout.readline().strip()


class Stm32Target:
    def __init__(self):
        sys.path.insert(0, os.path.join(REPO, "host"))
        import stm32_console as sc
        self.con = sc.Console()
        self.con.read_for(0.3)

    def ask(self, line):
        self.con.buf = b""
        self.con.send(line)
        end = time.time() + 60
        while time.time() < end:
            self.con.read_for(0.02)
            while b"\n" in self.con.buf:
                ln, self.con.buf = self.con.buf.split(b"\n", 1)
                ln = ln.strip().decode(errors="replace")
                if ln.startswith(("OK", "ERR")):
                    return ln
        return "TIMEOUT"


def main():
    target = PcTarget(sys.argv[2]) if sys.argv[1] == "pc" else Stm32Target()
    res = collections.Counter()
    first = []
    t0 = time.time()
    for name, req, expect in cases():
        got = target.ask(req).split()
        ok = got == expect
        res[(name, "pass" if ok else "FAIL")] += 1
        if not ok and len(first) < 5:
            first.append({"test": name, "got": " ".join(got)[:60], "expected": " ".join(expect)[:60]})
    summary = {"target": sys.argv[1], "cases": sum(res.values()),
               "failed": sum(v for (n, s), v in res.items() if s == "FAIL"),
               "by_test": {"%s %s" % k: v for k, v in sorted(res.items())}, "first_failures": first,
               "elapsed_s": round(time.time() - t0, 1)}
    print(json.dumps(summary, indent=1))
    return 1 if summary["failed"] else 0


if __name__ == "__main__":
    sys.exit(main())
