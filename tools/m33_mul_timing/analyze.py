#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
import json, sys, statistics
CLS = ["0x0", "1x1", "7Fx7F", "FFFFxFFFF", "7FFFFFFFx7FFFFFFF", "80000000x80000000", "FFFFFFFFxFFFFFFFF",
       "rand x rand", "rand x rand +acc", "1xFFFFFFFF", "FFFFFFFFx1", "7Fx80000000", "80000000x7F",
       "FFFFx7FFFFFFFF", "7FFFFFFFxFFFF", "0xFFFFFFFF", "FFFFFFFFx0", "mldsa q-1 x zeta", "mldsa t x -q",
       "mldsa 1 x -q", "mldsa neg x coeff", "mlkem -1665x1665", "mlkem 3328x-3329", "mlkem compress", "2^16x2^16",
       "int16 ext +acc"]
reps = [json.load(open(f)) for f in sys.argv[1:]]
N = 128
print("files:", ", ".join(sys.argv[1:]))
print("state:", {k: reps[0].get(k) for k in ("halted_in_secure_CDS", "secure_debug_enabled_S_SDE", "run_DSCSR", "run_MPU_CTRL_cur", "run_SAU_CTRL_cur", "cpuid_seen", "dwt_ctrl_seen", "demcr_seen")})
blocks = list(reps[0]["blocks"])
def allv(b, c):
    return [v for r in reps for v in r["blocks"][b][c]]
emp = [v for c in range(len(CLS)) for v in allv("EMPTY", c)]
print(f"EMPTY overhead: min {min(emp)} max {max(emp)}")
ov = min(emp)
print(f"\nTotal cycles for {N} instructions (min/max over {len(reps)} runs x 8 reps), overhead {ov} subtracted")
hdr = "class".ljust(20) + "".join(b.ljust(11) for b in blocks if b != "EMPTY")
print(hdr)
summary = {}
for c, name in enumerate(CLS):
    row = name.ljust(20)
    for b in blocks:
        if b == "EMPTY":
            continue
        v = allv(b, c)
        lo, hi = min(v) - ov, max(v) - ov
        summary.setdefault(b, []).extend([lo, hi])
        row += (f"{lo}" if lo == hi else f"{lo}-{hi}").ljust(11)
    print(row)
print("\nPer block across ALL operand classes (min..max total, cycles/instr):")
for b, v in summary.items():
    print(f"  {b:8s} {min(v)}..{max(v)}  -> {min(v)/N:.3f}..{max(v)/N:.3f} cyc/instr  {'CONSTANT' if min(v)==max(v) else 'VARIES'}")
mc = [r["mont_cyc"] for r in reps]
MN = ["zeros", "small", "+-(q-1)", "rand coeff x coeff", "rand int24 x coeff", "near 2^31*q bound", "0 x rand", "rand32 x rand32"]
print("\nmld_montgomery_reduce((int64)a*b) per call (incl. call + 2 CYCCNT reads):")
allm = []
for c, n in enumerate(MN):
    v = [x for m in mc for x in m[c]]
    allm += v
    print(f"  {n:22s} min {min(v)} max {max(v)}")
e = [x for r in reps for x in r["mont_empty"]]
print(f"  empty call            min {min(e)} max {max(e)}")
print(f"  ALL classes           min {min(allm)} max {max(allm)} -> {'CONSTANT' if min(allm)==max(allm) else 'VARIES'}")
# correctness spot check of montgomery outputs
import random
Q = 8380417
bad = 0
for r in reps:
    for c in range(8):
        pass
def mont_ref(a, b):
    x = a * b
    t = ((x & 0xFFFFFFFF) * 58728449) & 0xFFFFFFFF
    if t >> 31: t -= 1 << 32
    return (x - t * Q) >> 32
for r in reps:
    A = [v - (1 << 32) if v >> 31 else v for v in r["mont_a"]]
    B = [v - (1 << 32) if v >> 31 else v for v in r["mont_b"]]
    for i in range(len(A)):
        if mont_ref(A[i], B[i]) != r["mont_out"][i % 8][i // 8]:
            bad += 1
print(f"  montgomery outputs checked against a Python reference: {bad} mismatches")
PW = ["zeros", "+-(q-1)", "random coeffs", "small |x|<8", "rand int32 x coeff"]
print("\npointwise_montgomery over 256 coefficients (min/max over runs x 4 reps):")
allp = []
for c, n in enumerate(PW):
    v = [x for r in reps for x in r["pw_cyc"][c]]
    allp += v
    print(f"  {n:20s} min {min(v)} max {max(v)}")
print(f"  ALL                  min {min(allp)} max {max(allp)} -> {'CONSTANT' if min(allp)==max(allp) else 'VARIES'}")
