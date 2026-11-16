# SPDX-License-Identifier: Apache-2.0
"""Bit-exact model of the aegis_ntt datapath and schedule.

What this file checks (run it directly):
  1. Barrett reduction exactly as built in rtl/aegis_modmul.v, for both moduli,
     verified for EVERY product x = a*b with a, b in [0, q):
       q1 = x >> (n-1);  q3 = (q1 * mu) >> (n+1);  r = (x - q3*q) mod 2^(n+2)
     with n = bit length of q, mu = floor(2^(2n) / q) (HAC Algorithm 14.42,
     base 2). HAC Fact 14.43 gives 0 <= x - q3*q < 3q for x < 2^(2n). The check
     here does not rely on that: inside one block of x with the same q1, q3 is
     constant and r is linear in x, so testing both ends of each block covers
     every x. Result: 0 <= r < 3q and r == x (mod q) for all x <= (q-1)^2, so
     two conditional subtractions give the canonical result.
  2. The hardware butterfly order, bank mapping (bank = parity of the 8-bit
     index, address = index[6:0]), twiddle addressing and the merged final
     scaling of NTT^-1 give exactly the FIPS 203 / FIPS 204 results.
  3. Pipeline hazards: with one butterfly issued per clock and no stalls
     between layers, every coefficient read happens strictly after the write
     of that coefficient by the previous layer (the margin is reported).

Run directly to self-test:  python ntt_hw.py [--count N] [--seed S] [--fast]
"""

import argparse
import random
import sys

import ntt as ref

# ---------------------------------------------------------------- constants
Q = {"kem": ref.Q_KEM, "dsa": ref.Q_DSA}
NBITS = {"kem": 12, "dsa": 23}
MU = {m: (1 << (2 * NBITS[m])) // Q[m] for m in Q}          # 5039, 8396807
FINV = {"kem": ref.F_KEM, "dsa": ref.F_DSA}
ZETAS = {"kem": ref.ZETAS_KEM, "dsa": ref.ZETAS_DSA}
LAYERS = {"kem": 7, "dsa": 8}

# Pipeline timing of rtl/aegis_ntt.v, counted in clock edges after the edge
# that ends the issue cycle of a butterfly:
RD_EDGE = 1     # RAM read address captured (end of stage R)
WR_EDGE = 8     # RAM write committed (end of stage W)

M23 = (1 << 23) - 1


def _check_constants():
    for m in Q:
        n = NBITS[m]
        assert (1 << (n - 1)) <= Q[m] < (1 << n), m          # q has exactly n bits
        assert (Q[m] - 1) ** 2 < (1 << (2 * n)), m           # every product fits 2n bits
        assert 3 * Q[m] < (1 << (n + 2)), m                  # r fits n+2 bits
    assert MU["kem"] == 5039 and MU["dsa"] == 8396807


# ---------------------------------------------------------------- datapath
def barrett_raw(x, mode):
    """x - q3*q before the final corrections, with the RTL bit widths."""
    n = NBITS[mode]
    q1 = (x >> (n - 1)) & ((1 << (n + 1)) - 1)     # kem: x[23:11], dsa: x[45:22]
    q3 = (q1 * MU[mode]) >> (n + 1)                # kem: q2[25:13], dsa: q2[47:24]
    return (x - q3 * Q[mode]) & ((1 << (n + 2)) - 1)


def correct(r, mode):
    q = Q[mode]
    if r >= 2 * q:
        r -= 2 * q
    elif r >= q:
        r -= q
    return r & M23


def modmul(a, b, mode):
    return correct(barrett_raw((a * b) & ((1 << 46) - 1), mode), mode)


def add_mod(a, b, mode):
    q = Q[mode]
    s = a + b
    return (s - q if s >= q else s) & M23


def sub_mod(b, a, mode):
    """(b - a) mod q for a, b in [0, q)."""
    q = Q[mode]
    return (b - a if b >= a else b - a + q) & M23


def rom_table(mode):
    """Twiddle ROM contents, indexed by k = 0..255.
    k >= 1: zetas[k] (FIPS 203 / 204 tables). k = 0 is unused by the
    standards; the hardware stores zetas[1] * f there and uses it for the
    last NTT^-1 layer, where the final scaling by f is merged."""
    q, z, f = Q[mode], ZETAS[mode], FINV[mode]
    t = [0] * 256
    t[0] = (z[1] * f) % q
    for k in range(1, len(z)):
        t[k] = z[k]
    return t


def parity(v):
    return bin(v).count("1") & 1


def layer_log2len(mode, inverse, lc):
    """log2(len) for layer number lc (0-based in execution order)."""
    if inverse:
        return lc + (1 if mode == "kem" else 0)
    return 7 - lc


def butterfly_addr(bf, l, inverse):
    """Exactly the RTL address generation for butterfly bf in a layer with
    len = 2^l. Returns (j, j+len, k, last_inverse_layer)."""
    mask = (1 << l) - 1
    j = (bf & mask) | ((bf & ~mask & 0x7F) << 1)
    jb = j | (1 << l)
    k = (0x80 | ((~bf & 0x7F) if inverse else bf)) >> l
    last = inverse and l == 7
    if last:
        k = 0
    return j, jb, k, last


def schedule(mode, inverse):
    """Yields (issue_cycle, j, jb, k, last) in hardware issue order."""
    t = 0
    for lc in range(LAYERS[mode]):
        l = layer_log2len(mode, inverse, lc)
        for bf in range(128):
            yield (t,) + butterfly_addr(bf, l, inverse)
            t += 1


def hw_transform(x, mode, inverse):
    """Runs the hardware algorithm (sequentially) on two 128-entry banks."""
    q = Q[mode]
    rom = rom_table(mode)
    bank = [[None] * 128, [None] * 128]
    for i, v in enumerate(x):
        bank[parity(i)][i & 127] = v
    for _, j, jb, k, last in schedule(mode, inverse):
        pa, pb = parity(j), parity(jb)
        assert pa != pb, "bank conflict"
        a = bank[pa][j & 127]
        b = bank[pb][jb & 127]
        za = rom[k]
        zb = FINV[mode] if last else 1
        if inverse:   # Gentleman-Sande: a' = (a+b)*zb, b' = (b-a)*za
            ma, mb = sub_mod(b, a, mode), add_mod(a, b, mode)
        else:         # Cooley-Tukey:    p = b*za, a' = a+p, b' = a-p
            ma, mb = b, a
        pa_, pb_ = modmul(ma, za, mode), modmul(mb, zb, mode)
        if inverse:
            na, nb = pb_, pa_
        else:
            na, nb = add_mod(pb_, pa_, mode), sub_mod(pb_, pa_, mode)
        assert na < q and nb < q
        bank[pa][j & 127] = na
        bank[pb][jb & 127] = nb
    return [bank[parity(i)][i & 127] for i in range(256)]


def cycles(mode):
    """NTT_CYCLES value the RTL is expected to report (busy cycles)."""
    return LAYERS[mode] * 128 + WR_EDGE


# ---------------------------------------------------------------- checks
def check_barrett_all_products(mode):
    """Exhaustive over every x in [0, (q-1)^2], block by block (see docstring)."""
    q, n, mu = Q[mode], NBITS[mode], MU[mode]
    xmax = (q - 1) ** 2
    blk = 1 << (n - 1)
    lim = 3 * q
    for q1 in range((xmax >> (n - 1)) + 1):
        q3 = (q1 * mu) >> (n + 1)
        lo = q1 * blk
        hi = min(lo + blk - 1, xmax)
        rlo = lo - q3 * q
        if rlo < 0 or hi - q3 * q >= lim:
            raise AssertionError(f"Barrett bound fails for {mode} q1={q1}")
    return xmax + 1


def check_barrett_spot(mode, rng, count):
    q = Q[mode]
    edge = [0, 1, 2, q - 2, q - 1]
    pairs = [(a, b) for a in edge for b in edge]
    pairs += [(rng.randrange(q), rng.randrange(q)) for _ in range(count)]
    for a, b in pairs:
        assert modmul(a, b, mode) == (a * b) % q, (mode, a, b)
        r = barrett_raw(a * b, mode)
        assert r < 3 * q and r % q == (a * b) % q
    for a in edge + [rng.randrange(q) for _ in range(count)]:
        for b in edge:
            assert add_mod(a, b, mode) == (a + b) % q
            assert sub_mod(b, a, mode) == (b - a) % q
    return len(pairs)


def check_hazards(mode, inverse):
    """Minimum (read edge - write edge) over all read-after-write dependencies."""
    last_wr = {}
    margin = None
    for t, j, jb, _, _ in schedule(mode, inverse):
        rd = t + RD_EDGE
        for i in (j, jb):
            if i in last_wr:
                m = rd - last_wr[i]
                margin = m if margin is None else min(margin, m)
        for i in (j, jb):
            last_wr[i] = t + WR_EDGE
    assert margin is not None and margin >= 1, (mode, inverse, margin)
    return margin


def check_transforms(rng, count):
    n = 0
    for mode in ("kem", "dsa"):
        q = Q[mode]
        special = [[0] * 256, [q - 1] * 256, [1] + [0] * 255, [0] * 255 + [q - 1],
                   [(i * 7919) % q for i in range(256)]]
        vecs = special + [[rng.randrange(q) for _ in range(256)] for _ in range(count)]
        for inverse in (False, True):
            for x in vecs:
                want = ref.transform(mode, inverse, x)
                got = hw_transform(x, mode, inverse)
                assert got == want, (mode, inverse)
                n += 1
    return n


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--seed", type=int, default=3)
    ap.add_argument("--fast", action="store_true",
                    help="skip the exhaustive ML-DSA Barrett sweep (about 10 s)")
    args = ap.parse_args()
    rng = random.Random(args.seed)
    _check_constants()

    for mode in ("kem", "dsa"):
        if mode == "dsa" and args.fast:
            print("ntt_hw.py: ML-DSA Barrett exhaustive sweep SKIPPED (--fast)")
        else:
            nx = check_barrett_all_products(mode)
            print(f"ntt_hw.py: {mode.upper()} Barrett: 0 <= x - q3*q < 3q for every x in "
                  f"[0, (q-1)^2] ({nx} values, block-exhaustive) PASS")
        np_ = check_barrett_spot(mode, rng, 20000)
        print(f"ntt_hw.py: {mode.upper()} modmul/add/sub spot check, {np_} products PASS")

    for mode in ("kem", "dsa"):
        for inverse in (False, True):
            m = check_hazards(mode, inverse)
            print(f"ntt_hw.py: {mode.upper()} {'INTT' if inverse else 'NTT '} schedule: "
                  f"no RAW hazard, minimum margin {m} cycles, expected NTT_CYCLES {cycles(mode)}")

    n = check_transforms(rng, args.count)
    print(f"ntt_hw.py: hardware algorithm == FIPS 203/204 reference for {n} transforms PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
