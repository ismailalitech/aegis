# SPDX-License-Identifier: Apache-2.0
"""Reference NTT / NTT^-1 for ML-KEM (FIPS 203) and ML-DSA (FIPS 204).

The four transforms are written as literal transcriptions of the standards'
pseudo-code (FIPS 203 Algorithms 9 and 10, FIPS 204 Algorithms 41 and 42).
They are checked by:
  (a) NTT^-1(NTT(x)) == x for random x, both schemes;
  (b) ML-DSA: NTT^-1(NTT(a) * NTT(b)) (pointwise) == a*b mod (X^256 + 1, q);
  (c) ML-KEM: NTT^-1(MultiplyNTTs(NTT(a), NTT(b))) == a*b mod (X^256 + 1, q),
      MultiplyNTTs / BaseCaseMultiply being FIPS 203 Algorithms 11 and 12
      with gamma = zeta^(2*BitRev7(i)+1).
The negacyclic product is computed by plain schoolbook multiplication.

Run directly to self-test:  python ntt.py [--count N] [--seed S]
"""

import argparse
import random
import sys

N = 256

# ML-KEM
Q_KEM = 3329
ZETA_KEM = 17
F_KEM = 3303            # 128^-1 mod 3329 (FIPS 203 Algorithm 10, line 14)

# ML-DSA
Q_DSA = 8380417
ZETA_DSA = 1753
F_DSA = 8347681         # 256^-1 mod 8380417 (FIPS 204 Algorithm 42, line 21)


def bitrev(x, bits):
    r = 0
    for _ in range(bits):
        r = (r << 1) | (x & 1)
        x >>= 1
    return r


ZETAS_KEM = [pow(ZETA_KEM, bitrev(k, 7), Q_KEM) for k in range(128)]
ZETAS_DSA = [pow(ZETA_DSA, bitrev(k, 8), Q_DSA) for k in range(256)]
GAMMAS_KEM = [pow(ZETA_KEM, 2 * bitrev(i, 7) + 1, Q_KEM) for i in range(128)]


# ---------------------------------------------------------------- FIPS 203
def ntt_kem(f):
    """FIPS 203 Algorithm 9, NTT(f)."""
    q = Q_KEM
    f = list(f)
    i = 1
    length = 128
    while length >= 2:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS_KEM[i]
            i += 1
            for j in range(start, start + length):
                t = (zeta * f[j + length]) % q
                f[j + length] = (f[j] - t) % q
                f[j] = (f[j] + t) % q
        length //= 2
    return f


def intt_kem(f):
    """FIPS 203 Algorithm 10, NTT^-1(f)."""
    q = Q_KEM
    f = list(f)
    i = 127
    length = 2
    while length <= 128:
        for start in range(0, 256, 2 * length):
            zeta = ZETAS_KEM[i]
            i -= 1
            for j in range(start, start + length):
                t = f[j]
                f[j] = (t + f[j + length]) % q
                f[j + length] = (zeta * (f[j + length] - t)) % q
        length *= 2
    return [(x * F_KEM) % q for x in f]


def base_case_multiply(a0, a1, b0, b1, gamma):
    """FIPS 203 Algorithm 12."""
    q = Q_KEM
    c0 = (a0 * b0 + a1 * b1 * gamma) % q
    c1 = (a0 * b1 + a1 * b0) % q
    return c0, c1


def multiply_ntts(f, g):
    """FIPS 203 Algorithm 11."""
    h = [0] * 256
    for i in range(128):
        h[2 * i], h[2 * i + 1] = base_case_multiply(f[2 * i], f[2 * i + 1],
                                                    g[2 * i], g[2 * i + 1], GAMMAS_KEM[i])
    return h


# ---------------------------------------------------------------- FIPS 204
def ntt_dsa(w):
    """FIPS 204 Algorithm 41, NTT(w)."""
    q = Q_DSA
    w = list(w)
    m = 0
    length = 128
    while length >= 1:
        start = 0
        while start < 256:
            m += 1
            z = ZETAS_DSA[m]
            for j in range(start, start + length):
                t = (z * w[j + length]) % q
                w[j + length] = (w[j] - t) % q
                w[j] = (w[j] + t) % q
            start += 2 * length
        length //= 2
    return w


def intt_dsa(w):
    """FIPS 204 Algorithm 42, NTT^-1(w)."""
    q = Q_DSA
    w = list(w)
    m = 256
    length = 1
    while length < 256:
        start = 0
        while start < 256:
            m -= 1
            z = -ZETAS_DSA[m]
            for j in range(start, start + length):
                t = w[j]
                w[j] = (t + w[j + length]) % q
                w[j + length] = (t - w[j + length]) % q
                w[j + length] = (z * w[j + length]) % q
            start += 2 * length
        length *= 2
    return [(F_DSA * x) % q for x in w]


# ---------------------------------------------------------------- helpers
def negacyclic_mul(a, b, q):
    """Schoolbook a*b mod (X^256 + 1, q)."""
    c = [0] * 256
    for i in range(256):
        ai = a[i]
        if not ai:
            continue
        for j in range(256):
            k = i + j
            if k < 256:
                c[k] += ai * b[j]
            else:
                c[k - 256] -= ai * b[j]
    return [x % q for x in c]


def transform(mode, inverse, x):
    """mode: 'kem' or 'dsa'."""
    if mode == "kem":
        return intt_kem(x) if inverse else ntt_kem(x)
    if mode == "dsa":
        return intt_dsa(x) if inverse else ntt_dsa(x)
    raise ValueError(mode)


def modulus(mode):
    return Q_KEM if mode == "kem" else Q_DSA


def selftest(count=100, seed=2):
    rng = random.Random(seed)
    # Constants as stated in the standards.
    assert (128 * F_KEM) % Q_KEM == 1
    assert (256 * F_DSA) % Q_DSA == 1
    assert pow(ZETA_KEM, 128, Q_KEM) == Q_KEM - 1          # primitive 256th root
    assert pow(ZETA_DSA, 256, Q_DSA) == Q_DSA - 1          # primitive 512th root
    # Spot checks against the tables printed in FIPS 203 Appendix A and
    # FIPS 204 Appendix B.
    assert ZETAS_KEM[:8] == [1, 1729, 2580, 3289, 2642, 630, 1897, 848]
    assert ZETAS_KEM[-4:] == [2110, 2935, 885, 2154]
    assert GAMMAS_KEM[:4] == [17, Q_KEM - 17, 2761, Q_KEM - 2761]
    assert ZETAS_DSA[1:6] == [4808194, 3765607, 3761513, 5178923, 5496691]

    res = {}
    for mode, fwd, inv in (("kem", ntt_kem, intt_kem), ("dsa", ntt_dsa, intt_dsa)):
        q = modulus(mode)
        for _ in range(count):
            x = [rng.randrange(q) for _ in range(N)]
            assert inv(fwd(x)) == x, (mode, "inv(fwd)")
            assert fwd(inv(x)) == x, (mode, "fwd(inv)")
        res[mode + "_roundtrip"] = count

    q = Q_DSA
    for _ in range(count):
        a = [rng.randrange(q) for _ in range(N)]
        b = [rng.randrange(q) for _ in range(N)]
        ah, bh = ntt_dsa(a), ntt_dsa(b)
        c = intt_dsa([(u * v) % q for u, v in zip(ah, bh)])
        assert c == negacyclic_mul(a, b, q), "dsa pointwise"
    res["dsa_pointwise_mul"] = count

    q = Q_KEM
    for _ in range(count):
        a = [rng.randrange(q) for _ in range(N)]
        b = [rng.randrange(q) for _ in range(N)]
        c = intt_kem(multiply_ntts(ntt_kem(a), ntt_kem(b)))
        assert c == negacyclic_mul(a, b, q), "kem MultiplyNTTs"
    res["kem_multiplyntts"] = count
    return res


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=100)
    ap.add_argument("--seed", type=int, default=2)
    args = ap.parse_args()
    res = selftest(args.count, args.seed)
    print(f"ntt.py: ML-KEM  {res['kem_roundtrip']} x NTT^-1(NTT(x))==x and NTT(NTT^-1(x))==x PASS")
    print(f"ntt.py: ML-DSA  {res['dsa_roundtrip']} x NTT^-1(NTT(x))==x and NTT(NTT^-1(x))==x PASS")
    print(f"ntt.py: ML-DSA  {res['dsa_pointwise_mul']} x pointwise product == schoolbook negacyclic PASS")
    print(f"ntt.py: ML-KEM  {res['kem_multiplyntts']} x MultiplyNTTs (Alg 11/12) == schoolbook negacyclic PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
