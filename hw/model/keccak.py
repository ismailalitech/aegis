# SPDX-License-Identifier: Apache-2.0
"""Keccak-f[1600] reference model (FIPS 202), plus SHA3 / SHAKE sponges built
on top of it so the permutation can be checked against hashlib.

State layout matches the hardware: a list of 25 lanes, lane i = x + 5*y,
each lane a 64-bit integer holding state bytes 8i..8i+7 little-endian.

The round constants and rotation offsets are derived here from the FIPS 202
algorithms (rc LFSR, Algorithm 5; rho offsets, Algorithm 2) rather than typed
in, so the RTL tables (typed in) are checked against an independent source.

Run directly to self-test:  python keccak.py [--count N] [--seed S]
"""

import argparse
import hashlib
import random
import sys

MASK64 = (1 << 64) - 1


def _rc_bit(t):
    """FIPS 202 Algorithm 5: rc(t)."""
    if t % 255 == 0:
        return 1
    r = [1, 0, 0, 0, 0, 0, 0, 0]
    for _ in range(1, (t % 255) + 1):
        r = [0] + r
        r[0] ^= r[8]
        r[4] ^= r[8]
        r[5] ^= r[8]
        r[6] ^= r[8]
        r = r[:8]
    return r[0]


def _round_constants():
    rcs = []
    for ir in range(24):
        rc = 0
        for j in range(7):
            if _rc_bit(j + 7 * ir):
                rc |= 1 << ((1 << j) - 1)
        rcs.append(rc)
    return rcs


def _rho_offsets():
    """FIPS 202 Algorithm 2: offsets indexed by lane i = x + 5*y."""
    off = [0] * 25
    x, y = 1, 0
    for t in range(24):
        off[x + 5 * y] = ((t + 1) * (t + 2) // 2) % 64
        x, y = y, (2 * x + 3 * y) % 5
    return off


RC = _round_constants()
RHO = _rho_offsets()


def _rotl(v, n):
    n %= 64
    return ((v << n) | (v >> (64 - n))) & MASK64 if n else v


def keccak_round(a, ir):
    """One round (theta, rho, pi, chi, iota) on a 25-lane list; returns new list."""
    c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
    d = [c[(x - 1) % 5] ^ _rotl(c[(x + 1) % 5], 1) for x in range(5)]
    e = [a[i] ^ d[i % 5] for i in range(25)]
    b = [0] * 25
    for x in range(5):
        for y in range(5):
            # pi: A'[x, y] = A[(x + 3y) mod 5, x]  <=>  B[y, 2x+3y] = rot(A[x, y])
            b[y + 5 * ((2 * x + 3 * y) % 5)] = _rotl(e[x + 5 * y], RHO[x + 5 * y])
    out = [0] * 25
    for x in range(5):
        for y in range(5):
            out[x + 5 * y] = b[x + 5 * y] ^ ((~b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y])
    out[0] ^= RC[ir]
    return out


def keccak_f1600(lanes):
    """Keccak-f[1600] permutation (24 rounds). Input/output: 25 x 64-bit lanes."""
    a = list(lanes)
    assert len(a) == 25
    for ir in range(24):
        a = keccak_round(a, ir)
    return a


def bytes_to_lanes(b):
    assert len(b) == 200
    return [int.from_bytes(b[8 * i:8 * i + 8], "little") for i in range(25)]


def lanes_to_bytes(lanes):
    return b"".join(v.to_bytes(8, "little") for v in lanes)


def sponge(rate, msg, suffix, outlen):
    """Keccak[c] sponge with pad10*1; `suffix` holds the domain bits plus the
    first padding 1 bit (0x06 for SHA3, 0x1F for SHAKE)."""
    state = bytearray(200)
    padded = bytearray(msg) + bytes([suffix])
    while len(padded) % rate:
        padded.append(0)
    padded[-1] |= 0x80
    for off in range(0, len(padded), rate):
        for i in range(rate):
            state[i] ^= padded[off + i]
        state = bytearray(lanes_to_bytes(keccak_f1600(bytes_to_lanes(bytes(state)))))
    out = bytearray()
    while True:
        out += state[:rate]
        if len(out) >= outlen:
            return bytes(out[:outlen])
        state = bytearray(lanes_to_bytes(keccak_f1600(bytes_to_lanes(bytes(state)))))


def sha3_256(msg):
    return sponge(136, msg, 0x06, 32)


def sha3_512(msg):
    return sponge(72, msg, 0x06, 64)


def shake128(msg, outlen):
    return sponge(168, msg, 0x1F, outlen)


def shake256(msg, outlen):
    return sponge(136, msg, 0x1F, outlen)


ZERO_STATE_LANE0 = 0xF1258F7940E1DDE7


def selftest(count=300, seed=1):
    rng = random.Random(seed)
    # Known answer: permutation of the all-zero state.
    z = keccak_f1600([0] * 25)
    assert z[0] == ZERO_STATE_LANE0, hex(z[0])

    # Lengths chosen to hit empty, sub-block, exact-rate and multi-block cases
    # for every rate used below (72, 136, 168).
    lengths = [0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 271, 272, 273,
               335, 336, 337, 503, 504, 505, 1000, 2000]
    lengths += [rng.randrange(0, 1200) for _ in range(max(0, count - len(lengths)))]
    n = 0
    for ln in lengths:
        msg = bytes(rng.randrange(256) for _ in range(ln))
        assert sha3_256(msg) == hashlib.sha3_256(msg).digest(), ("sha3_256", ln)
        assert sha3_512(msg) == hashlib.sha3_512(msg).digest(), ("sha3_512", ln)
        outlen = rng.choice([1, 16, 32, 167, 168, 169, 400, 1000])
        assert shake128(msg, outlen) == hashlib.shake_128(msg).digest(outlen), ("shake128", ln, outlen)
        assert shake256(msg, outlen) == hashlib.shake_256(msg).digest(outlen), ("shake256", ln, outlen)
        n += 1
    multi = sum(1 for ln in lengths if ln >= 136)
    return n, multi


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--count", type=int, default=300)
    ap.add_argument("--seed", type=int, default=1)
    args = ap.parse_args()
    n, multi = selftest(args.count, args.seed)
    print(f"keccak.py: zero-state lane0 = 0x{ZERO_STATE_LANE0:016X} OK")
    print(f"keccak.py: {n} messages x (SHA3-256, SHA3-512, SHAKE128, SHAKE256) match hashlib "
          f"({multi} of them >= 136 bytes, multi-block) PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
