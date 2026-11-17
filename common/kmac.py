"""KMAC128 and KMAC256 (NIST SP 800-185), standard library only.

Python's hashlib offers SHA-3 and SHAKE but not cSHAKE, which KMAC is built on, so this module carries its own
Keccak-f[1600]. It is small and slow; it is used for short messages (the session heartbeat), not bulk data.
Checked against NIST's KMAC samples 1-6 (tests/host/test_kmac.py).
"""

_RC = [0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
       0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
       0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
       0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
       0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
       0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008]
_ROT = [[0, 36, 3, 41, 18], [1, 44, 10, 45, 2], [62, 6, 43, 15, 61], [28, 55, 25, 21, 56], [27, 20, 39, 8, 14]]
_M = (1 << 64) - 1


def _rol(v, n):
    return ((v << n) | (v >> (64 - n))) & _M if n else v


def _keccak_f(a):
    """a: list of 25 lanes, a[x + 5*y]."""
    for rc in _RC:
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x - 1) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        a = [a[i] ^ d[i % 5] for i in range(25)]
        b = [0] * 25
        for x in range(5):
            for y in range(5):
                b[y + 5 * ((2 * x + 3 * y) % 5)] = _rol(a[x + 5 * y], _ROT[x][y])
        a = [b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)]) for i in range(25)]
        a[0] ^= rc
    return a


def _sponge(data, rate, suffix, outlen):
    data = bytearray(data) + bytes([suffix])
    data += bytes((-len(data)) % rate)
    data[-1] |= 0x80
    a = [0] * 25
    for off in range(0, len(data), rate):
        blk = data[off:off + rate]
        for i in range(rate // 8):
            a[i] ^= int.from_bytes(blk[8 * i:8 * i + 8], "little")
        a = _keccak_f(a)
    out = bytearray()
    while True:
        out += b"".join(a[i].to_bytes(8, "little") for i in range(rate // 8))
        if len(out) >= outlen:
            return bytes(out[:outlen])
        a = _keccak_f(a)


def _left_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return bytes([n]) + x.to_bytes(n, "big")


def _right_encode(x):
    n = max(1, (x.bit_length() + 7) // 8)
    return x.to_bytes(n, "big") + bytes([n])


def _encode_string(s):
    return _left_encode(8 * len(s)) + s


def _bytepad(x, w):
    z = _left_encode(w) + x
    return z + bytes((-len(z)) % w)


def _kmac(rate, key, data, outlen, custom):
    prefix = _bytepad(_encode_string(b"KMAC") + _encode_string(custom), rate)
    body = _bytepad(_encode_string(key), rate) + data + _right_encode(8 * outlen)
    return _sponge(prefix + body, rate, 0x04, outlen)   # cSHAKE: domain bits 00, then pad10*1


def kmac128(key, data, outlen=32, custom=b""):
    return _kmac(168, bytes(key), bytes(data), outlen, bytes(custom))


def kmac256(key, data, outlen=32, custom=b""):
    return _kmac(136, bytes(key), bytes(data), outlen, bytes(custom))
