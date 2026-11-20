# SPDX-License-Identifier: Apache-2.0
"""Minimal CBOR (RFC 8949) decoder and encoder, standard library only.

Enough for PSA attestation tokens and COSE_Sign1: integers, byte and text
strings, arrays, maps, tags, simple values. Indefinite lengths and floats
other than the simple values are rejected on purpose.
"""


class Tag:
    def __init__(self, tag, value):
        self.tag, self.value = tag, value

    def __repr__(self):
        return "Tag(%d, %r)" % (self.tag, self.value)


class CBORError(ValueError):
    pass


def _head(data, i):
    if i >= len(data):
        raise CBORError("truncated")
    b = data[i]
    mt, ai = b >> 5, b & 31
    i += 1
    if ai < 24:
        return mt, ai, i
    n = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
    if n is None:
        raise CBORError("unsupported additional info %d" % ai)
    if i + n > len(data):
        raise CBORError("truncated")
    return mt, int.from_bytes(data[i:i + n], "big"), i + n


def _decode(data, i, depth):
    if depth > 16:
        raise CBORError("nesting too deep")
    mt, v, i = _head(data, i)
    if mt == 0:
        return v, i
    if mt == 1:
        return -1 - v, i
    if mt in (2, 3):
        if i + v > len(data):
            raise CBORError("truncated string")
        s = bytes(data[i:i + v])
        return (s if mt == 2 else s.decode("utf-8")), i + v
    if mt == 4:
        out = []
        for _ in range(v):
            x, i = _decode(data, i, depth + 1)
            out.append(x)
        return out, i
    if mt == 5:
        out = {}
        for _ in range(v):
            k, i = _decode(data, i, depth + 1)
            # Keys are integers or strings only, and never repeated: an array or map as key is unhashable in
            # Python (a TypeError the callers do not expect), and a repeated key would let two parsers disagree.
            if isinstance(k, bool) or not isinstance(k, (int, str, bytes)):
                raise CBORError("map key of unsupported type")
            if k in out:
                raise CBORError("duplicate map key")
            x, i = _decode(data, i, depth + 1)
            out[k] = x
        return out, i
    if mt == 6:
        x, i = _decode(data, i, depth + 1)
        return Tag(v, x), i
    if mt == 7:
        simple = {20: False, 21: True, 22: None}
        if v in simple:
            return simple[v], i
    raise CBORError("unsupported major type %d / value %d" % (mt, v))


def loads(data):
    x, i = _decode(data, 0, 0)
    if i != len(data):
        raise CBORError("trailing bytes")
    return x


def _enc_head(mt, v):
    if v < 24:
        return bytes([(mt << 5) | v])
    for ai, n in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if v < (1 << (8 * n)):
            return bytes([(mt << 5) | ai]) + v.to_bytes(n, "big")
    raise CBORError("integer too large")


def dumps(x):
    if isinstance(x, bool):
        return bytes([0xF5 if x else 0xF4])
    if x is None:
        return b"\xf6"
    if isinstance(x, int):
        return _enc_head(0, x) if x >= 0 else _enc_head(1, -1 - x)
    if isinstance(x, bytes):
        return _enc_head(2, len(x)) + x
    if isinstance(x, str):
        b = x.encode()
        return _enc_head(3, len(b)) + b
    if isinstance(x, (list, tuple)):
        return _enc_head(4, len(x)) + b"".join(dumps(e) for e in x)
    if isinstance(x, dict):
        return _enc_head(5, len(x)) + b"".join(dumps(k) + dumps(v) for k, v in x.items())
    if isinstance(x, Tag):
        return _enc_head(6, x.tag) + dumps(x.value)
    raise CBORError("cannot encode %r" % type(x))
