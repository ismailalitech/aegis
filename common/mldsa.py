"""ML-DSA-65 (FIPS 204) through liboqs, with ctypes only (works on the board's
stdlib-only Python and on the PC).

Library search: $AEGIS_LIBOQS, then liboqs.so.9 next to this file, then the
system loader. Signatures are domain-separated by prefixing a context label
to the message: sign(label, msg) signs label || 0x00 || msg.
"""
import ctypes
import ctypes.util
import os

PK_LEN = 1952
SK_LEN = 4032
SIG_LEN = 3309

_lib = None


def _load():
    global _lib
    if _lib is not None:
        return _lib
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [os.environ.get("AEGIS_LIBOQS"),
                  os.path.join(here, "liboqs.so.9"),
                  os.path.expanduser("~/aegis-tools/liboqs/lib/liboqs.so.9"),
                  ctypes.util.find_library("oqs")]
    for c in candidates:
        if c and (os.path.exists(c) or not os.path.sep in c):
            try:
                _lib = ctypes.CDLL(c)
                break
            except OSError:
                continue
    if _lib is None:
        raise OSError("liboqs not found (set AEGIS_LIBOQS)")
    _lib.OQS_init()
    u8p = ctypes.POINTER(ctypes.c_uint8)
    _lib.OQS_SIG_ml_dsa_65_keypair.argtypes = [u8p, u8p]
    _lib.OQS_SIG_ml_dsa_65_sign.argtypes = [u8p, ctypes.POINTER(ctypes.c_size_t), u8p, ctypes.c_size_t, u8p]
    _lib.OQS_SIG_ml_dsa_65_verify.argtypes = [u8p, ctypes.c_size_t, u8p, ctypes.c_size_t, u8p]
    for f in ("keypair", "sign", "verify"):
        getattr(_lib, "OQS_SIG_ml_dsa_65_" + f).restype = ctypes.c_int
    return _lib


def _buf(data_or_len):
    if isinstance(data_or_len, int):
        return (ctypes.c_uint8 * data_or_len)()
    return (ctypes.c_uint8 * len(data_or_len)).from_buffer_copy(data_or_len)


def keypair():
    lib = _load()
    pk, sk = _buf(PK_LEN), _buf(SK_LEN)
    if lib.OQS_SIG_ml_dsa_65_keypair(pk, sk) != 0:
        raise RuntimeError("ML-DSA-65 keypair failed")
    return bytes(pk), bytes(sk)


def _framed(label, msg):
    if b"\x00" in label:
        raise ValueError("label must not contain NUL")
    return label + b"\x00" + msg


def sign(sk, label, msg):
    lib = _load()
    if len(sk) != SK_LEN:
        raise ValueError("bad secret key length")
    m = _framed(label, msg)
    sig, siglen = _buf(SIG_LEN), ctypes.c_size_t(0)
    if lib.OQS_SIG_ml_dsa_65_sign(sig, ctypes.byref(siglen), _buf(m), len(m), _buf(sk)) != 0:
        raise RuntimeError("ML-DSA-65 sign failed")
    return bytes(sig)[:siglen.value]


def verify(pk, label, msg, sig):
    lib = _load()
    if len(pk) != PK_LEN or not sig or len(sig) > SIG_LEN:
        return False
    m = _framed(label, msg)
    return lib.OQS_SIG_ml_dsa_65_verify(_buf(m), len(m), _buf(sig), len(sig), _buf(pk)) == 0
