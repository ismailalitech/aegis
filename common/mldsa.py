"""ML-DSA-65 (FIPS 204), with two interchangeable backends.

  openssl   OpenSSL 3.5 or later through the Python "cryptography" package (version 47 or later). The backend for a
            verifier on an ordinary Linux server.
  liboqs    liboqs through ctypes: works on the board's stdlib-only Python. liboqs' own README says not to rely on it
            in production, so it stays for the bench and for cross-checking the other backend.

Choice: $AEGIS_PQ_BACKEND = openssl | liboqs | auto (default). auto takes openssl when the package offers ML-DSA and
ML-KEM, liboqs otherwise. Library search for liboqs: $AEGIS_LIBOQS, then liboqs.so.9 next to this file, then
~/aegis-tools, then the system loader.

Public keys and signatures are the FIPS 204 encodings in both, so either side of a link may use either backend.
Secret keys differ in form and each backend only signs with its own:
  openssl   the 32-byte seed (SEED_LEN); OpenSSL expands it at each use;
  liboqs    the 4032-byte expanded key (SK_LEN).
sign() picks the backend from the key's length, so a key made on the board keeps working there after an upgrade.

Signatures are domain-separated by prefixing a context label to the message: sign(label, msg) signs
label || 0x00 || msg with an empty FIPS 204 context string, hedged (fresh randomness in every signature).
"""
import ctypes
import ctypes.util
import os

PK_LEN = 1952
SK_LEN = 4032
SEED_LEN = 32
SIG_LEN = 3309

_lib = None
_ossl = None


def _load():
    """liboqs, or OSError."""
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


def _openssl():
    """The cryptography package's ML-DSA and ML-KEM modules as (mldsa, mlkem), or OSError."""
    global _ossl
    if _ossl is None:
        try:
            from cryptography.hazmat.primitives.asymmetric import mldsa as m, mlkem as k
            m.MLDSA65PrivateKey.generate()      # raises UnsupportedAlgorithm on an OpenSSL without ML-DSA
            k.MLKEM768PrivateKey.generate()
            _ossl = (m, k)
        except Exception as e:  # noqa: BLE001 - not installed, too old, or built without the algorithms
            raise OSError("OpenSSL backend not available (%s: %s)" % (type(e).__name__, e))
    return _ossl


def have(backend):
    try:
        _openssl() if backend == "openssl" else _load()
        return True
    except OSError:
        return False


def backend():
    """The backend that makes new keys: "openssl" or "liboqs"."""
    want = os.environ.get("AEGIS_PQ_BACKEND", "auto")
    if want not in ("auto", "openssl", "liboqs"):
        raise ValueError("AEGIS_PQ_BACKEND must be openssl, liboqs or auto")
    if want == "auto":
        if have("openssl"):
            return "openssl"
        if have("liboqs"):
            return "liboqs"
        raise OSError("no ML-DSA backend: install cryptography >= 47 (with OpenSSL >= 3.5) or liboqs")
    if not have(want):
        _openssl() if want == "openssl" else _load()   # raises the reason
    return want


def describe():
    """One line for logs and quotes: which library does the work."""
    b = backend()
    if b == "openssl":
        from cryptography.hazmat.backends.openssl import backend as ob
        return "openssl (%s)" % ob.openssl_version_text()
    return "liboqs"


def _buf(data_or_len):
    if isinstance(data_or_len, int):
        return (ctypes.c_uint8 * data_or_len)()
    return (ctypes.c_uint8 * len(data_or_len)).from_buffer_copy(data_or_len)


def keypair():
    """(public key, secret key); the secret key is a 32-byte seed with openssl, the expanded key with liboqs."""
    if backend() == "openssl":
        sk = _openssl()[0].MLDSA65PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()
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
    m = _framed(label, msg)
    if len(sk) == SEED_LEN:
        sig = _openssl()[0].MLDSA65PrivateKey.from_seed_bytes(sk).sign(m)
        if len(sig) != SIG_LEN:
            raise RuntimeError("ML-DSA-65 sign failed")
        return sig
    if len(sk) != SK_LEN:
        raise ValueError("bad secret key length")
    lib = _load()
    sig, siglen = _buf(SIG_LEN), ctypes.c_size_t(0)
    if lib.OQS_SIG_ml_dsa_65_sign(sig, ctypes.byref(siglen), _buf(m), len(m), _buf(sk)) != 0:
        raise RuntimeError("ML-DSA-65 sign failed")
    return bytes(sig)[:siglen.value]


def verify(pk, label, msg, sig, use=None):
    """True only for a valid signature. use = "openssl" or "liboqs" forces a backend (the cross-check test)."""
    if len(pk) != PK_LEN or not sig or len(sig) > SIG_LEN:
        return False
    m = _framed(label, msg)
    if (use or backend()) == "openssl":
        if len(sig) != SIG_LEN:
            return False
        try:
            _openssl()[0].MLDSA65PublicKey.from_public_bytes(pk).verify(sig, m)
            return True
        except OSError:
            raise
        except Exception:  # noqa: BLE001 - InvalidSignature, or a public key OpenSSL refuses to load
            return False
    lib = _load()
    return lib.OQS_SIG_ml_dsa_65_verify(_buf(m), len(m), _buf(sig), len(sig), _buf(pk)) == 0
