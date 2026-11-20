# SPDX-License-Identifier: Apache-2.0
"""ML-KEM-768 (FIPS 203), with the same two backends and the same choice as mldsa.py.

Encapsulation keys, ciphertexts and shared secrets are the FIPS 203 encodings in both. Decapsulation keys differ:
the 64-byte seed (SEED_LEN) with openssl, the 2400-byte expanded key (DK_LEN) with liboqs; decaps() picks the backend
from the key's length."""
import ctypes

import mldsa

EK_LEN = 1184
DK_LEN = 2400
SEED_LEN = 64
CT_LEN = 1088
SS_LEN = 32


def _lib():
    lib = mldsa._load()
    if not getattr(lib, "_aegis_kem_ready", False):
        u8p = ctypes.POINTER(ctypes.c_uint8)
        lib.OQS_KEM_ml_kem_768_keypair.argtypes = [u8p, u8p]
        lib.OQS_KEM_ml_kem_768_encaps.argtypes = [u8p, u8p, u8p]
        lib.OQS_KEM_ml_kem_768_decaps.argtypes = [u8p, u8p, u8p]
        for f in ("keypair", "encaps", "decaps"):
            getattr(lib, "OQS_KEM_ml_kem_768_" + f).restype = ctypes.c_int
        lib._aegis_kem_ready = True
    return lib


def keypair():
    if mldsa.backend() == "openssl":
        dk = mldsa._openssl()[1].MLKEM768PrivateKey.generate()
        return dk.public_key().public_bytes_raw(), dk.private_bytes_raw()
    ek, dk = mldsa._buf(EK_LEN), mldsa._buf(DK_LEN)
    if _lib().OQS_KEM_ml_kem_768_keypair(ek, dk) != 0:
        raise RuntimeError("ML-KEM-768 keypair failed")
    return bytes(ek), bytes(dk)


def encaps(ek, use=None):
    """(ciphertext, shared secret). Raises ValueError for a key of the wrong length and RuntimeError for one that
    fails the FIPS 203 modulus check, in both backends."""
    if len(ek) != EK_LEN:
        raise ValueError("bad encapsulation key length")
    if (use or mldsa.backend()) == "openssl":
        k = mldsa._openssl()[1]
        try:
            ss, ct = k.MLKEM768PublicKey.from_public_bytes(ek).encapsulate()
        except Exception as e:  # noqa: BLE001 - OpenSSL refuses a key whose coefficients are not reduced
            raise RuntimeError("ML-KEM-768 encaps failed (key rejected): %s" % type(e).__name__)
        return ct, ss
    ct, ss = mldsa._buf(CT_LEN), mldsa._buf(SS_LEN)
    if _lib().OQS_KEM_ml_kem_768_encaps(ct, ss, mldsa._buf(ek)) != 0:
        raise RuntimeError("ML-KEM-768 encaps failed (key rejected)")
    return bytes(ct), bytes(ss)


def decaps(ct, dk):
    if len(ct) != CT_LEN:
        raise RuntimeError("ML-KEM-768 decaps failed")
    if len(dk) == SEED_LEN:
        try:
            return mldsa._openssl()[1].MLKEM768PrivateKey.from_seed_bytes(dk).decapsulate(ct)
        except OSError:
            raise
        except Exception:  # noqa: BLE001
            raise RuntimeError("ML-KEM-768 decaps failed")
    if len(dk) != DK_LEN:
        raise ValueError("bad decapsulation key length")
    ss = mldsa._buf(SS_LEN)
    if _lib().OQS_KEM_ml_kem_768_decaps(ss, mldsa._buf(ct), mldsa._buf(dk)) != 0:
        raise RuntimeError("ML-KEM-768 decaps failed")
    return bytes(ss)
