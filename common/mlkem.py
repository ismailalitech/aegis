"""ML-KEM-768 (FIPS 203) through liboqs with ctypes (board and PC), same library search as mldsa.py."""
import ctypes

import mldsa

EK_LEN = 1184
DK_LEN = 2400
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
    ek, dk = mldsa._buf(EK_LEN), mldsa._buf(DK_LEN)
    if _lib().OQS_KEM_ml_kem_768_keypair(ek, dk) != 0:
        raise RuntimeError("ML-KEM-768 keypair failed")
    return bytes(ek), bytes(dk)


def encaps(ek):
    if len(ek) != EK_LEN:
        raise ValueError("bad encapsulation key length")
    ct, ss = mldsa._buf(CT_LEN), mldsa._buf(SS_LEN)
    if _lib().OQS_KEM_ml_kem_768_encaps(ct, ss, mldsa._buf(ek)) != 0:
        raise RuntimeError("ML-KEM-768 encaps failed (key rejected)")
    return bytes(ct), bytes(ss)


def decaps(ct, dk):
    ss = mldsa._buf(SS_LEN)
    if _lib().OQS_KEM_ml_kem_768_decaps(ss, mldsa._buf(ct), mldsa._buf(dk)) != 0:
        raise RuntimeError("ML-KEM-768 decaps failed")
    return bytes(ss)
