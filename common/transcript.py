# SPDX-License-Identifier: Apache-2.0
"""Aegis transcript v2: attestation and session provisioning as one signed transcript (docs/architecture.md,
"One transcript").

Before, the quote (PQCHAL) and the ML-KEM exchange (PQKEMINIT, PQKEMFIN) were two exchanges that shared nothing but
the endpoint's key: the endpoint signed "nonce || ek", which says nothing about the code that reported the
measurements. With one key serving two firmwares, the verifier could appraise one and finish the session with the
other. Here the three steps are one hash chain, and each later step is only valid for the earlier ones:

  T1 = SHA3-256("aegis-transcript-v2/quote"    || challenge[32] || SHA3-256(token)[32])        the quote, as appraised
  T2 = SHA3-256("aegis-transcript-v2/kem-init" || T1[32] || ek[1184])                          the endpoint's KEM key
  T3 = SHA3-256("aegis-transcript-v2/kem-fin"  || T2[32] || SHA3-256(ct)[32] || SHA3-256(credential)[32])

  endpoint signature (PQKEMEK)   ML-DSA-65 over "aegis-kem-init-v2" || 0x00 || T2
  credential (verifier-signed)   its body names T2 in "transcript_sha3_256" (next to SHA3-256(ct) and SHA3-256(ek))
  confirmation tag (PQKEMOK)     SHA3-256("aegis-confirm-v2" || K[32] || T3[32])
  session key                    SHA3-256("aegis-session-v2" || K[32] || T3[32])

Every field has a fixed length and every hash its own label, so no input of one step can be read as another's, and
none of the labels is a prefix of another. The token is the byte string the endpoint signed as its quote (it holds
the challenge and the measurements); the verifier hashes the bytes it appraised. The challenge is the one verifier
nonce of the whole transcript: PQKEMINIT carries it again, which is how the endpoint knows which quote the exchange
continues (the request line did not change). K is the ML-KEM-768 shared secret.

What the endpoint signs is T2: the quote it issued in this boot and the key it made for it. The ciphertext and the
credential come later, and are covered by the confirmation tag, which only the holder of the decapsulation key of
that signed ek can compute; there is no second signature.
"""
import hashlib

VERSION = "v2"
L_QUOTE = b"aegis-transcript-v2/quote"
L_KEM_INIT = b"aegis-transcript-v2/kem-init"
L_KEM_FIN = b"aegis-transcript-v2/kem-fin"
KEM_INIT_LABEL = b"aegis-kem-init-v2"     # the ML-DSA-65 label of the endpoint's signature over T2 (mldsa.sign)
L_CONFIRM = b"aegis-confirm-v2"
L_SESSION = b"aegis-session-v2"
HASH_LEN = 32
EK_LEN = 1184


def _sha3(*parts):
    return hashlib.sha3_256(b"".join(parts)).digest()


def _fixed(name, value, n):
    if not isinstance(value, (bytes, bytearray)) or len(value) != n:
        raise ValueError("transcript: %s must be %d bytes" % (name, n))
    return bytes(value)


def token_hash(token):
    """SHA3-256 of the quote's signed bytes (the token or claims map exactly as the endpoint sent it)."""
    if not isinstance(token, (bytes, bytearray)) or not token:
        raise ValueError("transcript: empty token")
    return _sha3(bytes(token))


def quote(challenge, tok_hash):
    """T1."""
    return _sha3(L_QUOTE, _fixed("challenge", challenge, HASH_LEN), _fixed("token hash", tok_hash, HASH_LEN))


def kem_init(t1, ek):
    """T2: what the endpoint signs with KEM_INIT_LABEL."""
    return _sha3(L_KEM_INIT, _fixed("T1", t1, HASH_LEN), _fixed("ek", ek, EK_LEN))


def kem_fin(t2, ct, credential):
    """T3."""
    return _sha3(L_KEM_FIN, _fixed("T2", t2, HASH_LEN), _sha3(bytes(ct)), _sha3(bytes(credential)))


def confirm_tag(k, t3):
    return _sha3(L_CONFIRM, _fixed("K", k, HASH_LEN), _fixed("T3", t3, HASH_LEN))


def session_key(k, t3):
    return _sha3(L_SESSION, _fixed("K", k, HASH_LEN), _fixed("T3", t3, HASH_LEN))
