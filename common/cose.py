# SPDX-License-Identifier: Apache-2.0
"""COSE_Sign1 (RFC 9052) signed with ML-DSA-65 (RFC 9964): the envelope of Aegis' standard evidence, attestation
results and endorsements (docs/evidence-format.md).

One object, one form. An Aegis COSE_Sign1 is

  18([                                      tag 18, COSE_Sign1 (RFC 9052 section 4.2)
    protected:   bstr .cbor {1: -49,        alg: ML-DSA-65 (RFC 9964, IANA "COSE Algorithms")
                             4: kid,        the signer's key: its COSE Key Thumbprint, 32 bytes (below)
                             16: typ},      "application/eat+cwt" (RFC 9596 "typ", RFC 9782)
    unprotected: {},                        empty: nothing in an Aegis object is outside the signature
    payload:     bstr,                      the claims (CBOR), attached
    signature:   bstr .size 3309            ML-DSA-65 over Sig_structure, pure, empty context (FIPS 204 ML-DSA.Sign)
  ])

  Sig_structure = ["Signature1", protected, h'', payload]     (RFC 9052 section 4.4; external_aad is empty)

  kid = SHA-256(deterministic CBOR of {1: 7, 3: -49, -1: public key})
        the COSE Key Thumbprint (RFC 9679) of the signer's key as an AKP COSE_Key (RFC 9964 section 6):
        a3 01 07 03 38 30 20 59 07a0 || 1952 bytes of key

Every CBOR item is in deterministic encoding (RFC 8949 section 4.2.1), so there is exactly one byte string for one
object and a hash of the file names it.

A verifier here is strict, because each of these is what a hostile sender would vary:
  - the algorithm is read only from the protected header and must be -49; nothing else is ever tried (no
    algorithm confusion, no downgrade to a classical algorithm that happens to be in a header);
  - the unprotected header must be empty: a "kid" or "alg" put there is not ignored, the object is refused;
  - the protected header holds exactly alg, kid and typ, in deterministic encoding; an unknown or "crit" header is
    refused, not skipped;
  - kid must be the thumbprint of the key the verifier already trusts for this role; the key is never taken from
    the object;
  - the payload is attached (not nil) and the signature has the one length ML-DSA-65 signatures have.

The same private key also signs Aegis' older messages as label || 0x00 || message (common/mldsa.py sign()). Every
such label begins "aegis-"; a Sig_structure begins 0x84 0x6a "Signature1". No message of one kind is a message of
the other, so a signature made for one is never valid for the other.

Standard library only (the gateway's Python has nothing else); ML-DSA through common/mldsa.py.
"""
import hashlib

import cbor
import mldsa

# The one place the COSE numbers live. RFC 9964 (May 2026, formerly draft-ietf-cose-dilithium) registered them;
# IANA "COSE Algorithms" and "COSE Key Types" list them without a "temporary" mark.
ALG_ML_DSA_65 = -49
KTY_AKP = 7
KEY_KTY, KEY_KID, KEY_ALG, KEY_PUB = 1, 2, 3, -1
HDR_ALG, HDR_CRIT, HDR_KID, HDR_TYP = 1, 2, 4, 16
TAG_SIGN1 = 18
TYP_EAT_CWT = "application/eat+cwt"     # RFC 9782
KID_LEN = 32
MAX_SIGN1 = 16384                       # bytes of one object: evidence is about 3.8 kB, an endorsement about 5.9 kB
CONTEXT = "Signature1"


class Refused(ValueError):
    """The bytes are not an Aegis COSE_Sign1 from the expected signer. The text says why."""


def key_thumbprint(pk):
    """The COSE Key Thumbprint (RFC 9679, SHA-256) of an ML-DSA-65 public key as an AKP key (RFC 9964 section 6):
    the kid of everything that key signs."""
    if not isinstance(pk, (bytes, bytearray)) or len(pk) != mldsa.PK_LEN:
        raise ValueError("not an ML-DSA-65 public key")
    return hashlib.sha256(cbor.dumps({KEY_KTY: KTY_AKP, KEY_ALG: ALG_ML_DSA_65, KEY_PUB: bytes(pk)}, sort=True)).digest()


def cose_key(pk):
    """The public key as a COSE_Key map (AKP, RFC 9964 section 3), with its thumbprint as kid."""
    return {KEY_KTY: KTY_AKP, KEY_KID: key_thumbprint(pk), KEY_ALG: ALG_ML_DSA_65, KEY_PUB: bytes(pk)}


def key_from_cose(key):
    """The ML-DSA-65 public key of a COSE_Key map as cose_key() makes it; Refused for anything else."""
    if not (isinstance(key, dict) and set(key) == {KEY_KTY, KEY_KID, KEY_ALG, KEY_PUB}
            and _is_int(key[KEY_KTY], KTY_AKP) and _is_int(key[KEY_ALG], ALG_ML_DSA_65)
            and isinstance(key[KEY_PUB], bytes) and len(key[KEY_PUB]) == mldsa.PK_LEN):
        raise Refused("not an AKP COSE_Key for ML-DSA-65 {kty, kid, alg, pub}")
    if key[KEY_KID] != key_thumbprint(key[KEY_PUB]):
        raise Refused("the COSE_Key's kid is not its thumbprint")
    return key[KEY_PUB]


def _is_int(v, want):
    return type(v) is int and v == want


def protected_header(kid, typ=TYP_EAT_CWT):
    return cbor.dumps({HDR_ALG: ALG_ML_DSA_65, HDR_KID: bytes(kid), HDR_TYP: typ}, sort=True)


def sig_structure(protected, payload):
    """The bytes the signature covers (RFC 9052 section 4.4). For device evidence these are also the bytes whose
    SHA3-256 goes into the transcript (common/transcript.py: T1's token hash)."""
    return cbor.dumps([CONTEXT, bytes(protected), b"", bytes(payload)])


def assemble(protected, payload, signature):
    return cbor.dumps(cbor.Tag(TAG_SIGN1, [bytes(protected), {}, bytes(payload), bytes(signature)]))


def sign1(sk, pk, payload, typ=TYP_EAT_CWT):
    """A COSE_Sign1 over payload by the key pair (sk, pk)."""
    protected = protected_header(key_thumbprint(pk), typ)
    return assemble(protected, payload, mldsa.sign_raw(sk, sig_structure(protected, payload)))


class Sign1:
    """A decoded COSE_Sign1. Until verify1() returned it, nothing in it is authenticated."""

    def __init__(self, protected, payload, signature, kid, typ):
        self.protected, self.payload, self.signature, self.kid, self.typ = protected, payload, signature, kid, typ

    @property
    def tbs(self):
        return sig_structure(self.protected, self.payload)


def _decode(data, limit):
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise Refused("no COSE object")
    if len(data) > limit:
        raise Refused("the COSE object is larger than %d bytes" % limit)
    obj = cbor.loads(bytes(data))
    if not (isinstance(obj, cbor.Tag) and obj.tag == TAG_SIGN1):
        raise Refused("not a tagged COSE_Sign1 (tag 18)")
    obj = obj.value
    if not (isinstance(obj, list) and len(obj) == 4):
        raise Refused("COSE_Sign1 is not an array of 4")
    protected, unprotected, payload, signature = obj
    if not (isinstance(protected, bytes) and protected):
        raise Refused("the protected header is not a non-empty byte string")
    if not isinstance(unprotected, dict):
        raise Refused("the unprotected header is not a map")
    if unprotected:
        # nothing outside the signature is read, so nothing may be there to be read by someone else
        raise Refused("the unprotected header is not empty (%s)" % ", ".join(sorted(repr(k)[:16] for k in unprotected)))
    if not isinstance(payload, bytes):
        raise Refused("no attached payload")
    if not (isinstance(signature, bytes) and len(signature) == mldsa.SIG_LEN):
        raise Refused("the signature is not an ML-DSA-65 signature (%d bytes)" % mldsa.SIG_LEN)
    hdr = cbor.loads(protected)
    if not isinstance(hdr, dict):
        raise Refused("the protected header is not a map")
    if cbor.dumps(hdr, sort=True) != protected:
        raise Refused("the protected header is not in deterministic encoding")
    alg = hdr.get(HDR_ALG)
    if not _is_int(alg, ALG_ML_DSA_65):
        raise Refused("the algorithm is not ML-DSA-65 (%d): %r" % (ALG_ML_DSA_65, alg))
    if HDR_CRIT in hdr:
        raise Refused("a critical header parameter this verifier does not know")
    unknown = set(hdr) - {HDR_ALG, HDR_KID, HDR_TYP}
    if unknown:
        raise Refused("protected header parameters this verifier does not know: %s"
                      % ", ".join(sorted(repr(k)[:16] for k in unknown)))
    kid, typ = hdr.get(HDR_KID), hdr.get(HDR_TYP)
    if not (isinstance(kid, bytes) and len(kid) == KID_LEN):
        raise Refused("no kid of %d bytes in the protected header" % KID_LEN)
    if not isinstance(typ, str):
        raise Refused("no typ in the protected header")
    if cbor.dumps(cbor.Tag(TAG_SIGN1, [protected, {}, payload, signature])) != bytes(data):
        raise Refused("the COSE_Sign1 is not in deterministic encoding")
    return Sign1(protected, payload, signature, kid, typ)


def parse(data, limit=MAX_SIGN1):
    """Decode without checking the signature: for display, and to find out which key is named. Refused only."""
    try:
        return _decode(data, limit)
    except Refused:
        raise
    except Exception as e:  # noqa: BLE001 - CBORError, RecursionError, a type the checks above did not expect
        raise Refused("not a COSE_Sign1: %s: %s" % (type(e).__name__, e)) from None


def verify1(data, pk, typ=TYP_EAT_CWT, limit=MAX_SIGN1):
    """The Sign1 of data, if it is an Aegis COSE_Sign1 of that typ signed by pk; Refused otherwise. pk is a key the
    caller already trusts for the role; the object only says (kid) which key it claims."""
    s = parse(data, limit)
    if s.typ != typ:
        raise Refused("typ is %r, not %r" % (s.typ[:40], typ))
    if s.kid != key_thumbprint(pk):
        raise Refused("kid %s... is not the expected key (%s...)" % (s.kid.hex()[:16], key_thumbprint(pk).hex()[:16]))
    if not mldsa.verify_raw(pk, s.tbs, s.signature):
        raise Refused("the ML-DSA-65 signature does not verify")
    return s
