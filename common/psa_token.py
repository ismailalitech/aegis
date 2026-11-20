# SPDX-License-Identifier: Apache-2.0
"""Verify a PSA initial attestation token (COSE_Sign1, ES256) from TF-M.

Standard library only. The ECDSA P-256 check is done by a pluggable function
`ecdsa_verify(pubkey_pem, message, der_signature) -> bool`; two are provided:
`verify_with_cryptography` (PC) and `verify_with_openssl_cli` (gateway, which
has the openssl tool but no Python crypto package).

Claim keys: TF-M can emit either the PSA profile 1 keys (-75000...) or the
newer EAT-based keys; both are mapped to the same names here.
"""
import hashlib
import os
import subprocess
import tempfile

import cbor

CLAIMS = {
    -75000: "profile", 265: "profile",
    -75001: "client_id", 2394: "client_id",
    -75002: "lifecycle", 2395: "lifecycle",
    -75003: "implementation_id", 2396: "implementation_id",
    -75004: "boot_seed", 2397: "boot_seed",
    -75005: "certification_ref", 2398: "certification_ref",
    -75006: "sw_components", 2399: "sw_components",
    -75008: "challenge", 10: "challenge",
    -75009: "instance_id", 256: "instance_id",
    -75010: "verification_service",
}
SWC = {1: "measurement_type", 2: "measurement_value", 4: "version", 5: "signer_id", 6: "measurement_desc"}


class TokenError(ValueError):
    pass


def raw_to_der(sig):
    if len(sig) != 64:
        raise TokenError("ES256 signature must be 64 bytes")

    def integer(b):
        b = b.lstrip(b"\x00") or b"\x00"
        if b[0] & 0x80:
            b = b"\x00" + b
        return b"\x02" + bytes([len(b)]) + b
    body = integer(sig[:32]) + integer(sig[32:])
    return b"\x30" + bytes([len(body)]) + body


def verify_with_cryptography(pub_pem, message, der_sig):
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    key = serialization.load_pem_public_key(pub_pem)
    try:
        key.verify(der_sig, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def verify_with_openssl_cli(pub_pem, message, der_sig):
    with tempfile.TemporaryDirectory() as d:
        paths = {}
        for name, data in (("pub.pem", pub_pem), ("msg", message), ("sig", der_sig)):
            paths[name] = os.path.join(d, name)
            with open(paths[name], "wb") as f:
                f.write(data)
        r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", paths["pub.pem"],
                            "-signature", paths["sig"], paths["msg"]], capture_output=True)
        return r.returncode == 0


def _guarded(what, fn, *args):
    """Run a decoding step; any failure (CBORError, TypeError, KeyError, RecursionError, ...) becomes TokenError,
    so a hostile token can only ever produce a refusal."""
    try:
        return fn(*args)
    except TokenError:
        raise
    except Exception as e:  # noqa: BLE001 - every decoding failure is a bad token
        raise TokenError("%s do not decode: %s: %s" % (what, type(e).__name__, e)) from None


def _envelope(token):
    obj = cbor.loads(token)
    if isinstance(obj, cbor.Tag):
        if obj.tag != 18:
            raise TokenError("not a COSE_Sign1 (tag %d)" % obj.tag)
        obj = obj.value
    if not (isinstance(obj, list) and len(obj) == 4):
        raise TokenError("COSE_Sign1 must be a 4-element array")
    protected, unprotected, payload, signature = obj
    if not (isinstance(protected, bytes) and isinstance(unprotected, dict) and isinstance(payload, bytes)
            and isinstance(signature, bytes)):
        raise TokenError("COSE_Sign1 fields have the wrong types")
    hdr = cbor.loads(protected) if protected else {}
    if not isinstance(hdr, dict):
        raise TokenError("protected header is not a map")
    if hdr.get(1) != -7:
        raise TokenError("algorithm is not ES256 (got %r)" % hdr.get(1))
    return protected, payload, signature


def envelope(token):
    """Decode only the COSE_Sign1 structure: (protected_bytes, payload_bytes, signature). The claims (payload) are not
    decoded. Raises TokenError only."""
    return _guarded("COSE_Sign1 fields", _envelope, token)


def decode_claims(payload):
    """Decode a claims payload to named claims. Raises TokenError only."""
    return _guarded("claims", lambda p: claims_from_map(cbor.loads(p)), payload)


def parse(token):
    """Return (protected_bytes, payload_bytes, signature, claims) WITHOUT checking the ES256 signature. Only for a
    token whose integrity was established another way (kind aegis-pq: an ML-DSA-65 signature over the whole token,
    verified first) or for display; otherwise use verify(), which checks the signature before decoding the claims.
    Raises TokenError only."""
    protected, payload, signature = envelope(token)
    return protected, payload, signature, decode_claims(payload)


def claims_from_map(raw):
    """PSA claim keys (numbers) to names, as in parse()."""
    if not isinstance(raw, dict):
        raise TokenError("claims are not a map")
    claims = {}
    for k, v in raw.items():
        name = CLAIMS.get(k, str(k))
        if name == "sw_components":
            if not isinstance(v, list) or not all(isinstance(c, dict) for c in v):
                raise TokenError("sw_components is not a list of maps")
            v = [{SWC.get(a, str(a)): b for a, b in comp.items()} for comp in v]
        claims[name] = v
    return claims


def parse_plain(token):
    """Claims of an unsigned CBOR claims map (kind aegis-linux: the ML-DSA-65 signature over it is the only
    signature, and it is checked by the caller)."""
    return decode_claims(token)


def verify(token, pub_pem, ecdsa_verify):
    """Check the signature, then decode and return the claims: unsigned claim bytes never reach the claims decoder.
    Raises TokenError on failure."""
    protected, payload, signature = envelope(token)
    sig_structure = cbor.dumps(["Signature1", protected, b"", payload])
    if not ecdsa_verify(pub_pem, sig_structure, raw_to_der(signature)):
        raise TokenError("token signature invalid")
    return decode_claims(payload)


def instance_id_for(pub_pem_der_point):
    """PSA instance ID = 0x01 || SHA-256(uncompressed public key point)."""
    return b"\x01" + hashlib.sha256(pub_pem_der_point).digest()


def summary(claims):
    out = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in claims.items() if k != "sw_components"}
    out["sw_components"] = [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in c.items()}
                            for c in claims.get("sw_components", [])]
    return out
