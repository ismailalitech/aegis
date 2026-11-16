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


def parse(token):
    """Return (protected_bytes, payload_bytes, signature, claims) without checking anything."""
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
    raw = cbor.loads(payload)
    if not isinstance(raw, dict):
        raise TokenError("claims are not a map")
    claims = {}
    for k, v in raw.items():
        name = CLAIMS.get(k, str(k))
        if name == "sw_components":
            v = [{SWC.get(a, str(a)): b for a, b in comp.items()} for comp in v]
        claims[name] = v
    return protected, payload, signature, claims


def verify(token, pub_pem, ecdsa_verify):
    """Check the signature; return the claims. Raises TokenError on failure."""
    protected, payload, signature, claims = parse(token)
    sig_structure = cbor.dumps(["Signature1", protected, b"", payload])
    if not ecdsa_verify(pub_pem, sig_structure, raw_to_der(signature)):
        raise TokenError("token signature invalid")
    return claims


def instance_id_for(pub_pem_der_point):
    """PSA instance ID = 0x01 || SHA-256(uncompressed public key point)."""
    return b"\x01" + hashlib.sha256(pub_pem_der_point).digest()


def summary(claims):
    out = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in claims.items() if k != "sw_components"}
    out["sw_components"] = [{k: (v.hex() if isinstance(v, bytes) else v) for k, v in c.items()}
                            for c in claims.get("sw_components", [])]
    return out
