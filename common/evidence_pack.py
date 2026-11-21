# SPDX-License-Identifier: Apache-2.0
"""The verifier's signature on an evidence pack (docs/evidence-format.md, "The signed manifest").

`fleet.py export-evidence` writes manifest.json, which names every file of the pack by its SHA-256 and says when the
pack was made ("exported"). manifest.json is not signed. Beside it the verifier writes manifest.cose: an Aegis
COSE_Sign1 (common/cose.py: ML-DSA-65, RFC 9964) by its identity key, with typ
"application/vnd.aegis.evidence-pack+cbor" (no EAR, audit batch or signed policy has that typ, and each of their
readers requires its own, so none of them is ever taken for another), whose payload is

  { 1: "tag:github.com,2026:ismailalitech/aegis/evidence-pack/v1",
    2: endpoint   tstr              the entry's name, as in the manifest
    3: exported   uint              the verifier's clock when it made the pack: the manifest's "exported"
    4: manifest   bstr .size 32     SHA-256 of manifest.json, byte for byte as written
    5: result     bstr .size 32     SHA-256 of attestation-result.cbor
  }

So the export time, and through the manifest's hash every file of the pack, are the verifier's signed statement. A
map with another key, or without one of these, is refused.

Standard library only; ML-DSA through common/mldsa.py.
"""
import hashlib
import json

import cbor
import cose

FORMAT = "tag:github.com,2026:ismailalitech/aegis/evidence-pack/v1"
TYP = "application/vnd.aegis.evidence-pack+cbor"
SIGNATURE_FILE = "manifest.cose"
P_FORMAT, P_ENDPOINT, P_EXPORTED, P_MANIFEST, P_RESULT = 1, 2, 3, 4, 5
MAX_TIME = 1 << 40


class Refused(ValueError):
    """The bytes are not the verifier's signed statement of this pack. The text says why."""


def sign(sk, pk, endpoint, exported, manifest_bytes, result_bytes):
    """manifest.cose for a pack whose manifest.json is manifest_bytes."""
    c = {P_FORMAT: FORMAT, P_ENDPOINT: endpoint, P_EXPORTED: int(exported),
         P_MANIFEST: hashlib.sha256(manifest_bytes).digest(), P_RESULT: hashlib.sha256(result_bytes).digest()}
    return cose.sign1(sk, pk, cbor.dumps(c, sort=True), typ=TYP)


def _read(data, pk, manifest_bytes, result_bytes):
    s = cose.verify1(data, pk, typ=TYP)
    c = cbor.loads(s.payload)
    if not isinstance(c, dict) or cbor.dumps(c, sort=True) != s.payload:
        raise Refused("the pack's signed statement is not a map in deterministic encoding")
    if set(c) != {P_FORMAT, P_ENDPOINT, P_EXPORTED, P_MANIFEST, P_RESULT}:
        raise Refused("the pack's signed statement is not {format, endpoint, exported, manifest, result}")
    if c[P_FORMAT] != FORMAT:
        raise Refused("the pack's signed statement is not of format %s" % FORMAT)
    if not (isinstance(c[P_ENDPOINT], str) and 0 < len(c[P_ENDPOINT]) <= 64):
        raise Refused("the endpoint is not a name")
    if not (type(c[P_EXPORTED]) is int and 0 <= c[P_EXPORTED] < MAX_TIME):
        raise Refused("the export time is not a time")
    for k in (P_MANIFEST, P_RESULT):
        if not (isinstance(c[k], bytes) and len(c[k]) == 32):
            raise Refused("a hash in the pack's signed statement is not 32 bytes")
    if manifest_bytes is not None:
        if hashlib.sha256(manifest_bytes).digest() != c[P_MANIFEST]:
            raise Refused("manifest.json is not the manifest the verifier signed")
        man = json.loads(bytes(manifest_bytes).decode())
        if not (isinstance(man, dict) and man.get("endpoint") == c[P_ENDPOINT] and man.get("exported") == c[P_EXPORTED]):
            raise Refused("the signed endpoint or export time is not the manifest's")
    if result_bytes is not None and hashlib.sha256(result_bytes).digest() != c[P_RESULT]:
        raise Refused("attestation-result.cbor is not the result the verifier signed into the pack")
    return {"endpoint": c[P_ENDPOINT], "exported": c[P_EXPORTED], "manifest_sha256": c[P_MANIFEST],
            "result_sha256": c[P_RESULT], "kid": s.kid}


def read(data, pk, manifest_bytes=None, result_bytes=None):
    """The signed statement in manifest.cose, checked under the verifier key pk and, if given, against the manifest's
    bytes (its hash, and its "endpoint" and "exported") and the result's bytes: {"endpoint", "exported", "manifest_sha256", "result_sha256", "kid"}. Refused or
    cose.Refused, and nothing else, whatever the bytes are."""
    try:
        return _read(data, pk, manifest_bytes, result_bytes)
    except (Refused, cose.Refused):
        raise
    except Exception as e:  # noqa: BLE001 - CBORError, RecursionError, a type the checks did not expect
        raise Refused("not a signed pack statement: %s: %s" % (type(e).__name__, e)) from None
