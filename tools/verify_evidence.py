#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Check Aegis evidence, attestation results and endorsements WITHOUT any Aegis code.

This file imports nothing from the Aegis repository. It uses three third-party packages:

  pycose         (1.1.0)  the COSE implementation: decodes the COSE_Sign1, resolves the algorithm from the protected
                          header and builds the Sig_structure (RFC 9052 section 4.4)
  cbor2          (5.x)    the CBOR codec (pycose 1.1.0 does not work with cbor2 6)
  cryptography   (>= 47, with OpenSSL >= 3.5)  ML-DSA-65 (FIPS 204) and SHA-2 / SHA-3

pycose 1.1.0 has no ML-DSA. RFC 9964 registers it for COSE as algorithm -49 with key type AKP (7); the class MlDsa65
below registers exactly that number with pycose (its documented extension point) and gives the verification to
OpenSSL. pycose's own verify_signature() only takes EC2, OKP and RSA key objects, so the signature is checked by
calling the registered algorithm on the Sig_structure pycose built.

It is a second, independent reading of docs/evidence-format.md: the claim numbers and rules below were written from
that document, not from common/eat.py.

  verify_evidence.py pack DIR [--verifier-key T] [--endorser-key T] [--device-key T] [--require-signed-export]
        an evidence pack (fleet.py export-evidence): every file against the manifest, the evidence under the device
        key, the attestation result under the verifier key, the endorsement under the endorser key, and that the
        three speak of the same device, quote and measurements. T is a key's COSE Key Thumbprint in hex, as you
        trust it; without it the keys of the pack are used and their thumbprints printed for you to compare.
        manifest.cose (Aegis 1.2) is the verifier's signature over manifest.json and the export time: checked under
        the verifier key, and a pack whose signature fails does not verify. A pack without it (exported by Aegis 1.1)
        verifies, and the report says "export time not signed"; --require-signed-export refuses such a pack. A pack
        whose result says aegis.pack-signed (every result of a 1.2 verifier) and has no manifest.cose is refused.
  verify_evidence.py evidence FILE --key KEY [--nonce HEX]
  verify_evidence.py result FILE --key KEY
  verify_evidence.py endorsement FILE --key KEY
        one object; KEY is a COSE_Key file (as in a pack's keys/) or a file with the ML-DSA-65 public key in hex.

Prints a JSON report; exit status 0 only if everything asked for verified.
"""
import argparse
import hashlib
import json
import os
import sys

import cbor2
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import mldsa
from pycose import headers
from pycose.algorithms import CoseAlgorithm
from pycose.messages import Sign1Message

ALG_ML_DSA_65 = -49         # RFC 9964
KTY_AKP = 7
HDR_TYP = 16                # RFC 9596
TYP = "application/eat+cwt"
PK_LEN, SIG_LEN = 1952, 3309
EVIDENCE_PROFILE = "tag:github.com,2026:ismailalitech/aegis/evidence/v1"
ENDORSEMENT_PROFILE = "tag:github.com,2026:ismailalitech/aegis/endorsement/v1"
EAR_PROFILE = "tag:ietf.org,2026:rats/ear#05"      # draft-ietf-rats-ear-06
TIERS = {2: "affirming", 32: "warning", 96: "contraindicated", 127: "incomplete"}
CATEGORIES = {0: "instance-identity", 1: "configuration", 2: "executables", 3: "file-system", 4: "hardware",
              5: "runtime-opaque", 6: "storage-opaque", 7: "sourced-data"}
PACK_TYP = "application/vnd.aegis.evidence-pack+cbor"
PACK_FORMAT = "tag:github.com,2026:ismailalitech/aegis/evidence-pack/v1"
PACK_SIGNATURE = "manifest.cose"
LEGACY_QUOTE_LABEL = b"aegis-endpoint-quote-v1"
LEGACY_ENDORSEMENT_LABEL = b"aegis-endorsement-v1"


@CoseAlgorithm.register_attribute()
class MlDsa65(CoseAlgorithm):
    """ML-DSA-65 for COSE (RFC 9964): pure ML-DSA, empty context, over the Sig_structure."""
    identifier = ALG_ML_DSA_65
    fullname = "ML_DSA_65"

    @classmethod
    def verify(cls, key, data, signature):
        try:
            mldsa.MLDSA65PublicKey.from_public_bytes(key).verify(signature, data)
            return True
        except (InvalidSignature, ValueError):
            return False


class Failed(Exception):
    pass


def need(cond, text):
    if not cond:
        raise Failed(text)


def thumbprint(pub):
    """COSE Key Thumbprint (RFC 9679, SHA-256) of an AKP key (RFC 9964 section 6)."""
    return hashlib.sha256(cbor2.dumps({1: KTY_AKP, 3: ALG_ML_DSA_65, -1: pub}, canonical=True)).digest()


def load_key(path):
    """An ML-DSA-65 public key from a COSE_Key file or a hex file."""
    with open(path, "rb") as f:
        data = f.read()
    try:
        pub = bytes.fromhex(data.decode().strip())
    except (UnicodeDecodeError, ValueError):
        key = cbor2.loads(data)
        need(isinstance(key, dict) and key.get(1) == KTY_AKP and key.get(3) == ALG_ML_DSA_65, "%s: not an AKP COSE_Key "
             "for ML-DSA-65" % path)
        pub = key.get(-1)
        need(key.get(2) in (None, thumbprint(pub)), "%s: the key's kid is not its thumbprint" % path)
    need(isinstance(pub, bytes) and len(pub) == PK_LEN, "%s: not an ML-DSA-65 public key" % path)
    return pub


def open_sign1(data, pub, what, typ=TYP):
    """Verify an Aegis COSE_Sign1 of that typ under pub; returns (claims, Sig_structure)."""
    try:
        raw = cbor2.loads(data)
        msg = Sign1Message.decode(data, allow_unknown_attributes=True)
    except Exception as e:  # noqa: BLE001 - whatever pycose or cbor2 make of bytes that are not a COSE_Sign1
        raise Failed("%s: not a COSE_Sign1: %s: %s" % (what, type(e).__name__, e)) from None
    # one object, one byte string: cbor2 reads past a complete item, and accepts lengths longer than they need be
    need(cbor2.dumps(raw) == data, "%s: not in deterministic encoding, or followed by other bytes" % what)
    prot = raw.value[0]
    need(isinstance(prot, bytes) and cbor2.dumps(cbor2.loads(prot), canonical=True) == prot,
         "%s: the protected header is not in deterministic encoding" % what)
    need(msg.phdr.get(headers.Algorithm) is MlDsa65, "%s: the protected algorithm is not ML-DSA-65 (-49)" % what)
    need(msg.uhdr == {}, "%s: the unprotected header is not empty" % what)
    need(set(msg.phdr) == {headers.Algorithm, headers.KID, HDR_TYP}, "%s: protected header is not {alg, kid, typ}" % what)
    need(msg.phdr[HDR_TYP] == typ, "%s: typ is not %s" % (what, typ))
    need(msg.phdr[headers.KID] == thumbprint(pub), "%s: kid is not the thumbprint of the given key" % what)
    need(isinstance(msg.payload, bytes), "%s: no attached payload" % what)
    need(len(msg.signature) == SIG_LEN, "%s: the signature is not %d bytes" % (what, SIG_LEN))
    tbs = msg._create_sig_structure()       # pycose's Sig_structure: ["Signature1", protected, h'', payload]
    need(MlDsa65.verify(pub, tbs, msg.signature), "%s: the ML-DSA-65 signature does not verify" % what)
    try:
        claims = cbor2.loads(msg.payload)
    except Exception as e:  # noqa: BLE001 - signed bytes that are not CBOR
        raise Failed("%s: the payload is not CBOR: %s: %s" % (what, type(e).__name__, e)) from None
    need(isinstance(claims, dict), "%s: the payload is not a claims map" % what)
    need(cbor2.dumps(claims, canonical=True) == msg.payload, "%s: the claims are not in deterministic encoding" % what)
    return claims, tbs


def read_components(value, what):
    need(isinstance(value, list) and value, "%s: measurements is not a non-empty list" % what)
    out = []
    for entry in value:
        need(isinstance(entry, list) and len(entry) == 2 and entry[0] == 295 and isinstance(entry[1], bytes),
             "%s: a measurement is not [295, bstr] (application/measured-component+cbor, RFC 10013)" % what)
        try:
            mc = cbor2.loads(entry[1])
        except Exception:  # noqa: BLE001
            raise Failed("%s: a measured component is not CBOR" % what) from None
        need(isinstance(mc, dict) and set(mc) <= {1, 2, 3} and {1, 2} <= set(mc), "%s: not a measured component" % what)
        need(cbor2.dumps(mc, canonical=True) == entry[1], "%s: a measured component is not in deterministic encoding" % what)
        cid, dig = mc[1], mc[2]
        need(isinstance(cid, list) and 1 <= len(cid) <= 2 and isinstance(cid[0], str) and 0 < len(cid[0]) <= 64,
             "%s: a component's id is not [name, [version]]" % what)
        need(isinstance(dig, list) and len(dig) == 2 and type(dig[0]) is int and dig[0] == 1
             and isinstance(dig[1], bytes) and len(dig[1]) == 32, "%s: a digest is not [1 (sha-256), 32 bytes]" % what)
        c = {"name": cid[0], "sha256": dig[1].hex()}
        if len(cid) > 1:
            need(isinstance(cid[1], list) and len(cid[1]) == 1 and isinstance(cid[1][0], str) and len(cid[1][0]) <= 64,
                 "%s: a component's version is not [text]" % what)
            c["version"] = cid[1][0]
        if 3 in mc:
            need(isinstance(mc[3], list) and len(mc[3]) == 1 and isinstance(mc[3][0], bytes) and 0 < len(mc[3][0]) <= 64,
                 "%s: a component's authorities is not [signer]" % what)
            c["signer"] = mc[3][0].hex()
        out.append(c)
    need(len(out) <= 16 and len({c["name"] for c in out}) == len(out), "%s: more than 16 components, or a name twice" % what)
    return out


def check_evidence(data, pub, nonce=None):
    claims, tbs = open_sign1(data, pub, "evidence")
    need(claims.get(265) == EVIDENCE_PROFILE, "evidence: eat_profile is not %s" % EVIDENCE_PROFILE)
    need(set(claims) <= {10, 256, 263, 265, 266, 273, 275, -82400}, "evidence: a claim outside the profile")
    need(isinstance(claims.get(10), bytes) and len(claims[10]) == 32, "evidence: eat_nonce is not 32 bytes")
    need(claims.get(256) == b"\x01" + hashlib.sha256(pub).digest(), "evidence: ueid is not 0x01 || SHA-256(device key)")
    need(type(claims.get(275)) is int and claims[275] == 1, "evidence: intuse is not 1")
    need((273 in claims) != (266 in claims), "evidence: needs measurements or a nested platform token, not both")
    need((273 in claims) == (-82400 in claims), "evidence: the platform profile goes with measurements, and only with them")
    need(-82400 not in claims or (isinstance(claims[-82400], str) and 0 < len(claims[-82400]) <= 64),
         "evidence: the platform profile is not a short text")
    need(263 not in claims or (type(claims[263]) is int and 0 <= claims[263] <= 4), "evidence: dbgstat is not 0 to 4")
    if nonce is not None:
        need(claims[10] == nonce, "evidence: eat_nonce is not the expected nonce")
    report = {"profile": claims[265], "eat_nonce": claims[10].hex(), "ueid": claims[256].hex(),
              "device_key_sha256": hashlib.sha256(pub).hexdigest(), "kid": thumbprint(pub).hex(),
              "signature": "ML-DSA-65 valid (COSE alg -49, RFC 9964)",
              # what transcript v2 binds a session to: T1 = SHA3-256("aegis-transcript-v2/quote" || nonce || this)
              "quote_sha3_256": hashlib.sha3_256(tbs).hexdigest()}
    if -82400 in claims:
        report["platform"] = claims[-82400]
    if 263 in claims:
        report["dbgstat"] = claims[263]
    if 273 in claims:
        report["measurements"] = read_components(claims[273], "evidence")
    else:
        sm = claims[266]
        need(isinstance(sm, dict) and set(sm) == {"platform"} and isinstance(sm["platform"], bytes)
             and len(sm["platform"]) > 2 and sm["platform"][:2] == b"\xd8\x3d",
             "evidence: submods is not {platform: CWT-tagged token}")
        tok = sm["platform"]
        try:
            inner = Sign1Message.decode(tok[2:], allow_unknown_attributes=True)
            inner_claims = cbor2.loads(inner.payload)
            need(isinstance(inner_claims, dict), "evidence: the nested platform token's payload is not a claims map")
        except Failed:
            raise
        except Exception as e:  # noqa: BLE001
            raise Failed("evidence: the nested platform token is not a COSE_Sign1: %s" % type(e).__name__) from None
        report["platform_token"] = {"sha256": hashlib.sha256(tok[2:]).hexdigest(),
                                    "claims": sorted(str(k) for k in inner_claims),
                                    "note": "the platform's own token (a PSA token on the STM32H573); its signature is "
                                            "checked with the platform's key, not here"}
    return report


def check_legacy_evidence(token, sig, pub):
    """The older format: a token and a detached ML-DSA-65 signature over "aegis-endpoint-quote-v1" || 0x00 || token."""
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(sig, LEGACY_QUOTE_LABEL + b"\x00" + token)
    except (InvalidSignature, ValueError):
        raise Failed("evidence (aegis-quote-v1): the ML-DSA-65 signature does not verify") from None
    return {"format": "aegis-quote-v1 (not COSE: label || 0x00 || token, detached signature)",
            "device_key_sha256": hashlib.sha256(pub).hexdigest(), "signature": "ML-DSA-65 valid",
            "quote_sha3_256": hashlib.sha3_256(token).hexdigest()}


def check_result(data, pub, now=None):
    claims, _ = open_sign1(data, pub, "attestation result")
    need(claims.get(265) == EAR_PROFILE, "attestation result: eat_profile is not %s" % EAR_PROFILE)
    need(isinstance(claims.get(6), int), "attestation result: no iat")
    vid, sm = claims.get(1004), claims.get(266)
    need(isinstance(vid, dict) and isinstance(vid.get(0), str) and isinstance(vid.get(1), str),
         "attestation result: no ear_verifier_id {developer, build}")
    need(isinstance(sm, dict) and len(sm) == 1, "attestation result: not exactly one appraisal in submods")
    label, a = next(iter(sm.items()))
    status = a.get(1000)
    need(status in TIERS and claims.get(1000) == status, "attestation result: ear_status is not a tier, or differs")
    need(isinstance(a.get(1001), dict) and a[1001], "attestation result: no trustworthiness vector")
    ver = a.get(1006) or {}
    need(isinstance(ver.get("aegis.admitted"), bool), "attestation result: no aegis.admitted")
    need(ver["aegis.admitted"] == (status in (2, 32)), "attestation result: %s with status %s" % (
        "admitted" if ver["aegis.admitted"] else "not admitted", TIERS[status]))
    if now is not None and 4 in claims:
        need(now < claims[4], "attestation result: expired at %d" % claims[4])
    att = a.get(1005) or {}
    report = {"profile": claims[265], "iat": claims[6], "exp": claims.get(4), "verifier": {"developer": vid[0], "build": vid[1]},
              "verifier_key_sha256": hashlib.sha256(pub).hexdigest(), "kid": thumbprint(pub).hex(),
              "signature": "ML-DSA-65 valid (COSE alg -49, RFC 9964)", "appraisal": label,
              "status": TIERS[status], "trustworthiness_vector": {str(k): v for k, v in a[1001].items()},
              "details": a.get(1010), "policy_ids": a.get(1003), "admitted": ver["aegis.admitted"],
              "endpoint": ver.get("aegis.endpoint"),
              "verifier_claims": {k: (v.hex() if isinstance(v, bytes) else v) for k, v in ver.items()}}
    if 10 in a:
        report["evidence_nonce"] = a[10].hex()
    if 273 in att:
        report["measurements"] = read_components(att[273], "attestation result")
    if 256 in att:
        report["ueid"] = att[256].hex()
    if 1014 in a:
        report["endorser_claims"] = {who: {str(k): v for k, v in c.items()} for who, c in a[1014].items()}
    if isinstance(a.get(1011), dict):
        report["vector_details"] = {CATEGORIES.get(k, str(k)): v for k, v in a[1011].items()}
    report.update(aegis_1_2_claims(ver))
    return report


def aegis_1_2_claims(ver):
    """The verifier claims Aegis 1.2 added (docs/evidence-format.md), each optional: a result without them is a 1.1
    result. One that is there and not of its form fails."""
    out = {}
    names = ("aegis.audit-log", "aegis.audit-batch", "aegis.audit-head")
    if any(k in ver for k in names):
        log, batch, head = (ver.get(k) for k in names)
        need(all(k in ver for k in names) and isinstance(log, bytes) and len(log) == 16 and type(batch) is int
             and 1 <= batch < 1 << 53 and isinstance(head, bytes) and len(head) == 32,
             "attestation result: aegis.audit-log, -batch and -head are not a log id (16 bytes), a batch number and "
             "a SHA-256 (32 bytes), all three")
        out["audit_head"] = {"log": log.hex(), "batch": batch, "sha256": head.hex(),
                             "meaning": "the verifier's audit log ended at this batch when the result was signed; "
                                        "check with tools/verify_audit.py log DIR --key KEY --result FILE"}
    if "aegis.warnings" in ver:
        warnings = ver["aegis.warnings"]
        need(isinstance(warnings, list) and 1 <= len(warnings) <= 8
             and all(isinstance(w, str) and 1 <= len(w) <= 300 for w in warnings),
             "attestation result: aegis.warnings is not 1 to 8 texts of 1 to 300 characters")
        out["warnings"] = warnings
    if "aegis.disabled" in ver:
        need(ver["aegis.disabled"] is True and ver.get("aegis.admitted") is False,
             "attestation result: aegis.disabled is not true, or comes with an admission")
        out["disabled"] = True
    if "aegis.pack-signed" in ver:
        need(ver["aegis.pack-signed"] is True, "attestation result: aegis.pack-signed is not true")
    out["pack_signed"] = "aegis.pack-signed" in ver
    if "aegis.min-trust" in ver:
        floor = ver["aegis.min-trust"]
        need(isinstance(floor, str) and 1 <= len(floor) <= 64, "attestation result: aegis.min-trust is not a label")
        out["min_trust"] = floor
    return out


def check_endorsement(data, pub):
    if data[:1] != b"\xd2":
        return check_legacy_endorsement(data, pub)
    claims, _ = open_sign1(data, pub, "endorsement")
    need(claims.get(265) == ENDORSEMENT_PROFILE, "endorsement: eat_profile is not %s" % ENDORSEMENT_PROFILE)
    need(claims.get(-82408) == hashlib.sha256(pub).digest(), "endorsement: names another endorser key")
    key = (claims.get(8) or {}).get(1)
    need(isinstance(key, dict) and key.get(1) == KTY_AKP and key.get(3) == ALG_ML_DSA_65
         and isinstance(key.get(-1), bytes) and len(key[-1]) == PK_LEN, "endorsement: cnf is not an ML-DSA-65 COSE_Key")
    report = {"format": "aegis-endorsement-cose-v1", "profile": claims[265], "endorser": claims.get(1),
              "device": claims.get(2), "issued": claims.get(6), "expires": claims.get(4),
              "endorser_key_sha256": hashlib.sha256(pub).hexdigest(), "kid": thumbprint(pub).hex(),
              "signature": "ML-DSA-65 valid (COSE alg -49, RFC 9964)",
              "device_key_sha256": hashlib.sha256(key[-1]).hexdigest(), "device_key_thumbprint": thumbprint(key[-1]).hex(),
              "kind": claims.get(-82401), "platform": claims.get(-82400), "device_state": claims.get(-82403),
              "measurements": read_components(claims.get(273), "endorsement"),
              "evidence_nonce": claims[10].hex(), "quote_sha3_256": claims[-82404].hex()}
    report["_device_key"] = key[-1]
    return report


def check_legacy_endorsement(data, pub):
    """aegis-endorsement-v1: JSON, ML-DSA-65 over "aegis-endorsement-v1" || 0x00 || canonical JSON of the body."""
    rec = json.loads(data.decode())
    need(rec.get("format") == "aegis-endorsement-v1", "endorsement: unknown format")
    body = rec["body"]
    msg = LEGACY_ENDORSEMENT_LABEL + b"\x00" + json.dumps(body, sort_keys=True, separators=(",", ":")).encode()
    try:
        mldsa.MLDSA65PublicKey.from_public_bytes(pub).verify(bytes.fromhex(rec["sig"]), msg)
    except (InvalidSignature, ValueError):
        raise Failed("endorsement (aegis-endorsement-v1): the ML-DSA-65 signature does not verify") from None
    need(body.get("endorser_pk_sha256") == hashlib.sha256(pub).hexdigest(), "endorsement: names another endorser key")
    return {"format": "aegis-endorsement-v1 (JSON, not COSE)", "endorser": body.get("endorser"),
            "device": body.get("device"), "issued": body.get("issued"), "expires": body.get("expires"),
            "endorser_key_sha256": hashlib.sha256(pub).hexdigest(), "signature": "ML-DSA-65 valid",
            "device_key_sha256": body.get("device_pk_sha256"), "kind": body.get("kind"), "platform": body.get("profile"),
            "device_state": body.get("device_state"),
            "measurements": [dict({"name": m["type"], "sha256": m["measurement_value"]},
                                  **({"signer": m["signer_id"]} if "signer_id" in m else {}))
                             for m in body.get("measurements", [])],
            "quote_sha3_256": body.get("evidence", {}).get("token_sha3_256")}


def check_pack_signature(d, man, man_bytes, result_bytes, verifier_pub, require, result_says=False):
    """manifest.cose: the verifier's signature over manifest.json and the export time. Returns the report's
    "export_time". result_says: the signed result carries aegis.pack-signed (its verifier signs every pack manifest),
    so a pack without manifest.cose had it removed."""
    path = os.path.join(d, PACK_SIGNATURE)
    named = man.get("signed_manifest")
    need(named in (None, PACK_SIGNATURE), "pack: the manifest names a signature file other than %s" % PACK_SIGNATURE)
    if not os.path.exists(path):
        need(named is None, "pack: the manifest names %s and the pack has none" % PACK_SIGNATURE)
        need(not result_says, "pack: the result says its verifier signs the manifest of every pack "
                              "(aegis.pack-signed) and the pack has no %s: it was removed" % PACK_SIGNATURE)
        need(not require, "pack: the export time is not signed (no %s: a pack from before Aegis 1.2, or one whose "
                          "signature was removed), and --require-signed-export was given" % PACK_SIGNATURE)
        return {"time": man.get("exported"), "signed": False,
                "note": "export time not signed: manifest.json and its \"exported\" are not signed in this pack "
                        "(a pack from before Aegis 1.2, or one whose %s was removed); the files are still bound by "
                        "what the signed result names" % PACK_SIGNATURE}
    with open(path, "rb") as f:
        data = f.read()
    c, _ = open_sign1(data, verifier_pub, "pack signature (%s)" % PACK_SIGNATURE, PACK_TYP)
    need(set(c) == {1, 2, 3, 4, 5}, "pack signature: the claims are not {1, 2, 3, 4, 5}")
    need(c[1] == PACK_FORMAT, "pack signature: the format is not %s" % PACK_FORMAT)
    need(isinstance(c[2], str) and 0 < len(c[2]) <= 64 and type(c[3]) is int and 0 <= c[3] < 1 << 40
         and isinstance(c[4], bytes) and len(c[4]) == 32 and isinstance(c[5], bytes) and len(c[5]) == 32,
         "pack signature: endpoint, time or hashes are not of their form")
    need(c[4] == hashlib.sha256(man_bytes).digest(), "pack signature: manifest.json is not the manifest the verifier "
                                                     "signed")
    need(c[5] == hashlib.sha256(result_bytes).digest(), "pack signature: the result is not the one the verifier "
                                                        "signed into the pack")
    need(c[2] == man.get("endpoint"), "pack signature: it is for another endpoint than the manifest's")
    need(c[3] == man.get("exported"), "pack signature: the signed export time is not the manifest's")
    return {"time": c[3], "signed": True,
            "note": "the export time and manifest.json are signed by the verifier key (%s, typ %s)" % (
                PACK_SIGNATURE, PACK_TYP)}


def check_pack(d, trust, require_signed_export=False):
    with open(os.path.join(d, "manifest.json"), "rb") as f:
        man_bytes = f.read()
    man = json.loads(man_bytes.decode())
    need(isinstance(man, dict), "pack: the manifest is not an object")
    need(man.get("format") == "aegis-evidence-pack-v1", "pack: unknown manifest format")
    files = {}
    for name, digest in man["files"].items():
        need(os.path.normpath(name) == name and not os.path.isabs(name) and not name.startswith(".."),
             "pack: a file name leaves the pack")
        with open(os.path.join(d, name), "rb") as f:
            files[name] = f.read()
        need(hashlib.sha256(files[name]).hexdigest() == digest, "pack: %s is not the file the manifest names" % name)
    report = {"endpoint": man["endpoint"], "policy_sha256": man["policy_sha256"], "keys": {}, "checks": []}
    keys = {}
    for role in ("verifier", "device", "endorser"):
        path = os.path.join(d, "keys", role + ".cosekey")
        if "keys/%s.cosekey" % role in files:
            keys[role] = load_key(path)
            tp = thumbprint(keys[role]).hex()
            if trust.get(role):
                need(tp == trust[role].lower(), "pack: the %s key is not the one you trust (%s)" % (role, tp))
            report["keys"][role] = {"thumbprint": tp, "sha256": hashlib.sha256(keys[role]).hexdigest(),
                                    "trusted": "given on the command line" if trust.get(role) else
                                    "NOT CHECKED: taken from the pack; compare the thumbprint with the key you trust"}
    need("verifier" in keys, "pack: no verifier key")
    need("attestation-result.cbor" in files, "pack: no attestation result")
    res = report["attestation_result"] = check_result(files["attestation-result.cbor"], keys["verifier"])
    need(res["endpoint"] == man["endpoint"], "pack: the result is for another endpoint")
    ev = None
    if "evidence.cbor" in files:
        need("device" in keys, "pack: no device key")
        ev = report["evidence"] = check_evidence(files["evidence.cbor"], keys["device"])
    elif "evidence.token" in files and "evidence.sig" in files:
        need("device" in keys, "pack: no device key")
        ev = report["evidence"] = check_legacy_evidence(files["evidence.token"], files["evidence.sig"], keys["device"])
    elif "evidence.token" in files:
        report["evidence"] = {"format": "psa-token (COSE_Sign1, ES256): not checked here; use a PSA token verifier "
                                        "with keys/device-iak.pem"}
    else:
        report["evidence"] = None           # the endpoint did not answer: the result says so
    vc = res["verifier_claims"]

    def same(what, a, b):
        need(a == b, "pack: %s differ between the files (%r, %r)" % (what, a, b))
        report["checks"].append("%s agree" % what)
    # the manifest is not signed: a file missing from the pack is caught by what the signed result names
    if vc.get("aegis.evidence-sha256") is not None:
        need("evidence.cbor" in files or "evidence.token" in files,
             "pack: the result names evidence (aegis.evidence-sha256) and the pack has none")
        need(vc.get("aegis.evidence-format") != "aegis-quote-v1" or "evidence.sig" in files,
             "pack: the result names evidence of the older quote and the pack has no evidence.sig")
    for name in ("evidence.cbor", "evidence.token"):
        if name in files:
            same("the evidence file and the result's evidence hash", hashlib.sha256(files[name]).hexdigest(),
                 vc.get("aegis.evidence-sha256"))
    if ev is not None:
        same("the quote hash (transcript v2) in evidence and result", ev["quote_sha3_256"], vc.get("aegis.quote-sha3-256"))
        same("the device key in evidence and result", ev["device_key_sha256"], vc.get("aegis.device-key-sha256"))
        if "eat_nonce" in ev:
            same("the nonce in evidence and result", ev["eat_nonce"], res.get("evidence_nonce"))
        if "measurements" in ev and "measurements" in res:
            same("the measurements in evidence and result", [(m["name"], m["sha256"]) for m in ev["measurements"]],
                 [(m["name"], m["sha256"]) for m in res["measurements"]])
    if man.get("policy_id"):
        need(man["policy_id"] in (res["policy_ids"] or []), "pack: the result was reached under another policy")
        report["checks"].append("the result names the manifest's policy")
    if "policy.json" in files:
        same("the policy file and the manifest's policy hash", hashlib.sha256(files["policy.json"]).hexdigest(),
             man["policy_now_sha256"])
    if res.get("endorser_claims") or trust.get("endorser"):
        need("endorsement.cbor" in files or "endorsement.json" in files,
             "pack: the result names an endorsement, or an endorser key was given, and the pack has no endorsement")
    for name in ("endorsement.cbor", "endorsement.json"):
        if name in files:
            need("endorser" in keys, "pack: no endorser key")
            en = report["endorsement"] = check_endorsement(files[name], keys["endorser"])
            en.pop("_device_key", None)
            need(en["device"] == man["endpoint"], "pack: the endorsement is for another device")
            if "device" in keys:
                same("the endorsed key and the device key", en["device_key_sha256"],
                     hashlib.sha256(keys["device"]).hexdigest())
            if "measurements" in res and res["admitted"]:
                same("the endorsed measurements and the result's", sorted((m["name"], m["sha256"]) for m in en["measurements"]),
                     sorted((m["name"], m["sha256"]) for m in res["measurements"]))
    # last, so that each finding above is reported as itself: a pack whose manifest.json was edited to fit is
    # then caught here, by the verifier's signature over it
    report["export_time"] = check_pack_signature(d, man, man_bytes, files["attestation-result.cbor"], keys["verifier"],
                                                 require_signed_export, res["pack_signed"])
    return report


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("what", choices=["pack", "evidence", "result", "endorsement"])
    ap.add_argument("path")
    ap.add_argument("--key", help="evidence, result, endorsement: the signer's public key (COSE_Key or hex file)")
    ap.add_argument("--nonce", help="evidence: the challenge the evidence must answer, hex")
    for role in ("verifier", "endorser", "device"):
        ap.add_argument("--%s-key" % role, help="pack: the COSE Key Thumbprint (hex) of the %s key you trust" % role)
    ap.add_argument("--require-signed-export", action="store_true",
                    help="pack: refuse a pack whose export time is not signed (no manifest.cose)")
    a = ap.parse_args(argv)
    try:
        if a.what == "pack":
            report = check_pack(a.path, {"verifier": a.verifier_key, "endorser": a.endorser_key, "device": a.device_key},
                                a.require_signed_export)
        else:
            if not a.key:
                ap.error("%s needs --key" % a.what)
            pub = load_key(a.key)
            with open(a.path, "rb") as f:
                data = f.read()
            if a.what == "evidence":
                report = check_evidence(data, pub, bytes.fromhex(a.nonce) if a.nonce else None)
            elif a.what == "result":
                report = check_result(data, pub)
            else:
                report = check_endorsement(data, pub)
                report.pop("_device_key", None)
    except Failed as e:
        print(json.dumps({"verified": False, "reason": str(e)}, indent=1))
        return 1
    except Exception as e:  # noqa: BLE001 - whatever hostile bytes provoke in this file, cbor2 or pycose: not verified
        print(json.dumps({"verified": False, "reason": "not readable: %s: %s" % (type(e).__name__, str(e)[:200])}, indent=1))
        return 1
    print(json.dumps(dict(report, verified=True), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
