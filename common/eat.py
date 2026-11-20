# SPDX-License-Identifier: Apache-2.0
"""The claims inside Aegis' COSE objects (common/cose.py): device evidence as an EAT (RFC 9711), and the verifier's
attestation result as an EAR (draft-ietf-rats-ear-06). docs/evidence-format.md is the specification; this file is
its one implementation on the verifier's side, and the claim numbers live here and nowhere else in Python.

Evidence (profile EVIDENCE_PROFILE), signed by the device's ML-DSA-65 identity key:

  10    eat_nonce      bstr .size 32     the verifier's challenge
  256   ueid           bstr .size 33     0x01 (RAND) || SHA-256(the device's public key): the key's old fingerprint
  263   dbgstat        0..4              optional: only from a port whose secure world reads the debug state itself
  265   eat_profile    EVIDENCE_PROFILE
  273   measurements   [+ [295, bstr .cbor measured-component]]     (RFC 10013), or
  266   submods        {"platform": bstr .cbor #6.61(token)}        the platform's own token, nested (RFC 9711
                                                                    section 4.2.18): TF-M's PSA token on the STM32
  275   intuse         1 (generic)
  -82400 platform      text              the Aegis platform profile the policy pins ("aegis-rw612-tfm-v1", ...);
                                         with measurements, and only with them

  measured-component = {1: [name, [version]], 2: [1 (sha-256), digest .size 32], ? 3: [signer]}
  "authorities" (3) is the component's signer, where the platform knows one; "flags" (4) is not used.

Exactly one of 273 and 266. A claim that is not in this list is refused, not skipped: a later version cannot add a
restriction that this verifier would silently ignore. Claims maps are in deterministic encoding.

Private claims use keys below -65536, the CWT registry's private-use range; -82400 to -82499 is the block this
project uses, and a number in it means something only under one of the two Aegis profiles.

Standard library only.
"""
import hashlib

import cbor
import cose

# ---- names and numbers ----------------------------------------------------------------------------------------------
EVIDENCE_PROFILE = "tag:github.com,2026:ismailalitech/aegis/evidence/v1"
ENDORSEMENT_PROFILE = "tag:github.com,2026:ismailalitech/aegis/endorsement/v1"
# draft-ietf-rats-ear-06 (20 November 2026), section 3. Not an RFC: the profile string and the claim numbers 1000 to
# 1015 below are that draft's and may change before publication. They are used through these constants only.
EAR_PROFILE = "tag:ietf.org,2026:rats/ear#05"
EAR_DRAFT = "draft-ietf-rats-ear-06"

ISS, SUB, EXP, IAT, CNF, NONCE = 1, 2, 4, 6, 8, 10                  # RFC 8392, RFC 8747, RFC 9711
UEID, DBGSTAT, PROFILE, SUBMODS, MEASUREMENTS, INTUSE = 256, 263, 265, 266, 273, 275     # RFC 9711
CNF_COSE_KEY = 1                                                    # RFC 8747 section 3.2
P_PLATFORM = -82400         # text: the Aegis platform profile
P_KIND = -82401             # text: the policy kind (endorsements)
P_SERIAL = -82402           # text (endorsements)
P_DEVICE_STATE = -82403     # text: "development" | "closed", the operator's statement (endorsements)
P_EVIDENCE_HASH = -82404    # bstr .size 32: SHA3-256 of the appraised quote's signed bytes (endorsements)
P_NOTES = -82405            # text (endorsements)
P_INSTANCE = -82406         # bstr: an instance ID that is not a UEID (endorsements of devices with the old claims)
P_FORMAT = -82407           # uint: the claims' version, 1 (endorsements)

CF_MEASURED_COMPONENT = 295     # CoAP Content-Format of application/measured-component+cbor (RFC 10013)
MC_ID, MC_DIGEST, MC_AUTHORITIES, MC_FLAGS, MC_RAW = 1, 2, 3, 4, 5
NI_SHA256 = 1                   # IANA "Named Information Hash Algorithm Registry"
UEID_RAND = 0x01
INTUSE_GENERIC = 1
CWT_TAG = 61
SUBMOD_PLATFORM = "platform"
MAX_COMPONENTS = 16

EAR_STATUS, EAR_VECTOR, EAR_RAW_EVIDENCE, EAR_POLICY_IDS, EAR_VERIFIER_ID = 1000, 1001, 1002, 1003, 1004
EAR_ATTESTER_CLAIMS, EAR_VERIFIER_CLAIMS, EAR_STATUS_DETAILS, EAR_VECTOR_DETAILS = 1005, 1006, 1010, 1011
EAR_ENDORSER_CLAIMS = 1014
VERIFIER_DEVELOPER, VERIFIER_BUILD = 0, 1
# AR4SI (draft-ietf-rats-ar4si-11): the tiers, and the two categories Aegis has something to say about
AFFIRMING, WARNING, CONTRAINDICATED, INCOMPLETE = 2, 32, 96, 127
TIER_NAMES = {AFFIRMING: "affirming", WARNING: "warning", CONTRAINDICATED: "contraindicated", INCOMPLETE: "incomplete"}
V_INSTANCE_IDENTITY, V_EXECUTABLES = 0, 2
II_RECOGNIZED = 2            # AR4SI: recognized, not known to be compromised (here: the key is endorsed)
II_NOT_RECOGNIZED = 97       # AR4SI: not recognized, and it should be (an endorsement is required and was refused)
CRYPTO_FAILED = 99           # AR4SI, any category: cryptographic validation of the evidence failed
# AR4SI leaves -33 to -96 to "a non-standard reason for the warning". Aegis' two:
II_FIRST_USE = -33           # the key was pinned on first use: no endorser says which device holds it
II_SHARED_KEY = -34          # a development profile whose key is the same on every chip
EX_BOOT_APPROVED = 3         # AR4SI: only recognized, approved executables were loaded during boot
EX_UNRECOGNIZED = 33         # AR4SI: executables that are not recognized
EX_SELF_MEASURED = -35       # non-standard warning: the approved set, but measured by the measured software itself
VERIFIER_DEVELOPER_NAME = "https://github.com/ismailalitech/aegis"
VERIFIER_BUILD_NAME = "aegis-fleet-verifier 1 (evidence eat-cose-v1, results %s)" % EAR_DRAFT


class Refused(ValueError):
    """The claims are not the ones of the profile. The text says why."""


def _guard(what, fn, *args):
    try:
        return fn(*args)
    except Refused:
        raise
    except Exception as e:  # noqa: BLE001 - whatever a hostile claims set provokes is a refusal
        raise Refused("%s not usable: %s: %s" % (what, type(e).__name__, e)) from None


def _is_uint(v, limit=1 << 40):
    return type(v) is int and 0 <= v < limit


def _is_text(v, limit=256):
    return isinstance(v, str) and 0 < len(v) <= limit


def claims_map(payload, what="claims"):
    """The claims map in payload; Refused unless it is one CBOR map in deterministic encoding."""
    c = cbor.loads(payload)
    if not isinstance(c, dict):
        raise Refused("the %s are not a map" % what)
    if cbor.dumps(c, sort=True) != bytes(payload):
        raise Refused("the %s are not in deterministic encoding" % what)
    return c


def ueid_for(pk):
    """The UEID of a device: type RAND, the SHA-256 of its ML-DSA-65 public key (the hash every Aegis policy and
    record already names the key by)."""
    return bytes([UEID_RAND]) + hashlib.sha256(pk).digest()


# ---- measured components (RFC 10013) --------------------------------------------------------------------------------

def measured_component(name, digest, version=None, signer=None):
    """One entry of the measurements claim: [295, bstr .cbor measured-component]."""
    mc = {MC_ID: [name, [version]] if version is not None else [name], MC_DIGEST: [NI_SHA256, bytes(digest)]}
    if signer is not None:
        mc[MC_AUTHORITIES] = [bytes(signer)]
    return [CF_MEASURED_COMPONENT, cbor.dumps(mc, sort=True)]


def _component(entry):
    """A measurements entry as the verifier's component: PSA's names, which the policy code already uses."""
    if not (isinstance(entry, list) and len(entry) == 2 and type(entry[0]) is int and entry[0] == CF_MEASURED_COMPONENT
            and isinstance(entry[1], bytes)):
        raise Refused("a measurement is not [295, bstr] (application/measured-component+cbor)")
    mc = claims_map(entry[1], "measured component")
    if set(mc) - {MC_ID, MC_DIGEST, MC_AUTHORITIES} or not {MC_ID, MC_DIGEST} <= set(mc):
        # flags (4) and raw measurements (5) are not part of this profile
        raise Refused("a measured component is not {id, digested-measurement[, authorities]}")
    cid, dig = mc[MC_ID], mc[MC_DIGEST]
    if not (isinstance(cid, list) and 1 <= len(cid) <= 2 and _is_text(cid[0], 64)):
        raise Refused("a measured component's id is not [name, [version]]")
    out = {"measurement_type": cid[0]}
    if len(cid) == 2:
        if not (isinstance(cid[1], list) and len(cid[1]) == 1 and isinstance(cid[1][0], str) and len(cid[1][0]) <= 64):
            raise Refused("a measured component's version is not [text]")
        out["version"] = cid[1][0]
    if not (isinstance(dig, list) and len(dig) == 2 and type(dig[0]) is int and dig[0] == NI_SHA256
            and isinstance(dig[1], bytes) and len(dig[1]) == 32):
        raise Refused("a measured component's digest is not [1 (sha-256), 32 bytes]")
    out["measurement_value"] = dig[1]
    if MC_AUTHORITIES in mc:
        a = mc[MC_AUTHORITIES]
        if not (isinstance(a, list) and len(a) == 1 and isinstance(a[0], bytes) and 0 < len(a[0]) <= 64):
            raise Refused("a measured component's authorities is not [one signer]")
        out["signer_id"] = a[0]
    return out


def components(value):
    """The measurements claim as a list of components; Refused unless it is 1 to 16 measured components, one per
    name."""
    if not (isinstance(value, list) and 0 < len(value) <= MAX_COMPONENTS):
        raise Refused("measurements is not a list of 1 to %d measured components" % MAX_COMPONENTS)
    out = [_component(e) for e in value]
    if len({c["measurement_type"] for c in out}) != len(out):
        raise Refused("two measured components of one name")
    return out


def measurements_claim(comps):
    """The measurements claim for components in the verifier's form ({measurement_type, measurement_value, ...}, bytes
    or hex)."""
    def raw(v):
        return bytes.fromhex(v) if isinstance(v, str) else v
    return [measured_component(c["measurement_type"], raw(c["measurement_value"]), c.get("version"),
                               raw(c["signer_id"]) if c.get("signer_id") else None) for c in comps]


# ---- evidence -------------------------------------------------------------------------------------------------------

_EVIDENCE_KEYS = {NONCE, UEID, DBGSTAT, PROFILE, SUBMODS, MEASUREMENTS, INTUSE, P_PLATFORM}
_EVIDENCE_REQUIRED = {NONCE, UEID, PROFILE, INTUSE}


def evidence_payload(challenge, pk, comps=None, platform=None, platform_token=None, dbgstat=None):
    """The evidence claims as a device makes them (sdk/src/aegis_proto.c, make_eat): for the Python provers and the
    tests. comps: [(name, digest, version)]."""
    c = {NONCE: bytes(challenge), UEID: ueid_for(pk), PROFILE: EVIDENCE_PROFILE, INTUSE: INTUSE_GENERIC}
    if comps is not None:
        c[MEASUREMENTS] = [measured_component(n, d, v) for n, d, v in comps]
    if platform_token is not None:
        # tag 61 before the token's own bytes, as a device does it: the token is never decoded and encoded again
        c[SUBMODS] = {SUBMOD_PLATFORM: bytes([0xD8, CWT_TAG]) + bytes(platform_token)}
    if platform is not None:
        c[P_PLATFORM] = platform
    if dbgstat is not None:
        c[DBGSTAT] = dbgstat
    return cbor.dumps(c, sort=True)


def _read_evidence(payload, pk):
    c = claims_map(payload, "evidence claims")
    unknown = set(c) - _EVIDENCE_KEYS
    if unknown:
        raise Refused("evidence claims this verifier does not know: %s" % ", ".join(sorted(repr(k)[:16] for k in unknown)))
    missing = _EVIDENCE_REQUIRED - set(c)
    if missing:
        raise Refused("the evidence lacks claim %s" % ", ".join(str(k) for k in sorted(missing)))
    if c[PROFILE] != EVIDENCE_PROFILE:
        raise Refused("eat_profile is not %s" % EVIDENCE_PROFILE)
    if not (isinstance(c[NONCE], bytes) and len(c[NONCE]) == 32):
        raise Refused("eat_nonce is not 32 bytes")
    if c[UEID] != ueid_for(pk):
        raise Refused("ueid is not that of the key that signed the evidence")
    if not (type(c[INTUSE]) is int and c[INTUSE] == INTUSE_GENERIC):
        raise Refused("intuse is not 1 (generic)")
    if DBGSTAT in c and not (type(c[DBGSTAT]) is int and 0 <= c[DBGSTAT] <= 4):
        raise Refused("dbgstat is not 0 to 4")
    if P_PLATFORM in c and not _is_text(c[P_PLATFORM], 64):
        raise Refused("the platform profile is not a short text")
    if (MEASUREMENTS in c) == (SUBMODS in c):
        raise Refused("the evidence must carry measurements or a platform token, and not both")
    if (MEASUREMENTS in c) != (P_PLATFORM in c):
        raise Refused("the platform profile goes with measurements, and only with them")
    out = {"nonce": c[NONCE], "ueid": c[UEID], "platform": c.get(P_PLATFORM), "dbgstat": c.get(DBGSTAT),
           "components": None, "platform_token": None}
    if MEASUREMENTS in c:
        out["components"] = components(c[MEASUREMENTS])
    else:
        sm = c[SUBMODS]
        if not (isinstance(sm, dict) and set(sm) == {SUBMOD_PLATFORM} and isinstance(sm[SUBMOD_PLATFORM], bytes)):
            raise Refused('submods is not {"platform": nested token}')
        tok = sm[SUBMOD_PLATFORM]
        # a nested CBOR token is tagged as a CWT (RFC 9711 section 4.2.18.3); the platform's COSE_Sign1 follows
        if not (len(tok) > 2 and tok[0] == 0xD8 and tok[1] == CWT_TAG):
            raise Refused("the nested platform token is not tagged as a CWT (tag 61)")
        out["platform_token"] = tok[2:]
    return out


def read_evidence(payload, pk):
    """The evidence claims of a verified COSE payload, checked against the profile: {"nonce", "ueid", "platform",
    "dbgstat", "components" or "platform_token"}. pk is the key the signature was verified with. Refused only."""
    return _guard("evidence claims", _read_evidence, payload, pk)


# ---- attestation results (EAR) --------------------------------------------------------------------------------------

def policy_id(policy_bytes):
    """An appraisal policy's name: the "ni" URI (RFC 6920) of the policy file's SHA-256."""
    import base64
    return "ni:///sha-256;" + base64.urlsafe_b64encode(hashlib.sha256(policy_bytes).digest()).rstrip(b"=").decode()


def appraisal(verdict, facts):
    """(status, vector, vector details) for one verdict of the fleet verifier. facts is what attest() noted on the
    way (fleet.py): "stage" (how far the appraisal got), "signature" (None, False, True), "components_ok".

    The rules, which docs/evidence-format.md states for a relying party:
      instance-identity   2 endorsed key; -33 key pinned without an endorsement; -34 a development key every chip shares;
                          97 an endorsement is required and was refused; 99 the signature does not verify
      executables         3 every component is an allowed (and, where endorsed, the endorsed) one, measured by an
                          earlier boot stage or the secure world; -35 the same, measured by the software itself;
                          33 a component is not an allowed or not the endorsed one
      status              affirming only if the endpoint is admitted, every claim made is affirming and the verdict
                          carries no warning; warning if admitted otherwise; contraindicated if the evidence was
                          appraised (or the key's endorsement refused) and the endpoint is not admitted; incomplete
                          if there was nothing to appraise (no answer, an entry the policy rules refuse)
    The status is never better than the verdict: not admitted is never affirming or warning."""
    stage = facts.get("stage")
    vector, details = {}, {}
    enrolment, trust = verdict.get("enrolment"), verdict.get("trust")
    if stage == "endorsement":
        vector[V_INSTANCE_IDENTITY] = II_NOT_RECOGNIZED
    elif facts.get("signature") is False:
        vector[V_INSTANCE_IDENTITY] = CRYPTO_FAILED
    elif facts.get("signature"):
        if trust == "development-shared-key":
            vector[V_INSTANCE_IDENTITY] = II_SHARED_KEY
            details[V_INSTANCE_IDENTITY] = ["the key of this development profile is the same on every chip"]
        elif enrolment == "endorsed":
            vector[V_INSTANCE_IDENTITY] = II_RECOGNIZED
        else:
            # trust on first use, or a classical key the policy pins (kind psa): nobody vouched for the key
            vector[V_INSTANCE_IDENTITY] = II_FIRST_USE
            details[V_INSTANCE_IDENTITY] = ["the key is pinned without an endorsement: nothing names the device "
                                            "that holds it"]
    if stage == "appraised" and facts.get("components_ok") is not None:
        if not facts["components_ok"]:
            vector[V_EXECUTABLES] = EX_UNRECOGNIZED
        elif trust in ("software", "device-key"):
            vector[V_EXECUTABLES] = EX_SELF_MEASURED
            details[V_EXECUTABLES] = ["the components are measured by the measured software itself (trust: %s)" % trust]
        else:
            vector[V_EXECUTABLES] = EX_BOOT_APPROVED
    if not vector:
        vector[V_INSTANCE_IDENTITY] = 0     # AR4SI: no assertion; the vector may not be empty
    if not verdict.get("admitted"):
        status = CONTRAINDICATED if stage in ("endorsement", "evidence", "appraised") else INCOMPLETE
    elif verdict.get("warning") or any(not 2 <= v <= 31 for v in vector.values()):
        status = WARNING
    else:
        status = AFFIRMING
    return status, vector, details


def _short(texts, n=8, limit=300):
    return [str(t)[:limit] for t in texts[:n]] or None


def ear_payload(verdict, facts, policy, iat, exp=None, label=None):
    """The EAR claims (draft-ietf-rats-ear-06) for one verdict, as bytes. policy: policy_id() of the policy file the
    verdict was reached under. One appraisal, under the submodule label of the endpoint's kind."""
    status, vector, vdetails = appraisal(verdict, facts)
    a = {EAR_STATUS: status, EAR_VECTOR: vector, EAR_POLICY_IDS: [policy]}
    why = list(verdict.get("reasons") or []) + ([verdict["warning"]] if verdict.get("warning") else [])
    if why and status != AFFIRMING:
        a[EAR_STATUS_DETAILS] = _short(why)
    if vdetails:
        a[EAR_VECTOR_DETAILS] = vdetails
    quote = verdict.get("quote") or {}
    if facts.get("nonce"):
        a[NONCE] = facts["nonce"]
    att = {}
    if facts.get("ueid"):
        att[UEID] = facts["ueid"]
    if facts.get("components"):
        att[MEASUREMENTS] = measurements_claim(facts["components"])
    if facts.get("platform"):
        att[P_PLATFORM] = facts["platform"]
    if facts.get("dbgstat") is not None:
        att[DBGSTAT] = facts["dbgstat"]
    if att:
        a[EAR_ATTESTER_CLAIMS] = att
    ver = {"aegis.endpoint": verdict["endpoint"], "aegis.kind": verdict.get("kind", "psa"),
           "aegis.admitted": bool(verdict.get("admitted")),
           "aegis.evidence-format": facts.get("format") or "none"}
    for key, name in (("trust", "aegis.trust"), ("enrolment", "aegis.enrolment"),
                      ("session_binding", "aegis.session-binding"), ("device_pk_sha256", "aegis.device-key-sha256")):
        if verdict.get(key):
            ver[name] = verdict[key]
    if quote.get("token_sha3_256"):
        ver["aegis.quote-sha3-256"] = bytes.fromhex(quote["token_sha3_256"])     # T1's token hash (transcript v2)
    if facts.get("evidence_sha256"):
        ver["aegis.evidence-sha256"] = facts["evidence_sha256"]                  # the evidence file of the pack
    if verdict.get("enforcement"):
        ver["aegis.enforcement"] = verdict["enforcement"]
    a[EAR_VERIFIER_CLAIMS] = ver
    e = verdict.get("endorsement")
    if e:
        a[EAR_ENDORSER_CLAIMS] = {e["endorser_name"]: {
            "aegis.record-sha256": e["record_sha256"], "aegis.device-key-sha256": e["device_pk_sha256"],
            "aegis.device-state": e["device_state"], IAT: e["issued"]}}
    top = {PROFILE: EAR_PROFILE, IAT: int(iat),
           EAR_VERIFIER_ID: {VERIFIER_DEVELOPER: VERIFIER_DEVELOPER_NAME, VERIFIER_BUILD: VERIFIER_BUILD_NAME},
           EAR_STATUS: status, SUBMODS: {label or verdict.get("kind", "psa"): a}}
    if exp is not None:
        top[EXP] = int(exp)
    return cbor.dumps(top, sort=True)


def _read_ear(payload):
    c = claims_map(payload, "attestation result")
    if c.get(PROFILE) != EAR_PROFILE:
        raise Refused("eat_profile is not %s" % EAR_PROFILE)
    vid, sm = c.get(EAR_VERIFIER_ID), c.get(SUBMODS)
    if not (_is_uint(c.get(IAT)) and isinstance(vid, dict) and _is_text(vid.get(VERIFIER_DEVELOPER))
            and _is_text(vid.get(VERIFIER_BUILD)) and isinstance(sm, dict) and len(sm) == 1):
        raise Refused("the attestation result lacks iat, the verifier's id or its one appraisal")
    if EXP in c and not (_is_uint(c[EXP]) and c[EXP] > c[IAT]):
        raise Refused("exp is not a time after iat")
    label, a = next(iter(sm.items()))
    if not (isinstance(label, str) and isinstance(a, dict)):
        raise Refused("the appraisal is not a map under a text label")
    status, vector = a.get(EAR_STATUS), a.get(EAR_VECTOR)
    if status not in TIER_NAMES or c.get(EAR_STATUS) != status:
        raise Refused("ear_status is not a tier, or differs between the result and its appraisal")
    if not (isinstance(vector, dict) and vector and all(type(k) is int and 0 <= k <= 7 and type(v) is int
                                                        and -128 <= v <= 127 for k, v in vector.items())):
        raise Refused("ear_trustworthiness_vector is not a vector")
    ver = a.get(EAR_VERIFIER_CLAIMS)
    if not (isinstance(ver, dict) and isinstance(ver.get("aegis.endpoint"), str)
            and isinstance(ver.get("aegis.admitted"), bool)):
        raise Refused("the appraisal lacks the verifier's claims")
    if ver["aegis.admitted"] and status not in (AFFIRMING, WARNING):
        raise Refused("admitted, but the status is %s" % TIER_NAMES[status])
    return {"iat": c[IAT], "exp": c.get(EXP), "verifier": dict(vid), "label": label, "status": TIER_NAMES[status],
            "vector": dict(vector), "details": a.get(EAR_STATUS_DETAILS), "policy_ids": a.get(EAR_POLICY_IDS),
            "nonce": a.get(NONCE), "attester_claims": a.get(EAR_ATTESTER_CLAIMS), "verifier_claims": ver,
            "endorser_claims": a.get(EAR_ENDORSER_CLAIMS), "endpoint": ver["aegis.endpoint"],
            "admitted": ver["aegis.admitted"]}


def read_ear(data, verifier_pk, now=None):
    """An attestation result signed by verifier_pk, as a dict; cose.Refused or Refused otherwise. With now (Unix
    time) a result past its exp is refused."""
    s = cose.verify1(data, verifier_pk)
    r = _guard("attestation result", _read_ear, s.payload)
    if now is not None and r["exp"] is not None and now >= r["exp"]:
        raise Refused("the attestation result expired at %d (now %d)" % (r["exp"], int(now)))
    return r
