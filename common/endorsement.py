# SPDX-License-Identifier: Apache-2.0
"""Endorsement records: an endorser's signed statement that one ML-DSA-65 key is the identity key of one device.

Without one, a verifier pins whatever device key it was first given (trust on first use). With one, the verifier
trusts a device key only if an endorser it trusts signed for it: the endorser talked to the device on a trusted cable
or LAN, took its key and a fresh quote, checked the quote against the reference measurements and signed this record
(provision/aegis_provision.py; docs/enrolment.md says what that proves and what it does not).

The record is a JSON object:

  {"format": "aegis-endorsement-v1",
   "body": {...},            the claims, below
   "sig": "<hex>",           ML-DSA-65 by the endorser over canonical(body) (common/wire.py), label LABEL
   "device_pk": "<hex>"}     the device's public key itself, so that the one file is the whole enrolment; it is not
                             under the signature, the body names its SHA-256

  body:
   "v": 1, "type": "endorsement"
   "device"               the device's name at the verifier (the policy entry's "name")
   "serial"               optional: the operator's serial number or label for the board
   "kind"                 the device family: the policy kind (aegis-pq, aegis-device, aegis-tee, aegis-linux)
   "profile"              the claims profile, for kinds whose quote carries one; absent for aegis-pq
   "device_pk_alg"        "ML-DSA-65"
   "device_pk_sha256"     SHA-256 of the device's public key (1952 bytes)
   "measurements"         [{"type", "measurement_value", "signer_id"?}, ...]: what the device reported at the bench and
                          the endorser found in its reference values; sorted by type
   "instance_id"          optional: the quote's instance ID
   "evidence"             {"challenge", "token_sha3_256"}: the quote the endorser appraised
   "device_state"         "development" or "closed": the operator's statement of the device's lifecycle (debug port,
                          secure boot) when it was endorsed. Not measured by anything here.
   "endorser"             the endorser's own name
   "endorser_pk_sha256"   SHA-256 of the endorser's ML-DSA-65 public key: which trusted key to check the signature with
   "issued"               Unix time, the endorser's clock
   "expires"              optional Unix time
   "notes"                optional

Every value is a string, an integer or a list of maps of strings, and no key is optional in meaning: a version 1
verifier refuses a body with a key it does not know, so a later version cannot add a restriction that an old verifier
would silently ignore. The body is a flat claims set on purpose: an EAT (CBOR claims in a COSE_Sign1 signed with
ML-DSA-65) can carry the same claims one for one; docs/enrolment.md has the intended mapping.

The standard form of the same record (docs/evidence-format.md, "The endorsement"): format
"aegis-endorsement-cose-v1", one COSE_Sign1 (common/cose.py: ML-DSA-65, kid = the endorser key's COSE Key
Thumbprint) whose payload is an EAT with the body's claims, one for one:

  1 iss = endorser            2 sub = device          6 iat = issued          4 exp = expires
  8 cnf = {1: COSE_Key}       the device's public key itself (AKP, ML-DSA-65), here under the signature
  10 eat_nonce = evidence.challenge                   265 eat_profile = the endorsement profile
  256 ueid = instance_id, if it is a UEID (0x01 and 16, 24 or 32 bytes); otherwise private claim -82406
  273 measurements = measured components (RFC 10013): name = type, SHA-256 digest, authorities = [signer_id]
  private: -82400 profile, -82401 kind, -82402 serial, -82403 device_state, -82404 evidence.token_sha3_256,
           -82405 notes, -82407 v, -82408 endorser_pk_sha256

loads() reads either form and gives the same record shape with the same body, so every rule below applies to both;
sign_cose() makes the standard one. A third party checks it with any COSE library and the endorser's public key
(tools/verify_evidence.py).

Standard library only, and ML-DSA through common/mldsa.py: the gateway's Python has no other packages.
"""
import hashlib
import json
import os
import re
import secrets

import mldsa
import wire

FORMAT = "aegis-endorsement-v1"
FORMAT_COSE = "aegis-endorsement-cose-v1"   # the same claims as an EAT in a COSE_Sign1
P_ENDORSER_KEY = -82408                     # bstr .size 32: SHA-256 of the endorser's public key (the policy's name for it)
LABEL = b"aegis-endorsement-v1"
ENDORSER_LABEL = b"aegis-endorser-v1"       # the endorser's own record of its key (endorser.json)
PK_ALG = "ML-DSA-65"
DEVICE_STATES = ("development", "closed")
MAX_RECORD = 65536                          # bytes of a record file; a real one is about 11 kB
MAX_MEASUREMENTS = 16
_BODY_KEYS = {"v", "type", "device", "serial", "kind", "profile", "device_pk_alg", "device_pk_sha256", "measurements",
              "instance_id", "evidence", "device_state", "endorser", "endorser_pk_sha256", "issued", "expires", "notes"}
_REQUIRED = _BODY_KEYS - {"serial", "profile", "instance_id", "expires", "notes"}
_RECORD_KEYS = {"format", "body", "sig", "device_pk"}
_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}\Z")


class Refused(ValueError):
    """The record, or the list of trusted endorsers, does not make this key a trusted one. The text says why."""


def pk_sha256(pk):
    return hashlib.sha256(pk).hexdigest()


def _is_hex(v, digits=None):
    return (isinstance(v, str) and len(v) % 2 == 0 and (digits is None or len(v) == digits) and len(v) > 0
            and all(c in "0123456789abcdef" for c in v))


def _is_text(v, limit=256):
    return isinstance(v, str) and 0 < len(v) <= limit


def is_name(v):
    """A device or entry name: it becomes part of file names (endorsements/<name>.json, the endorser's <name>.json,
    the gateway's credentials/<name>.json), so only letters, digits, ".", "_" and "-", at most 64, not starting with a
    dot."""
    return isinstance(v, str) and _NAME.match(v) is not None


def _is_time(v):
    return isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 1 << 40


def check_body(body):
    """Refused unless body is a well-formed version 1 endorsement body: every key known, every value of its type."""
    if not isinstance(body, dict):
        raise Refused("the body is not a map")
    unknown = set(body) - _BODY_KEYS
    if unknown:
        raise Refused("the body has keys this verifier does not know: %s" % ", ".join(sorted(map(str, unknown))))
    missing = _REQUIRED - set(body)
    if missing:
        raise Refused("the body lacks %s" % ", ".join(sorted(missing)))
    if type(body["v"]) is not int or body["v"] != 1 or body["type"] != "endorsement":
        raise Refused("not a version 1 endorsement")
    for k in ("device", "kind", "endorser"):
        if not _is_text(body[k]):
            raise Refused("%s is not a short text" % k)
    if not is_name(body["device"]):
        raise Refused("device is not a name (letters, digits, '.', '_', '-'; no leading dot)")
    for k, limit in (("serial", 256), ("profile", 256), ("notes", 1024)):
        if k in body and not _is_text(body[k], limit):
            raise Refused("%s is not a short text" % k)
    if body["device_pk_alg"] != PK_ALG:
        raise Refused("the device key is not %s" % PK_ALG)
    for k in ("device_pk_sha256", "endorser_pk_sha256"):
        if not _is_hex(body[k], 64):
            raise Refused("%s is not 64 lower-case hex digits" % k)
    if "instance_id" in body and not _is_hex(body["instance_id"]):
        raise Refused("instance_id is not hex")
    if body["device_state"] not in DEVICE_STATES:
        raise Refused("device_state is not one of %s" % ", ".join(DEVICE_STATES))
    ev = body["evidence"]
    if not (isinstance(ev, dict) and set(ev) == {"challenge", "token_sha3_256"}
            and _is_hex(ev["challenge"], 64) and _is_hex(ev["token_sha3_256"], 64)):
        raise Refused("evidence is not a challenge and a token hash")
    ms = body["measurements"]
    if not (isinstance(ms, list) and 0 < len(ms) <= MAX_MEASUREMENTS):
        raise Refused("measurements is not a list of 1 to %d components" % MAX_MEASUREMENTS)
    for m in ms:
        if not (isinstance(m, dict) and {"type", "measurement_value"} <= set(m) <= {"type", "measurement_value",
                                                                                   "signer_id"}
                and _is_text(m["type"], 64) and _is_hex(m["measurement_value"])
                and ("signer_id" not in m or _is_hex(m["signer_id"]))):
            raise Refused("a measurement is not {type, measurement_value, signer_id}")
    if len({m["type"] for m in ms}) != len(ms):
        raise Refused("two measurements of one type")
    if not _is_time(body["issued"]):
        raise Refused("issued is not a time")
    if "expires" in body and not (_is_time(body["expires"]) and body["expires"] > body["issued"]):
        raise Refused("expires is not a time after issued")
    return body


def sign(body, endorser_sk, device_pk):
    """The record for body, signed. The caller checks it with check() before it lets anyone trust it."""
    check_body(body)
    if pk_sha256(device_pk) != body["device_pk_sha256"]:
        raise Refused("the body names another device key")
    sig = mldsa.sign(endorser_sk, LABEL, wire.canonical(body))
    return {"format": FORMAT, "body": body, "sig": sig.hex(), "device_pk": device_pk.hex()}


def dumps(record):
    if record.get("format") == FORMAT_COSE:
        return record["cose"]
    return (json.dumps(record, indent=1, sort_keys=True) + "\n").encode()


# ---- the standard form: an EAT in a COSE_Sign1 -----------------------------------------------------------------------

def _claims(body, device_pk):
    import cose
    import eat
    c = {eat.ISS: body["endorser"], eat.SUB: body["device"], eat.IAT: body["issued"],
         eat.CNF: {eat.CNF_COSE_KEY: cose.cose_key(device_pk)},
         eat.NONCE: bytes.fromhex(body["evidence"]["challenge"]), eat.PROFILE: eat.ENDORSEMENT_PROFILE,
         eat.MEASUREMENTS: eat.measurements_claim([{"measurement_type": m["type"],
                                                    "measurement_value": m["measurement_value"],
                                                    "signer_id": m.get("signer_id")} for m in body["measurements"]]),
         eat.P_KIND: body["kind"], eat.P_DEVICE_STATE: body["device_state"],
         eat.P_EVIDENCE_HASH: bytes.fromhex(body["evidence"]["token_sha3_256"]), eat.P_FORMAT: body["v"],
         P_ENDORSER_KEY: bytes.fromhex(body["endorser_pk_sha256"])}
    for key, claim in (("expires", eat.EXP), ("profile", eat.P_PLATFORM), ("serial", eat.P_SERIAL),
                       ("notes", eat.P_NOTES)):
        if key in body:
            c[claim] = body[key]
    if "instance_id" in body:
        inst = bytes.fromhex(body["instance_id"])
        c[eat.UEID if _is_ueid(inst) else eat.P_INSTANCE] = inst
    return c


def _is_ueid(b):
    return len(b) in (17, 25, 33) and b[0] == 0x01      # RFC 9711 section 4.2.1: type RAND, 128, 192 or 256 bits


def _body(c):
    """The version 1 body and the device key that an endorsement's EAT claims say; Refused for any other claims."""
    import cose
    import eat
    known = {eat.ISS, eat.SUB, eat.EXP, eat.IAT, eat.CNF, eat.NONCE, eat.UEID, eat.PROFILE, eat.MEASUREMENTS,
             eat.P_PLATFORM, eat.P_KIND, eat.P_SERIAL, eat.P_DEVICE_STATE, eat.P_EVIDENCE_HASH, eat.P_NOTES,
             eat.P_INSTANCE, eat.P_FORMAT, P_ENDORSER_KEY}
    unknown = set(c) - known
    if unknown:
        raise Refused("the record has claims this verifier does not know: %s"
                      % ", ".join(sorted(repr(k)[:16] for k in unknown)))
    need = {eat.ISS, eat.SUB, eat.IAT, eat.CNF, eat.NONCE, eat.PROFILE, eat.MEASUREMENTS, eat.P_KIND,
            eat.P_DEVICE_STATE, eat.P_EVIDENCE_HASH, eat.P_FORMAT, P_ENDORSER_KEY}
    if need - set(c):
        raise Refused("the record lacks claim %s" % ", ".join(str(k) for k in sorted(need - set(c))))
    if c[eat.PROFILE] != eat.ENDORSEMENT_PROFILE:
        raise Refused("eat_profile is not %s" % eat.ENDORSEMENT_PROFILE)
    if eat.UEID in c and eat.P_INSTANCE in c:
        raise Refused("two instance IDs")
    cnf = c[eat.CNF]
    if not (isinstance(cnf, dict) and set(cnf) == {eat.CNF_COSE_KEY}):
        raise Refused("cnf is not {COSE_Key}")
    device_pk = cose.key_from_cose(cnf[eat.CNF_COSE_KEY])
    for k in (eat.NONCE, eat.P_EVIDENCE_HASH, P_ENDORSER_KEY):
        if not (isinstance(c[k], bytes) and len(c[k]) == 32):
            raise Refused("claim %d is not 32 bytes" % k)
    inst = c.get(eat.UEID, c.get(eat.P_INSTANCE))
    if inst is not None and not (isinstance(inst, bytes) and 0 < len(inst) <= 64
                                 and (eat.UEID in c) == _is_ueid(inst)):
        raise Refused("the instance ID is not a byte string in the claim for its form")
    body = {"v": c[eat.P_FORMAT], "type": "endorsement", "device": c[eat.SUB], "kind": c[eat.P_KIND],
            "device_pk_alg": PK_ALG, "device_pk_sha256": pk_sha256(device_pk),
            "measurements": [dict({"type": m["measurement_type"], "measurement_value": m["measurement_value"].hex()},
                                  **({"signer_id": m["signer_id"].hex()} if "signer_id" in m else {}))
                             for m in eat.components(c[eat.MEASUREMENTS])],
            "evidence": {"challenge": c[eat.NONCE].hex(), "token_sha3_256": c[eat.P_EVIDENCE_HASH].hex()},
            "device_state": c[eat.P_DEVICE_STATE], "endorser": c[eat.ISS],
            "endorser_pk_sha256": c[P_ENDORSER_KEY].hex(), "issued": c[eat.IAT]}
    for key, claim in (("expires", eat.EXP), ("profile", eat.P_PLATFORM), ("serial", eat.P_SERIAL),
                       ("notes", eat.P_NOTES)):
        if claim in c:
            body[key] = c[claim]
    if inst is not None:
        body["instance_id"] = inst.hex()
    if any(isinstance(v, bool) for v in body.values()):
        raise Refused("a claim is a boolean")
    return check_body(body), device_pk


def _open_cose(data, endorser_pk=None):
    """The record of a COSE endorsement; with endorser_pk its signature and kid are checked first, without it nothing
    in the result is authenticated. Refused only."""
    import cose
    import eat
    try:
        s = cose.verify1(data, endorser_pk) if endorser_pk is not None else cose.parse(data)
        body, device_pk = _body(eat.claims_map(s.payload, "endorsement claims"))
    except Refused:
        raise
    except Exception as e:  # noqa: BLE001 - cose.Refused, eat.Refused, and whatever hostile claims provoke
        raise Refused("%s" % e if isinstance(e, ValueError) else "the record is not usable: %s: %s"
                      % (type(e).__name__, e)) from None
    return {"format": FORMAT_COSE, "body": body, "device_pk": device_pk.hex(), "cose": bytes(data),
            "kid": s.kid.hex()}


def sign_cose(body, endorser_sk, endorser_pk, device_pk):
    """The record for body in the standard form, as bytes: an EAT in a COSE_Sign1 by the endorser's key. The caller
    checks it with check(loads(...)) before it lets anyone trust it."""
    import cbor
    import cose
    check_body(body)
    if pk_sha256(device_pk) != body["device_pk_sha256"]:
        raise Refused("the body names another device key")
    if pk_sha256(endorser_pk) != body["endorser_pk_sha256"]:
        raise Refused("the body names another endorser key")
    if any(len(m["measurement_value"]) != 64 for m in body["measurements"]):
        raise Refused("the standard form carries SHA-256 measurements only")
    data = cose.sign1(endorser_sk, endorser_pk, cbor.dumps(_claims(body, device_pk), sort=True))
    if _open_cose(data)["body"] != body:
        raise Refused("the body does not survive the standard form")    # a claim the EAT cannot carry as it is
    return data


def _no_duplicates(pairs):
    """Two values for one key: which one a reader takes depends on the reader, so neither is taken."""
    out = {}
    for k, v in pairs:
        if k in out:
            raise ValueError("duplicate key %r" % k[:40])
        out[k] = v
    return out


def _no_constant(name):
    raise ValueError("%s is not JSON" % name)


def loads(data):
    """A record from bytes. Refused for anything that is not one JSON object of the known shape; the signature is
    not checked here."""
    if len(data) > MAX_RECORD:
        raise Refused("the record is larger than %d bytes" % MAX_RECORD)
    if data[:1] == b"\xd2":         # CBOR tag 18: the standard form (a JSON record starts with "{")
        return _open_cose(data)
    try:
        rec = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates, parse_constant=_no_constant)
    except (ValueError, RecursionError) as e:
        raise Refused("the record is not JSON: %s" % type(e).__name__) from None
    if not isinstance(rec, dict):
        raise Refused("the record is not a JSON object")
    if rec.get("format") != FORMAT:
        raise Refused("unknown record format %r" % (rec.get("format"),))
    if set(rec) - _RECORD_KEYS or not {"body", "sig"} <= set(rec):
        raise Refused("the record is not {format, body, sig, device_pk}")
    if not _is_hex(rec["sig"], 2 * mldsa.SIG_LEN):
        raise Refused("sig is not an ML-DSA-65 signature in hex")
    if "device_pk" in rec and not _is_hex(rec["device_pk"], 2 * mldsa.PK_LEN):
        raise Refused("device_pk is not an ML-DSA-65 public key in hex")
    check_body(rec["body"])
    if "device_pk" in rec and pk_sha256(bytes.fromhex(rec["device_pk"])) != rec["body"]["device_pk_sha256"]:
        raise Refused("the record carries another key than the one its body names")
    return rec


def load(path):
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_RECORD + 1)
    except FileNotFoundError:
        raise Refused("no endorsement record (%s)" % path) from None
    except OSError as e:
        raise Refused("the endorsement record cannot be read: %s" % e) from None
    return loads(data)


def record_sha256(record):
    """Names one record: SHA-256 over the signed body and the signature (signatures are randomised, so two records for
    the same body have different names). For the standard form: SHA-256 of the COSE_Sign1 itself, which has one
    encoding."""
    if record.get("format") == FORMAT_COSE:
        return hashlib.sha256(record["cose"]).hexdigest()
    return wire.digest({"body": record["body"], "sig": record["sig"]})


def trusted(endorsers, base_dir):
    """The policy's "endorsers" list as {pk_sha256: {"name", "pk", "revoked"}}.

    Each entry: {"name": ..., "pk_file": <hex ML-DSA-65 public key, path relative to the policy>, "pk_sha256": <its
    SHA-256>, "revoked": true (optional)}. The hash is in the policy itself, so the policy says which keys it trusts
    and a key file that was replaced is not used. Refused if the list is malformed: one bad entry must not leave the
    others looking like the whole list."""
    if endorsers is None:
        return {}
    if not isinstance(endorsers, list):
        raise Refused('the policy\'s "endorsers" is not a list')
    out = {}
    for e in endorsers:
        if not (isinstance(e, dict) and _is_text(e.get("name")) and _is_text(e.get("pk_file"), 4096)
                and _is_hex(e.get("pk_sha256"), 64) and isinstance(e.get("revoked", False), bool)):
            raise Refused('an entry of the policy\'s "endorsers" is not {name, pk_file, pk_sha256[, revoked]}')
        path = e["pk_file"] if os.path.isabs(e["pk_file"]) else os.path.join(base_dir, e["pk_file"])
        try:
            with open(path) as f:
                pk = bytes.fromhex(f.read(4 * mldsa.PK_LEN).strip())
        except (OSError, ValueError) as err:
            raise Refused("endorser %s: key file not usable: %s" % (e["name"], err)) from None
        if len(pk) != mldsa.PK_LEN or pk_sha256(pk) != e["pk_sha256"]:
            raise Refused("endorser %s: the key in %s is not the key the policy pins (pk_sha256)" % (e["name"], path))
        if e["pk_sha256"] in out:
            raise Refused("endorser key %s... is listed twice" % e["pk_sha256"][:16])
        out[e["pk_sha256"]] = {"name": e["name"], "pk": pk, "revoked": e.get("revoked", False)}
    return out


def check(record, trust, device, kind, profile, device_pk, now):
    """The body of record, if it makes device_pk the trusted key of this policy entry; Refused otherwise.

    trust is trusted()'s result; device, kind and profile are the policy entry's (profile None for a kind without
    one); now is this verifier's Unix time. In order: an endorser the policy trusts and has not revoked signed exactly
    this body; the body names this device, this family and this key; it has not expired."""
    cose_form = record.get("format") == FORMAT_COSE
    # the standard form: the body is read again from the signed bytes, whatever the record's "body" says
    body = _open_cose(record.get("cose"))["body"] if cose_form else check_body(record.get("body"))
    who = trust.get(body["endorser_pk_sha256"])
    if who is None:
        raise Refused("signed by a key that is not a trusted endorser of this policy (%s..., calls itself %r)"
                      % (body["endorser_pk_sha256"][:16], body["endorser"][:40]))
    if who["revoked"]:
        raise Refused("endorser %s is revoked in this policy" % who["name"])
    if cose_form:
        try:
            _open_cose(record["cose"], who["pk"])   # alg, kid and the ML-DSA-65 signature over the Sig_structure
        except Refused as e:
            raise Refused("the record of endorser %s does not verify (%s)" % (who["name"], e)) from None
    else:
        try:
            sig = bytes.fromhex(record.get("sig", ""))
        except (TypeError, ValueError):
            raise Refused("sig is not hex") from None
        if not mldsa.verify(who["pk"], LABEL, wire.canonical(body), sig):
            raise Refused("the signature of endorser %s does not verify (record altered, or not signed by that key)"
                          % who["name"])
    if body["device"] != device:
        raise Refused("the record endorses device %r, not %r" % (body["device"][:40], device))
    if body["kind"] != kind or body.get("profile") != profile:
        raise Refused("the record endorses family %s, the policy entry is %s"
                      % (family(body["kind"], body.get("profile")), family(kind, profile)))
    if pk_sha256(device_pk) != body["device_pk_sha256"]:
        raise Refused("the pinned key (sha256 %s...) is not the endorsed key (%s...): substituted key"
                      % (pk_sha256(device_pk)[:16], body["device_pk_sha256"][:16]))
    if "expires" in body and now >= body["expires"]:
        raise Refused("the endorsement expired at %d (now %d)" % (body["expires"], int(now)))
    return dict(body, endorser_name=who["name"])


def family(kind, profile):
    return "%s/%s" % (kind, profile) if profile else str(kind)


def measurement_reasons(reported, endorsed):
    """Why a quote's components are not the endorsed ones (empty list: they are). reported: [(type, measurement hex,
    signer hex or None)], as the quote gave them. Exact: every reported component is an endorsed one (and by the
    endorsed signer, where the record names one), and every endorsed component was reported."""
    reasons = []
    want = {m["type"]: m for m in endorsed}
    seen = set()
    for typ, value, signer in reported:
        m = want.get(typ) if isinstance(typ, str) else None
        if m is None:
            reasons.append("component %r is not in the endorsement" % (typ,))
        elif m["measurement_value"] != value or ("signer_id" in m and m["signer_id"] != signer):
            reasons.append("component %s is not the endorsed one (measurement %s..., endorsed %s...)"
                           % (typ, str(value)[:12], m["measurement_value"][:12]))
        else:
            seen.add(typ)
    for typ in sorted(set(want) - seen - {r[0] for r in reported if isinstance(r[0], str)}):
        reasons.append("endorsed component %s is not in the quote" % typ)
    return reasons


# ---- files: nothing half-written is ever in a place a verifier reads -------------------------------------------------

def _fsync_dir(path):
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def stage(path, data, mode=0o644):
    """Write data next to path (same directory, so the rename is atomic) and return the temporary name."""
    d = os.path.dirname(os.path.abspath(path))
    os.makedirs(d, exist_ok=True)
    tmp = "%s.tmp.%d.%s" % (path, os.getpid(), secrets.token_hex(4))
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
    except BaseException:
        discard(tmp)
        raise
    return tmp


def commit(tmp, path):
    os.replace(tmp, path)
    _fsync_dir(os.path.dirname(os.path.abspath(path)))


def discard(tmp):
    try:
        os.unlink(tmp)
    except OSError:
        pass


def write_atomic(path, data, mode=0o644):
    tmp = stage(path, data, mode)
    try:
        commit(tmp, path)
    except BaseException:
        discard(tmp)
        raise
