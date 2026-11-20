# SPDX-License-Identifier: Apache-2.0
"""A signed fleet policy (docs/audit-and-policy.md): the policy file inside a COSE_Sign1, signed by the operator's
policy-signing key, with a version that only goes up.

  COSE_Sign1 (common/cose.py: ML-DSA-65, RFC 9964), typ "application/vnd.aegis.fleet-policy+cbor", payload

  { 1: "tag:github.com,2026:ismailalitech/aegis/policy/v1",
    2: version    uint, 1 or more       a verifier accepts a policy only if its version is higher than the last one
                                        it accepted, or it is that same policy again
    3: issued     uint                  the signer's clock
    4: policy     bstr                  the policy file, byte for byte: the JSON a verifier ran from until now
    5: signer     tstr                  the signer's name, for the journal and the audit log
    ? 6: audience tstr                  the fleet this policy is for, where one key signs for more than one
  }

The policy stays the JSON it was: its SHA-256 is what an attestation result names (common/eat.py policy_id) whether
the file came signed or not.

Off unless asked for. A verifier checks a policy's signature only if it has been given the keys to check it with: a
signers file, {"format": "aegis-policy-signers-v1", "signers": [{"name", "pk": hex}], "audience"?: text}. With one, a
policy that is not signed by one of those keys, for that audience, with a version it has not gone past, is refused.
Without one a policy is the plain JSON file it always was.

The policy-signing key is not the verifier's identity key: the verifier holds no key that can sign a policy, so
whoever takes over the verifier's policy directory cannot make one.

Standard library only; ML-DSA through common/mldsa.py.
"""
import hashlib
import json
import os
import time

import cbor
import cose
import mldsa

FORMAT = "tag:github.com,2026:ismailalitech/aegis/policy/v1"
TYP = "application/vnd.aegis.fleet-policy+cbor"
P_FORMAT, P_VERSION, P_ISSUED, P_POLICY, P_SIGNER, P_AUDIENCE = 1, 2, 3, 4, 5, 6
MAX_SIGNED = 1 << 20                    # bytes of a signed policy: far more than any fleet's
SIGNERS_FORMAT = "aegis-policy-signers-v1"
SIGNERS_FILE = "policy-signers.json"    # in the verifier's state directory, unless --policy-signers names another
VERSION_FORMAT = "aegis-policy-version-v1"
VERSION_FILE = "policy-version.json"    # in the verifier's state directory: the last version it accepted
MAX_VERSION = 1 << 53


class Refused(ValueError):
    """The policy is not one this verifier may run from. The text says why."""


def is_signed(data):
    """Whether the bytes of a policy file are a COSE_Sign1 (tag 18) rather than JSON: the first byte says."""
    return data[:1] == b"\xd2"


def _is_text(v, limit=64):
    return isinstance(v, str) and 0 < len(v) <= limit


def _no_duplicates(pairs):
    out = {}
    for k, v in pairs:
        if k in out:
            raise Refused("the policy names %r twice in one object" % (k[:40],))
        out[k] = v
    return out


def parse_policy(policy_bytes):
    """The policy as a dict; Refused unless the bytes are one JSON object with an "endpoints" list and no key twice
    in any object (two readers of a signed file must not be able to read it two ways)."""
    try:
        policy = json.loads(policy_bytes.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except Refused:
        raise
    except Exception as e:  # noqa: BLE001 - UnicodeDecodeError, JSONDecodeError, RecursionError
        raise Refused("the policy is not JSON: %s: %s" % (type(e).__name__, str(e)[:120])) from None
    if not (isinstance(policy, dict) and isinstance(policy.get("endpoints"), list)):
        raise Refused('the policy is not an object with "endpoints"')
    return policy


def sign(sk, pk, policy_bytes, version, signer, issued=None, audience=None):
    """The signed policy for policy_bytes (the JSON file as it is)."""
    parse_policy(policy_bytes)
    if not (type(version) is int and 1 <= version < MAX_VERSION):
        raise ValueError("a policy's version is a whole number from 1")
    if not _is_text(signer) or (audience is not None and not _is_text(audience)):
        raise ValueError("the signer's name and the audience are short texts")
    c = {P_FORMAT: FORMAT, P_VERSION: version, P_ISSUED: int(time.time() if issued is None else issued),
         P_POLICY: bytes(policy_bytes), P_SIGNER: signer}
    if audience is not None:
        c[P_AUDIENCE] = audience
    return cose.sign1(sk, pk, cbor.dumps(c, sort=True), typ=TYP)


def _open(data, signers, audience):
    s = cose.parse(data, MAX_SIGNED)
    if s.typ != TYP:
        raise Refused("typ is %r, not %r: not a signed policy" % (s.typ[:48], TYP))
    who = signers.get(s.kid)
    if who is None:
        raise Refused("signed by a key that is not a policy signer of this verifier (kid %s...)" % s.kid.hex()[:16])
    s = cose.verify1(data, who["pk"], typ=TYP, limit=MAX_SIGNED)
    c = cbor.loads(s.payload)
    if not isinstance(c, dict) or cbor.dumps(c, sort=True) != s.payload:
        raise Refused("the signed policy's claims are not a map in deterministic encoding")
    keys = {P_FORMAT, P_VERSION, P_ISSUED, P_POLICY, P_SIGNER}
    if not keys <= set(c) <= keys | {P_AUDIENCE}:
        raise Refused("the signed policy is not {format, version, issued, policy, signer[, audience]}")
    if c[P_FORMAT] != FORMAT:
        raise Refused("the signed policy's format is not %s" % FORMAT)
    if not (type(c[P_VERSION]) is int and 1 <= c[P_VERSION] < MAX_VERSION and type(c[P_ISSUED]) is int
            and 0 <= c[P_ISSUED] < 1 << 40 and isinstance(c[P_POLICY], bytes) and _is_text(c[P_SIGNER])
            and (P_AUDIENCE not in c or _is_text(c[P_AUDIENCE]))):
        raise Refused("the signed policy's version, time, policy, signer or audience is not one")
    if audience is not None and c.get(P_AUDIENCE) != audience:
        raise Refused("the policy is for %s, this verifier's fleet is %r" % (
            "%r" % c[P_AUDIENCE] if P_AUDIENCE in c else "no fleet in particular", audience))
    return {"policy": parse_policy(c[P_POLICY]), "policy_bytes": c[P_POLICY], "version": c[P_VERSION],
            "issued": c[P_ISSUED], "signer": c[P_SIGNER], "audience": c.get(P_AUDIENCE), "signer_name": who["name"],
            "signer_key_sha256": hashlib.sha256(who["pk"]).hexdigest(), "kid": s.kid.hex(),
            "policy_sha256": hashlib.sha256(c[P_POLICY]).hexdigest(), "signed_sha256": hashlib.sha256(data).hexdigest()}


def open_signed(data, signers, audience=None):
    """The policy inside a signed policy file, if one of signers (load_signers()["keys"]) signed it, for audience if
    the verifier has one: {"policy" (dict), "policy_bytes", "version", "issued", "signer" (as signed), "signer_name"
    (as the signers file calls the key), "signer_key_sha256", "audience", "policy_sha256", "signed_sha256"}.
    Refused (this module's, or cose.Refused) and nothing else, whatever the bytes are. Says nothing about the
    version being new: check_version()."""
    try:
        return _open(data, signers, audience)
    except (Refused, cose.Refused):
        raise
    except Exception as e:  # noqa: BLE001 - CBORError, RecursionError, a type the checks above did not expect
        raise Refused("not a signed policy: %s: %s" % (type(e).__name__, e)) from None


def signers_file(keys, audience=None):
    """The bytes of a signers file for [(name, public key)]."""
    doc = {"format": SIGNERS_FORMAT, "signers": [{"name": n, "pk": bytes(pk).hex()} for n, pk in keys]}
    if audience is not None:
        doc["audience"] = audience
    return (json.dumps(doc, indent=1) + "\n").encode()


def load_signers(path):
    """The verifier's policy signers: {"keys": {kid: {"name", "pk"}}, "audience": text or None}. Refused if the file
    is there and is anything but a list of at least one key: a verifier that was told to check signatures must not
    find itself checking none. OSError if it cannot be read."""
    with open(path, "rb") as f:
        data = f.read(1 << 20)
    try:
        doc = json.loads(data.decode("utf-8"), object_pairs_hook=_no_duplicates)
    except Refused:
        raise
    except Exception as e:  # noqa: BLE001
        raise Refused("%s is not JSON: %s" % (path, type(e).__name__)) from None
    if not (isinstance(doc, dict) and doc.get("format") == SIGNERS_FORMAT and not set(doc) - {"format", "signers",
                                                                                               "audience", "notes"}
            and isinstance(doc.get("signers"), list) and doc["signers"]):
        raise Refused('%s is not {"format": "%s", "signers": [one or more][, "audience"]}' % (path, SIGNERS_FORMAT))
    if "audience" in doc and not _is_text(doc["audience"]):
        raise Refused("%s: the audience is not a short text" % path)
    keys = {}
    for e in doc["signers"]:
        if not (isinstance(e, dict) and set(e) <= {"name", "pk", "notes"} and _is_text(e.get("name"))
                and isinstance(e.get("pk"), str)):
            raise Refused("%s: a signer is not {name, pk}" % path)
        try:
            pk = bytes.fromhex(e["pk"])
        except ValueError:
            pk = b""
        if len(pk) != mldsa.PK_LEN:
            raise Refused("%s: the key of signer %s is not an ML-DSA-65 public key in hex" % (path, e["name"]))
        kid = cose.key_thumbprint(pk)
        if kid in keys:
            raise Refused("%s lists one key twice" % path)
        keys[kid] = {"name": e["name"], "pk": pk}
    return {"keys": keys, "audience": doc.get("audience"), "sha256": hashlib.sha256(data).hexdigest()}


# ---- the version a verifier has reached -------------------------------------------------------------------------------

def last_version(state):
    """What this verifier last accepted: {"version", "policy_sha256", "signed_sha256", ...}, or None if it never
    accepted a signed policy. Refused if the record is there and unreadable: a counter that cannot be read is not a
    counter at zero."""
    path = os.path.join(state, VERSION_FILE)
    try:
        with open(path, "rb") as f:
            data = f.read(65536)
    except FileNotFoundError:
        return None
    try:
        rec = json.loads(data.decode("utf-8"))
        ok = (isinstance(rec, dict) and rec.get("format") == VERSION_FORMAT and type(rec.get("version")) is int
              and 1 <= rec["version"] < MAX_VERSION and isinstance(rec.get("policy_sha256"), str))
    except Exception:  # noqa: BLE001
        ok = False
    if not ok:
        raise Refused("%s is not this verifier's record of the last policy version: put back the file, or remove it "
                      "to accept any version again" % path)
    return rec


def check_version(info, last):
    """Refused unless the opened policy info may follow last (last_version()): a higher version, or the same version
    of the same policy (the loop reads its policy file again every cycle)."""
    if last is None or info["version"] > last["version"]:
        return
    if info["version"] == last["version"]:
        if info["policy_sha256"] == last["policy_sha256"]:
            return
        raise Refused("version %d was already accepted for another policy (sha256 %s...): a new policy needs a "
                      "higher version" % (info["version"], last["policy_sha256"][:16]))
    raise Refused("version %d is older than the last one this verifier accepted (%d): rollback refused"
                  % (info["version"], last["version"]))


def remember_version(state, info, now=None):
    """Record info as the last accepted policy, if it is newer than what is recorded. Written under a temporary name
    and renamed, flushed to disk first: the counter never goes back to an older value by a crash."""
    import endorsement      # for its atomic write
    last = last_version(state)
    if last is not None and last["version"] >= info["version"]:
        return last
    rec = {"format": VERSION_FORMAT, "version": info["version"], "policy_sha256": info["policy_sha256"],
           "signed_sha256": info["signed_sha256"], "signer_key_sha256": info["signer_key_sha256"],
           "signer": info["signer_name"], "accepted": int(time.time() if now is None else now)}
    endorsement.write_atomic(os.path.join(state, VERSION_FILE), (json.dumps(rec, indent=1) + "\n").encode(), 0o600)
    return rec
