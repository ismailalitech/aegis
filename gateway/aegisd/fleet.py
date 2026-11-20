#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Aegis fleet verifier (gateway side, Phase 3/4): attest endpoints, decide admission.

  fleet.py once  POLICY.json             attest every endpoint once, print verdicts
  fleet.py watch POLICY.json [--interval 30]   re-attest forever, write the state file

For each endpoint the gateway sends a fresh 32-byte challenge and expects a PSA
attestation token (COSE_Sign1, ES256) from the endpoint's TF-M secure world. An
endpoint is ADMITTED only if all of these hold:
  - it answered in time with a well-formed token,
  - the token signature verifies with the endpoint's enrolled attestation key,
  - the token's challenge is the one just sent (no replay),
  - every reported software component (SPE, NSPE, ...) matches one allowed
    measurement and signer in the policy.
Anything else, including no answer at all (a node that cannot attest), is
QUARANTINED with the reasons listed. Standard library only, plus the openssl tool.

Strict by default: a "psa" endpoint without "iak_pub_pem" (unsigned claims) and a
plain-claims endpoint without a pinned "profile" are refused without contacting
them. The ZynqMP development profile (one OP-TEE key for every chip) is refused
too unless its entry says "allow_dev_profile": true; it is then admitted with the
trust label "development-shared-key" and a WARNING line. `fleet.py check POLICY`
lists what a policy would refuse.

Enforcement is a hook: if the policy names "enforce_cmd", it is run with the
endpoint name and verdict after every decision (for example to add or remove a
firewall rule), with AEGIS_ADMIT_TTL set to the seconds an admission may live
without being refreshed by the next cycle (admit_ttl()). A hook that fails is
reported in the verdict and in the journal line ("enforcement FAILED"). Without
the hook the gateway only decides and records.

The same loop runs on an ordinary Linux host (--platform linux, docs/pc-verifier.md). There it is observe-only (an
"enforce_cmd" runs only with --enforce), keeps its state under the user's state directory instead of /var/lib/aegis,
and issues credentials only to endpoints whose policy entry names this verifier's key in "verifier_pin_sha256"
(the key the endpoint's firmware pins, tools/gen_gateway_pin.py): any other endpoint would refuse the credential, and
the attempt would cancel a provisioning exchange the gateway may have in flight. Attestation needs no pin and
touches no session state on the endpoint.

One transcript (common/transcript.py, docs/architecture.md): an entry with "transcript": "v2" gets a session only
through the bound exchange. PQKEMINIT then carries the challenge of the quote this cycle appraised, the endpoint's
signature over its ML-KEM key must cover that quote, and the credential, the confirmation tag and the session key all
depend on the same hash chain: with endpoint images that follow the protocol, the session is finished with the code
that was appraised, in the same boot, or not at all. The older exchange (the endpoint signs nonce || ek and nothing of
the quote) is then refused, and a stored session made that way is replaced. Without the key the older exchange is
used, so an endpoint whose firmware has not been upgraded keeps working; every such session is marked "unbound" in the
journal and the state file, with a line at warning priority when it is issued and when the loop starts. What the
transcript says is that one boot of the code holding the endpoint's key signed the appraised quote and then made the
session's key; it does not stop code that holds the key and lies, which on this bench anyone who can flash the
endpoint can build (docs/architecture.md says what would).

Endorsed enrolment (common/endorsement.py, docs/enrolment.md): an entry with "endorsement": "required" is admitted
only if a record signed by one of the policy's trusted endorsers ("endorsers": [{"name", "pk_file", "pk_sha256"}])
names this entry's device, family and exactly the pinned key, and the quote's components are the endorsed ones.
Without such a record, with a record for another key (a substituted key file), from an endorser the policy does not
list, altered, or expired, other than the one the entry pins ("endorsement_sha256") or older than the policy's
"max_endorsement_age_s", the endpoint is refused without being contacted. `fleet.py enroll-endorsed POLICY RECORD...`
puts a record and its key into the policy's directory and pins the record in the entry, checked first and in an order
that leaves nothing trusted if it stops half way. Without the key in the entry the pinned key is whatever was first put there (`enroll-pq`, trust on
first use); every such endpoint is marked "trust-on-first-use" in its verdict and its journal line, with a line at
warning priority when the loop starts.

Standard evidence (docs/evidence-format.md): an entry with "evidence_format": "eat-cose-v1" is asked for an EAT in a
COSE_Sign1 signed with ML-DSA-65 (request PQEAT) instead of the older claims and detached signature (PQCHAL), which
stay the default: firmware in the field keeps working. The same policy rules apply to both. For every verdict the
loop signs an attestation result (an EAR in a COSE_Sign1, by this verifier's identity key) and keeps it, with the
evidence it appraised, under STATE_DIR/attestation/<name>/; `fleet.py export-evidence POLICY NAME` copies them, the
endorsement record and the public keys into one directory that tools/verify_evidence.py checks with third-party
libraries only.
"""
import argparse
import hashlib
import json
import os
import re
import secrets
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.abspath(os.path.join(HERE, "..", "..", "common")))
import psa_token  # noqa: E402
import kmac  # noqa: E402

PQ_LABEL = b"aegis-endpoint-quote-v1"
LINUX_PROFILE = "aegis-linux-software-v1"   # kind aegis-linux: key and measurements held by Linux, not by hardware
DEVICE_PROFILE = "aegis-rw612-els-v1"       # kind aegis-device: key from the chip's ELS, measurement by the firmware
DEVICE_TFM_PROFILE = "aegis-rw612-tfm-v1"   # the same chip with TF-M: key and measurements in the TrustZone secure side
# kinds whose quote is a plain CBOR claims map signed only with ML-DSA-65: {accepted profile: trust label}
TEE_DEVHUK_PROFILE = "aegis-zynqmp-optee-devhuk-v1"  # ZynqMP, OP-TEE: key in the secure world, from a fixed HUK
TEE_PROFILE = "aegis-zynqmp-optee-v1"         # ZynqMP, OP-TEE: key from the PUF-protected device key (design)
PLAIN_KINDS = {"aegis-linux": {LINUX_PROFILE: "software"},
               "aegis-device": {DEVICE_PROFILE: "device-key", DEVICE_TFM_PROFILE: "trustzone"},
               "aegis-tee": {TEE_DEVHUK_PROFILE: "development-shared-key", TEE_PROFILE: "trustzone"}}
# Profiles whose key is the same on every chip: a quote proves the firmware, not which device sent it. Refused unless
# the endpoint's entry opts in with "allow_dev_profile": true (bench use).
DEV_PROFILES = {TEE_DEVHUK_PROFILE}
PQ_KINDS = ("aegis-pq",) + tuple(PLAIN_KINDS)
KNOWN_KINDS = ("psa",) + PQ_KINDS
HEARTBEAT_MACS = ("kmac256", "sha3-256")
DEFAULT_HEARTBEAT_MAC = "kmac256"   # every current endpoint image; SHA-3-only images need "heartbeat_mac": "sha3-256"
ENFORCE_TIMEOUT_S = 30
KEM_INIT_LABEL = b"aegis-kem-init-v1"
CRED_LABEL = b"aegis-credential-v1"
CRED_LIFETIME_S = 3600
TRANSCRIPTS = ("v2",)               # policy key "transcript": the bound exchange is required
UNBOUND_NOTE = ('unbound: the session is not tied to the attestation (no "transcript": "v2" in the policy entry); '
                "weaker")
ENDORSEMENTS = ("required",)        # policy key "endorsement": the pinned key must be endorsed (common/endorsement.py)
ENDORSED, TOFU, NOT_ENDORSED = "endorsed", "trust-on-first-use", "refused"     # verdict["enrolment"]
# an entry's name becomes part of file names (keys, endorsements/<name>.json, credentials/<name>.json): the same rule as
# common/endorsement.py is_name()
ENTRY_NAME = re.compile(r"[A-Za-z0-9_-][A-Za-z0-9._-]{0,63}\Z")
RENEW_WARNING_S = 30 * 86400        # `check` warns when an endorsement stops being accepted sooner than this
EAT_COSE = "eat-cose-v1"            # policy key "evidence_format": EAT in COSE_Sign1, ML-DSA-65 (common/cose.py, eat.py)
EVIDENCE_FORMATS = (EAT_COSE,)
LEGACY_QUOTE = "aegis-quote-v1"     # the default: claims or a PSA token, and a detached ML-DSA-65 signature over
#                                     "aegis-endpoint-quote-v1" || 0x00 || token
PSA_TOKEN = "psa-token"             # kind psa: TF-M's token alone (COSE_Sign1, ES256)
PACK_FORMAT = "aegis-evidence-pack-v1"
TOFU_NOTE = ('trust on first use: nothing shows that the pinned key belongs to a genuine device (no "endorsement": '
             '"required" in the policy entry); weaker')


class TranscriptRefused(ValueError):
    """The endpoint's answer does not continue the transcript of the quote this verifier appraised."""


class EndpointBusy(ConnectionError):
    """The endpoint reset or closed the connection before sending a single byte. The STM32 and RW612 provers serve one
    connection at a time and reset a second one at once (tcp_abort in on_accept), so this is what a request sees while
    another verifier is talking to the endpoint."""


BUSY_RETRIES = 3            # attempts after the first, for requests that change nothing on the endpoint
BUSY_BACKOFF_S = (0.4, 1.2)  # random pause before each retry, so two verifiers that collided do not collide again


def _send_line(host, port, line, timeout, limit):
    """One request line on a fresh connection; the first reply line. EndpointBusy if the endpoint reset the connection
    or closed it without a byte."""
    got = False
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            s.sendall(line + b"\n")
            buf = b""
            while b"\n" not in buf and len(buf) < limit:
                chunk = s.recv(min(limit, 65536))
                if not chunk:
                    break
                got = True
                buf += chunk
    except (ConnectionResetError, BrokenPipeError) as e:
        if got:
            raise
        raise EndpointBusy("endpoint reset the connection (busy with another verifier?): %s" % e) from e
    if not got:
        raise EndpointBusy("endpoint closed the connection without a reply (busy with another verifier?)")
    return buf.split(b"\n")[0].strip().decode(errors="replace")


def _request(host, port, line, timeout, limit=16384, retry_busy=True):
    """_send_line, retried while the endpoint is busy. Only for requests that are safe to repeat: a quote (fresh
    challenge every time), the public key, the session id and the heartbeat (fresh nonce; its counter rises anyway).
    A connection the endpoint resets at accept was never processed, so a retry is the first attempt it sees."""
    import random
    attempts = 1 + (BUSY_RETRIES if retry_busy else 0)
    for i in range(attempts):
        try:
            return _send_line(host, port, line.encode() if isinstance(line, str) else line, timeout, limit)
        except EndpointBusy:
            if i == attempts - 1:
                raise
            time.sleep(random.uniform(*BUSY_BACKOFF_S))


def request_token(host, port, challenge, timeout):
    line = _request(host, port, b"CHAL " + challenge.hex().encode(), timeout, limit=4096)
    parts = line.split()
    if len(parts) != 4 or parts[0] != "TOKEN" or parts[3] != "END":
        raise ValueError("no token in reply: %r" % line[:40])
    tok = bytes.fromhex(parts[2])
    if len(tok) != int(parts[1]):
        raise ValueError("token length mismatch")
    return tok


def request_pq(host, port, challenge, timeout):
    """Aegis PQ quote: returns (token, ML-DSA-65 signature)."""
    line = _request(host, port, "PQCHAL " + challenge.hex(), timeout)
    p = line.split()
    if len(p) != 6 or p[0] != "PQTOKEN" or p[5] != "END":
        raise ValueError("no PQ quote in reply: %r" % line[:40])
    tok, sig = bytes.fromhex(p[2]), bytes.fromhex(p[4])
    if len(tok) != int(p[1]) or len(sig) != int(p[3]):
        raise ValueError("PQ quote length mismatch")
    return tok, sig


def request_eat(host, port, challenge, timeout):
    """Standard evidence: the endpoint's EAT for this challenge, a COSE_Sign1 (docs/evidence-format.md)."""
    line = _request(host, port, "PQEAT " + challenge.hex(), timeout)
    p = line.split()
    if len(p) != 4 or p[0] != "PQEAT" or p[3] != "END":
        raise ValueError("no EAT evidence in reply: %r" % line[:40])
    ev = bytes.fromhex(p[2])
    if len(ev) != int(p[1]):
        raise ValueError("EAT evidence length mismatch")
    return ev


def request_pq_key(host, port, timeout=10):
    line = _request(host, port, "PQKEY", timeout)
    p = line.split()
    if len(p) != 4 or p[0] != "PQKEY" or p[3] != "END":
        raise ValueError("no PQ key in reply: %r" % line[:40])
    pk = bytes.fromhex(p[2])
    if len(pk) != int(p[1]):
        raise ValueError("PQ key length mismatch")
    return pk


def _exchange(host, port, line, timeout):
    """One request, one attempt: KEM provisioning steps are never repeated (a PQKEMINIT replaces the pending
    exchange). EndpointBusy if the endpoint answered nothing."""
    return _request(host, port, line, timeout, limit=65536, retry_busy=False)


def _sha3(*parts):
    import hashlib
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def provision(ep, base_dir, gw_sk, gw_identity_sha256, measurements, timeout=30.0, quote=None, endorsers=None,
              expect_pk_sha256=None):
    """ML-KEM-768 provisioning of an admitted aegis-pq endpoint.

    Without "transcript" in the entry (the first version; nothing ties it to the attestation):
    1. gateway nonce -> endpoint returns a fresh ML-KEM-768 encapsulation key, signed with its
       enrolled ML-DSA-65 key (so the key cannot be swapped on the way);
    2. gateway encapsulates (ct, K) and sends ct with a credential signed by the gateway's own
       ML-DSA-65 identity key;
    3. endpoint decapsulates and answers a key-confirmation tag; the gateway accepts only if the
       tag equals SHA3-256("aegis-confirm-v1" || K || nonce || SHA3(ct) || SHA3(credential)).
    Both sides then hold session = SHA3-256("aegis-session-v1" || K || nonce || SHA3(ct)).

    With "transcript": "v2" (common/transcript.py): quote is attest()'s record of the quote just appraised,
    {"challenge", "token_sha3_256"} in hex, and the same three messages continue its transcript:
    1. PQKEMINIT carries that quote's challenge; the endpoint's signature must be over
       T2 = H(kem-init || T1 || ek), T1 = H(quote || challenge || SHA3(token)), label "aegis-kem-init-v2". A signature
       of the first version, or one over another quote, is refused (TranscriptRefused) before anything is sent back;
    2. the credential names T2 ("transcript_sha3_256") next to the ciphertext and the key;
    3. the tag must equal SHA3-256("aegis-confirm-v2" || K || T3), T3 = H(kem-fin || T2 || SHA3(ct) || SHA3(cred)).
    Both sides then hold session = SHA3-256("aegis-session-v2" || K || T3).

    The endpoint's key is the pinned one, and for an entry with "endorsement": "required" only if it is endorsed
    (device_key(); endorsers is the policy's "endorsers"). expect_pk_sha256, if given, is the key this cycle's quote
    was verified with: a key file that changed since is refused before anything is sent.
    Returns a dict; raises ValueError on any failure."""
    import hmac
    import mldsa
    import mlkem
    import transcript
    import wire
    host, port = ep["host"], int(ep["port"])
    bound = ep.get("transcript") is not None
    if bound and ep["transcript"] not in TRANSCRIPTS:
        raise ValueError("unknown transcript %r" % (ep["transcript"],))
    pk, _ = device_key(ep, base_dir, endorsers)
    if expect_pk_sha256 is not None and hashlib.sha256(pk).hexdigest() != expect_pk_sha256:
        raise ValueError("the pinned key changed since this cycle's quote was verified")
    if bound:
        try:
            challenge, tok_hash = bytes.fromhex(quote["challenge"]), bytes.fromhex(quote["token_sha3_256"])
            t1 = transcript.quote(challenge, tok_hash)
        except (TypeError, KeyError, ValueError):
            raise TranscriptRefused("transcript v2: no appraised quote of this cycle to continue") from None
        nonce = challenge       # the one verifier nonce of the transcript: it names the quote to the endpoint
    else:
        nonce = secrets.token_bytes(32)
    p = _exchange(host, port, "PQKEMINIT " + nonce.hex(), timeout).split()
    # bound: any answer that is not a signed continuation of the quote is refused the same way, malformed or not
    bad = TranscriptRefused if bound else ValueError
    if len(p) != 6 or p[0] != "PQKEMEK" or p[5] != "END":
        raise bad("no KEM key in reply: %r" % " ".join(p)[:40])
    try:
        ek, sig = bytes.fromhex(p[2]), bytes.fromhex(p[4])
    except ValueError:
        raise bad("KEM key or signature is not hex") from None
    if len(ek) != mlkem.EK_LEN:
        raise bad("ML-KEM key of the wrong length")
    if bound:
        t2 = transcript.kem_init(t1, ek)
        if not mldsa.verify(pk, transcript.KEM_INIT_LABEL, t2, sig):
            if mldsa.verify(pk, KEM_INIT_LABEL, nonce + ek, sig):
                raise TranscriptRefused("transcript v2 required, but the endpoint answered the unbound exchange: its "
                                        "ML-KEM key is not tied to the quote just appraised (firmware without "
                                        "transcript v2, a restart or another quote in between)")
            raise TranscriptRefused("ML-KEM key not signed over the transcript of the quote just appraised")
    elif not mldsa.verify(pk, KEM_INIT_LABEL, nonce + ek, sig):
        raise ValueError("ML-KEM key not signed by the enrolled endpoint key")
    ct, k = mlkem.encaps(ek)
    now = int(time.time())
    body = {"v": 1, "type": "credential", "endpoint": ep["name"],
            "endpoint_pq_pk_sha256": hashlib.sha256(pk).hexdigest(),
            "measurements": measurements, "kem": "ML-KEM-768", "kem_ct_sha3_256": _sha3(ct).hex(), "kem_ek_sha3_256": _sha3(ek).hex(),
            "issued": now, "expires": now + CRED_LIFETIME_S, "gateway_identity_sha256": gw_identity_sha256}
    if bound:
        # T2 alone: it covers the quote, and the body must stay small (the STM32 partition verifies at most 1214
        # bytes of it); the quote itself is kept beside the credential in this verifier's state
        body.update({"transcript": transcript.VERSION, "transcript_sha3_256": t2.hex()})
    cred = wire.canonical(body) + b"\n" + mldsa.sign(gw_sk, CRED_LABEL, wire.canonical(body))
    p = _exchange(host, port, "PQKEMFIN %s %s" % (ct.hex(), cred.hex()), timeout).split()
    if len(p) != 3 or p[0] != "PQKEMOK" or p[2] != "END":
        raise ValueError("provisioning refused by endpoint: %r" % " ".join(p)[:40])
    if bound:
        t3 = transcript.kem_fin(t2, ct, cred)
        expect, session = transcript.confirm_tag(k, t3), transcript.session_key(k, t3)
    else:
        expect = _sha3(b"aegis-confirm-v1", k, nonce, _sha3(ct), _sha3(cred))
        session = _sha3(b"aegis-session-v1", k, nonce, _sha3(ct))
    try:
        tag = bytes.fromhex(p[1])
    except ValueError:
        raise ValueError("key confirmation is not hex") from None
    if not hmac.compare_digest(tag, expect):
        raise ValueError("key confirmation failed")
    session_id = _sha3(b"aegis-session-id-v1", session)
    return {"credential": cred, "body": body, "session_key": session, "session_id": session_id.hex(),
            "credential_sha3_256": _sha3(cred).hex(), "transcript": transcript.VERSION if bound else None,
            "transcript_sha3_256": t3.hex() if bound else None,
            "quote": {"challenge": challenge.hex(), "token_sha3_256": tok_hash.hex()} if bound else None}


def quote_to_continue(ep, base_dir, ecdsa_verify=None, timeout=10.0, endorsers=None):
    """For tools that run provision() outside the loop (tests/board): the quote a session of this entry must
    continue, from an attestation made now, or None where the entry does not ask for the transcript. As in the loop,
    only an admitted endpoint gets a session: ValueError with the reasons otherwise."""
    if ep.get("transcript") is None:
        return None
    v = attest(ep, ecdsa_verify or psa_token.verify_with_openssl_cli, base_dir, timeout, endorsers)
    if not v["admitted"]:
        raise ValueError("not admitted, so no session: %s" % "; ".join(v["reasons"]))
    return v["quote"]


def heartbeat_tag(mode, session_key, nonce, ctr, status):
    """The heartbeat MAC. Policy key "heartbeat_mac" per endpoint:
    "kmac256" (default): KMAC256(K=session, X=nonce || counter || status, L=256, S="aegis-hb-v2")  (SP 800-185)
    "sha3-256":          SHA3-256("aegis-hb-v1" || session || nonce || counter || status)        (the first version)
    Both sides must use the same one. Every endpoint image in endpoints/ computes KMAC256 (the STM32 partition unless
    built with AEGIS_HB_KMAC=0, the RW612 and ZynqMP TA always, the Linux prover by default); an endpoint still on a
    SHA-3 image needs "heartbeat_mac": "sha3-256" in its entry."""
    if mode is None:
        mode = DEFAULT_HEARTBEAT_MAC
    if mode == "kmac256":
        return kmac.kmac256(session_key, nonce + ctr + status, 32, b"aegis-hb-v2")
    if mode == "sha3-256":
        return _sha3(b"aegis-hb-v1", session_key, nonce, ctr, status)
    raise ValueError("unknown heartbeat_mac %r" % mode)


def heartbeat(ep, session_key, timeout=10.0):
    """Fresh nonce -> (status bytes, counter); raises ValueError unless the endpoint's tag equals
    heartbeat_tag(ep["heartbeat_mac"], ...)."""
    import hmac
    nonce = secrets.token_bytes(32)
    p = _request(ep["host"], int(ep["port"]), "PQHB " + nonce.hex(), timeout, limit=65536).split()
    if len(p) != 5 or p[0] != "PQHB" or p[4] != "END":
        raise ValueError("no heartbeat: %r" % " ".join(p)[:40])
    status, ctr, tag = bytes.fromhex(p[1]), bytes.fromhex(p[2]), bytes.fromhex(p[3])
    expect = heartbeat_tag(ep.get("heartbeat_mac"), session_key, nonce, ctr, status)
    if len(ctr) != 8 or not hmac.compare_digest(tag, expect):
        raise ValueError("heartbeat tag invalid")
    return status, int.from_bytes(ctr, "little")


def query_session(ep, timeout=10.0):
    p = _request(ep["host"], int(ep["port"]), "PQSESSION", timeout).split()
    if len(p) != 4 or p[0] != "PQSESSION" or p[3] != "END":
        raise ValueError("no session: %r" % " ".join(p)[:40])
    return p[1], p[2]


def check_components(claims, allowed):
    """allowed: list of {type, measurement_value, signer_id}. Returns list of reasons."""
    reasons = []
    comps = claims.get("sw_components", [])
    if not comps:
        return ["token has no software components"]
    if not isinstance(comps, list):
        return ["sw_components is not a list"]
    for c in comps:
        if not isinstance(c, dict):
            reasons.append("malformed software component")
            continue
        typ = c.get("measurement_type")
        mv = c.get("measurement_value", b"")
        sid = c.get("signer_id", b"")
        mv = mv.hex() if isinstance(mv, bytes) else mv
        sid = sid.hex() if isinstance(sid, bytes) else sid
        if not isinstance(mv, str) or not isinstance(sid, str):
            reasons.append("component %r has a malformed measurement or signer" % (typ,))
            continue
        ok = any(a["type"] == typ and a["measurement_value"] == mv and a.get("signer_id", sid) == sid
                 for a in allowed)
        if not ok:
            reasons.append("component %s not allowed (measurement %s...)" % (typ, mv[:12]))
    return reasons


def endorsed_components(claims, endorsed):
    """Reasons a quote's components are not exactly the ones its endorsement names (common/endorsement.py)."""
    import endorsement

    def text(v):
        return v.hex() if isinstance(v, bytes) else v
    comps = claims.get("sw_components", [])
    if not isinstance(comps, list):
        return ["endorsement: sw_components is not a list"]
    if not all(isinstance(c, dict) for c in comps):
        return ["endorsement: a software component is not a map"]
    reported = [(c.get("measurement_type"), text(c.get("measurement_value")),
                 text(c["signer_id"]) if "signer_id" in c else None) for c in comps]
    return ["endorsement: %s" % r for r in endorsement.measurement_reasons(reported, endorsed)]


def _path(base_dir, p):
    return p if os.path.isabs(p) else os.path.join(base_dir, p)


def endorsement_file(ep, base_dir):
    """Where an entry's endorsement record lives: "endorsement_file", else endorsements/<name>.json beside the
    policy."""
    return _path(base_dir, ep.get("endorsement_file") or os.path.join("endorsements", "%s.json" % ep["name"]))


def _endorsed_family(ep):
    kind = ep.get("kind", "psa")
    return kind, (ep.get("profile") if kind in PLAIN_KINDS else None)


def device_key(ep, base_dir, endorsers=None, now=None):
    """The ML-DSA-65 key this verifier trusts for an entry, and how it came to be trusted: (public key, None) for a
    key pinned by trust on first use, (public key, endorsement) for an entry with "endorsement": "required", where
    endorsement is the record's body with "endorser_name" (the policy's name for the signing key) and "record_sha256".
    Everything that verifies something with the pinned key takes it from here.

    Raises endorsement.Refused (a ValueError) if the entry requires an endorsement and there is no record, or the
    record is not signed by a trusted endorser of the policy (endorsers: the policy's "endorsers"), or it names
    another device, family or key than the entry and the pinned key file, or it has expired. OSError or ValueError if
    the key file itself is missing or not hex."""
    mode = ep.get("endorsement")
    try:
        with open(_path(base_dir, ep["pq_pub_file"])) as f:
            pk = bytes.fromhex(f.read().strip())
    except FileNotFoundError:
        if mode is None:
            raise
        import endorsement
        raise endorsement.Refused("no key is pinned for %s (%s): enrol the device with `fleet.py enroll-endorsed`"
                                  % (ep["name"], _path(base_dir, ep["pq_pub_file"]))) from None
    if mode is None:
        return pk, None
    import endorsement
    if mode not in ENDORSEMENTS:
        raise endorsement.Refused("unknown endorsement %r" % (mode,))
    trust = endorsement.trusted(endorsers, base_dir)
    if not trust:
        raise endorsement.Refused('the policy lists no trusted endorsers ("endorsers")')
    rec = endorsement.load(endorsement_file(ep, base_dir))
    kind, profile = _endorsed_family(ep)
    now = time.time() if now is None else now
    body = endorsement.check(rec, trust, ep["name"], kind, profile, pk, now)
    return pk, dict(body, record_sha256=_current_record(ep, rec, body, now))


def _current_record(ep, rec, body, now):
    """The record's name (record_sha256) if it is the one the entry pins and young enough; Refused otherwise.

    "endorsement_sha256" in an entry names the one record the verifier accepts for it (enroll-endorsed writes it): an
    older record of the same endorser for the same device and key, copied back with its key, is then refused.
    "max_endorsement_age_s" (in the entry, or at the top of the policy: effective_entry()) refuses a record issued
    longer ago than that on this verifier's clock."""
    import endorsement
    name = endorsement.record_sha256(rec)
    pin = ep.get("endorsement_sha256")
    if pin is not None and pin != name:
        raise endorsement.Refused("the record (%s...) is not the one the policy pins (endorsement_sha256 %s...): an "
                                  "older or another record" % (name[:16], str(pin)[:16]))
    max_age = ep.get("max_endorsement_age_s")
    if max_age is not None and now - body["issued"] > max_age:
        raise endorsement.Refused("the endorsement is older than max_endorsement_age_s %d (issued %d, now %d)"
                                  % (max_age, body["issued"], int(now)))
    return name


def effective_entry(policy, ep):
    """The entry as the verifier applies it: policy-wide settings that the entry does not set itself, merged in."""
    if isinstance(ep, dict) and "max_endorsement_age_s" in policy and "max_endorsement_age_s" not in ep:
        return dict(ep, max_endorsement_age_s=policy["max_endorsement_age_s"])
    return ep


def enrolment_note(ep, base_dir, endorsers=None):
    """For `check` and the start of `watch`: (how an entry's key is trusted, whether that is a refusal)."""
    if ep.get("endorsement") is None:
        return "enrolment: %s" % TOFU_NOTE, False
    now = time.time()
    try:
        _, e = device_key(ep, base_dir, endorsers, now)
    except (OSError, ValueError) as err:
        return "enrolment: endorsement REFUSED: %s" % err, True
    ends = []
    if "expires" in e:
        ends.append((e["expires"], "the record expires"))
    if ep.get("max_endorsement_age_s") is not None:
        ends.append((e["issued"] + ep["max_endorsement_age_s"], "the record reaches max_endorsement_age_s"))
    note = "enrolment: endorsed by %s (record %s..., %s, device key %s..., device state %s, issued %s%s)" % (
        e["endorser_name"], e["record_sha256"][:12],
        "pinned by endorsement_sha256" if ep.get("endorsement_sha256") else
        "NOT pinned: no endorsement_sha256, an older record of this endorser for this key would be accepted",
        e["device_pk_sha256"][:16], e["device_state"], time.strftime("%Y-%m-%d", time.gmtime(e["issued"])),
        "".join(", %s on %s" % (what, time.strftime("%Y-%m-%d", time.gmtime(t))) for t, what in sorted(ends)))
    if ends:
        t, what = min(ends)
        if t - now < RENEW_WARNING_S:
            note += "; WARNING: %s in %.1f days: endorse the device again" % (what, (t - now) / 86400)
    return note, False


def install_endorsement(policy, base_dir, record_path, force=False, policy_path=None):
    """Enrol one device from its endorsement record (the file provision/aegis_provision.py wrote): put the record and
    the device key it carries where the policy's entry for that device looks for them and, with policy_path (the file
    policy was read from), pin that record in the entry ("endorsement_sha256"). Returns (name, body).

    Checked before anything is written: the record is signed by a trusted endorser of this policy and names an entry
    of it, that entry's family, and the key it carries; it is not older than max_endorsement_age_s. A different key
    already pinned for the entry, or a record issued before the one installed now, is kept unless force (as enroll-pq
    does). Then every file is written under a temporary name and renamed into place: the record first, the key next,
    the policy last (its previous content kept as POLICY.bak). If anything fails, what was there before is put back;
    if the process dies between the renames, the entry has a record without its key (or with the old key, which the
    record does not name), or a record and key that the old pin does not name, and nothing is trusted that was not
    before. Raises endorsement.Refused or OSError; nothing is trusted then."""
    import endorsement
    rec = endorsement.load(record_path)
    if "device_pk" not in rec:
        raise endorsement.Refused("the record does not carry the device key (device_pk)")
    pk = bytes.fromhex(rec["device_pk"])
    name = rec["body"]["device"]
    eps = [e for e in policy.get("endpoints", []) if isinstance(e, dict) and e.get("name") == name]
    if len(eps) != 1:
        raise endorsement.Refused("the policy has %s entry named %r" % ("no" if not eps else "more than one", name[:40]))
    ep = eps[0]
    applied = effective_entry(policy, ep)
    errors = policy_errors(applied)
    if errors:
        raise endorsement.Refused("; ".join(errors))
    if ep.get("kind") not in PQ_KINDS:
        raise endorsement.Refused("entry %s is kind %s, which has no post-quantum key to endorse" % (name, ep.get("kind", "psa")))
    trust = endorsement.trusted(policy.get("endorsers"), base_dir)
    if not trust:
        raise endorsement.Refused('the policy lists no trusted endorsers ("endorsers")')
    kind, profile = _endorsed_family(ep)
    now = time.time()
    body = endorsement.check(rec, trust, name, kind, profile, pk, now)
    record_name = _current_record({k: v for k, v in applied.items() if k != "endorsement_sha256"}, rec, body, now)
    key_path, rec_path = _path(base_dir, ep["pq_pub_file"]), endorsement_file(ep, base_dir)

    def previous(path):
        try:
            with open(path, "rb") as f:
                return f.read()
        except FileNotFoundError:
            return None
    old_key, old_rec = previous(key_path), previous(rec_path)
    if old_key is not None and old_key.strip().lower() != rec["device_pk"].encode() and not force:
        raise endorsement.Refused("another key is already pinned for %s in %s (--force replaces it)" % (name, key_path))
    try:
        old_issued = endorsement.loads(old_rec)["body"]["issued"] if old_rec is not None else None
    except endorsement.Refused:
        old_issued = None
    if old_issued is not None and old_issued > body["issued"] and not force:
        raise endorsement.Refused("the record installed for %s was issued later (%d) than this one (%d): an older "
                                  "record does not replace a newer one (--force does)" % (name, old_issued, body["issued"]))
    new_policy = old_policy = None
    if policy_path is not None:
        # the file as it is now, so that nothing someone changed since it was read is lost; the entry itself must be
        # the one that was checked
        old_policy = previous(policy_path)
        try:
            on_disk = json.loads(old_policy.decode()) if old_policy is not None else None
        except ValueError:
            on_disk = None
        mine = [e for e in (on_disk or {}).get("endpoints", []) if isinstance(e, dict) and e.get("name") == name]
        if len(mine) != 1 or mine[0] != ep:
            raise endorsement.Refused("the entry for %s in %s changed since it was read: run the command again"
                                      % (name, policy_path))
        mine[0]["endorsement_sha256"] = record_name
        new_policy = (json.dumps(on_disk, indent=1) + "\n").encode()
    staged, done = [], []
    try:
        steps = [(rec_path, endorsement.dumps(rec), old_rec, 0o644),
                 (key_path, rec["device_pk"].encode() + b"\n", old_key, 0o644)]
        if new_policy is not None:
            endorsement.write_atomic(policy_path + ".bak", old_policy, os.stat(policy_path).st_mode & 0o777)
            steps.append((policy_path, new_policy, old_policy, os.stat(policy_path).st_mode & 0o777))
        for path, data, old, mode in steps:
            staged.append((endorsement.stage(path, data, mode), path, old, mode))
        for tmp, path, old, mode in staged:
            endorsement.commit(tmp, path)
            done.append((path, old, mode))
    except BaseException:
        for tmp, *_ in staged:
            endorsement.discard(tmp)
        for path, old, mode in reversed(done):      # put back what was there, the last one first
            try:
                if old is None:
                    os.unlink(path)
                else:
                    endorsement.write_atomic(path, old, mode)
            except OSError:
                pass                # the record stays without its key, or unpinned: still nothing new trusted
        raise
    if new_policy is not None:
        ep["endorsement_sha256"] = record_name
    return name, dict(body, record_sha256=record_name)


def policy_errors(ep):
    """Reasons an endpoint entry is refused before the endpoint is even asked (strict profiles). Empty if the entry
    is acceptable."""
    kind = ep.get("kind", "psa")
    if not (isinstance(ep.get("name"), str) and ENTRY_NAME.match(ep["name"])):
        # it becomes part of file names: "../x" must not reach outside the policy's and the state's directories
        return ["policy: the entry's name %r is not a name (letters, digits, '.', '_', '-', at most 64, no leading "
                "dot)" % (str(ep.get("name"))[:40],)]
    if kind not in KNOWN_KINDS:
        return ["policy: unknown kind %r" % kind]
    errors = []
    if kind == "psa" and not ep.get("iak_pub_pem"):
        errors.append("policy: kind psa without iak_pub_pem (unsigned tokens are not accepted)")
    if kind in PQ_KINDS and not ep.get("pq_pub_file"):
        errors.append("policy: kind %s without pq_pub_file" % kind)
    if kind in PLAIN_KINDS:
        pin, accepted = ep.get("profile"), PLAIN_KINDS[kind]
        if not pin:
            errors.append("policy: no profile pinned (kind %s needs \"profile\": %s)" % (kind, " or ".join(sorted(accepted))))
        elif pin not in accepted:
            errors.append("policy: pinned profile %s is not one of kind %s (%s)" % (pin, kind, " or ".join(sorted(accepted))))
        elif pin in DEV_PROFILES and ep.get("allow_dev_profile") is not True:
            errors.append("policy: profile %s is a development profile (one key for every chip); "
                          "set \"allow_dev_profile\": true to admit it on the bench" % pin)
    pin = ep.get("verifier_pin_sha256")
    if pin is not None and not (isinstance(pin, str) and len(pin) == 64 and all(c in "0123456789abcdefABCDEF" for c in pin)):
        errors.append("policy: verifier_pin_sha256 is not 64 hex digits")
    mac = ep.get("heartbeat_mac")
    if mac is not None and mac not in HEARTBEAT_MACS:
        errors.append("policy: unknown heartbeat_mac %r" % mac)
    tr = ep.get("transcript")
    if tr is not None and tr not in TRANSCRIPTS:
        # a value this verifier does not know must not fall back to the unbound exchange
        errors.append("policy: unknown transcript %r (known: %s)" % (tr, ", ".join(TRANSCRIPTS)))
    elif tr is not None and kind not in PQ_KINDS:
        errors.append("policy: transcript %s needs a post-quantum kind (%s)" % (tr, ", ".join(PQ_KINDS)))
    en = ep.get("endorsement")
    if en is not None and en not in ENDORSEMENTS:
        # a value this verifier does not know must not fall back to trust on first use
        errors.append("policy: unknown endorsement %r (known: %s)" % (en, ", ".join(ENDORSEMENTS)))
    elif en is not None and kind not in PQ_KINDS:
        errors.append("policy: endorsement %s needs a post-quantum kind (%s)" % (en, ", ".join(PQ_KINDS)))
    elif en is not None and ep.get("profile") in DEV_PROFILES:
        errors.append("policy: profile %s has one key for every chip, so no endorsement can tie it to one device"
                      % ep["profile"])
    pin = ep.get("endorsement_sha256")
    if pin is not None and not (isinstance(pin, str) and len(pin) == 64 and all(c in "0123456789abcdef" for c in pin)):
        errors.append("policy: endorsement_sha256 is not 64 lower-case hex digits")
    age = ep.get("max_endorsement_age_s")
    if age is not None and not (isinstance(age, int) and not isinstance(age, bool) and age > 0):
        errors.append("policy: max_endorsement_age_s is not a positive whole number of seconds")
    fmt = ep.get("evidence_format")
    if fmt is not None and fmt not in EVIDENCE_FORMATS:
        # a value this verifier does not know must not fall back to the older format
        errors.append("policy: unknown evidence_format %r (known: %s)" % (fmt, ", ".join(EVIDENCE_FORMATS)))
    elif fmt is not None and kind not in PQ_KINDS:
        errors.append("policy: evidence_format %s needs a post-quantum kind (%s)" % (fmt, ", ".join(PQ_KINDS)))
    return errors


def policy_warnings(ep):
    if ep.get("allow_dev_profile") is True and ep.get("profile") in DEV_PROFILES:
        return ["WARNING: %s may be admitted on development profile %s: its key is the same on every chip"
                % (ep.get("name"), ep["profile"])]
    return []


def binding_note(ep):
    """For `check` and the start of `watch`: how a provisioned endpoint's session is tied to its attestation."""
    if not ep.get("provision"):
        return None
    if ep.get("transcript") in TRANSCRIPTS:
        return "session bound to the attestation (transcript %s required; the unbound exchange is refused)" % ep["transcript"]
    return "session %s" % UNBOUND_NOTE


def attest(ep, ecdsa_verify, base_dir, timeout=10.0, endorsers=None, facts=None):
    """kind "psa": PSA token signed by the endpoint's IAK (ES256).
    kind "aegis-pq": the same token plus an ML-DSA-65 signature by the endpoint's enrolled
    post-quantum key; the ML-DSA check is mandatory, the ES256 check runs only if an
    iak_pub_pem is configured.
    kind "aegis-linux": a plain CBOR claims map (PSA claim numbers, profile aegis-linux-software-v1) signed only
    with the endpoint's ML-DSA-65 key. The key and the measurements are held by Linux, not by hardware: the verdict
    says so ("trust": "software").
    kind "aegis-device": the same plain claims from a microcontroller whose ML-DSA-65 key is derived inside the chip's
    key store (NXP ELS) and never stored. Profile aegis-rw612-els-v1: the firmware measures itself, "trust":
    "device-key" (the key proves the chip, not the firmware). Profile aegis-rw612-tfm-v1: the key and the measurements
    (SPE, NSPE) are in a TF-M secure partition that the non-secure image cannot reach, "trust": "trustzone".
    Plain-claims kinds must pin the profile ("profile": ...); see policy_errors() for what is refused up front.
    An entry with "endorsement": "required" is refused, without being contacted, unless device_key() finds its pinned
    key endorsed by one of endorsers (the policy's "endorsers"); its quote must then report exactly the endorsed
    components, besides passing the policy's "allowed". verdict["enrolment"] says which way the key is trusted.
    An entry with "evidence_format": "eat-cose-v1" is asked for standard evidence (PQEAT): an EAT in a COSE_Sign1
    signed with the same ML-DSA-65 key (common/cose.py, common/eat.py). Its claims go through the same rules; an
    answer in the older format is then not accepted, and the other way round.
    facts, if given, is a dict that receives what an attestation result needs and the verdict does not carry
    (attestation_result()): "stage" (policy, endorsement, no-evidence, evidence, appraised: how far it got),
    "format", "evidence" and "evidence_sig" (the bytes received), "signature" (False, True; absent if not checked),
    "nonce", "ueid", "platform", "components", "components_ok".
    Never raises for anything the endpoint sends, nor for anything an endorsement record contains."""
    kind = ep.get("kind", "psa")
    verdict = {"endpoint": ep["name"], "kind": kind, "time": int(time.time()), "admitted": False, "reasons": []}
    facts = {} if facts is None else facts
    facts.clear()
    facts["stage"] = "policy"
    errors = policy_errors(ep)
    if errors:
        verdict["reasons"] += errors
        return verdict
    eat_format = ep.get("evidence_format") == EAT_COSE
    facts["format"] = EAT_COSE if eat_format else LEGACY_QUOTE if kind in PQ_KINDS else PSA_TOKEN
    if eat_format:
        verdict["evidence_format"] = EAT_COSE
    pk = endorsed = None
    facts["stage"] = "endorsement"
    if kind in PQ_KINDS and ep.get("endorsement") is not None:
        try:
            pk, endorsed = device_key(ep, base_dir, endorsers)
        except Exception as e:  # noqa: BLE001 - Refused, a missing key file, or whatever a hostile record provokes
            verdict["enrolment"] = NOT_ENDORSED
            verdict["reasons"].append("endorsement required: %s" % (e if isinstance(e, (ValueError, OSError)) else
                                                                    "%s: %s" % (type(e).__name__, e)))
            return verdict
        verdict["enrolment"] = ENDORSED
        verdict["endorsement"] = {k: endorsed[k] for k in ("endorser_name", "endorser_pk_sha256", "record_sha256",
                                                           "device_pk_sha256", "device_state", "issued", "expires",
                                                           "serial") if k in endorsed}
    elif kind in PQ_KINDS:
        verdict["enrolment"] = TOFU
    challenge = secrets.token_bytes(32)
    t0 = time.monotonic()
    sig = ev = None
    facts["stage"] = "no-evidence"
    try:
        if eat_format:
            tok = request_eat(ep["host"], int(ep["port"]), challenge, timeout)
        elif kind in PQ_KINDS:
            tok, sig = request_pq(ep["host"], int(ep["port"]), challenge, timeout)
        else:
            tok = request_token(ep["host"], int(ep["port"]), challenge, timeout)
    except (OSError, ValueError) as e:
        verdict["reasons"].append("no attestation: %s" % e)
        verdict["elapsed_s"] = round(time.monotonic() - t0, 3)
        return verdict
    verdict["elapsed_s"] = round(time.monotonic() - t0, 3)
    facts.update(stage="evidence", evidence=tok, evidence_sig=sig)
    try:
        if kind in PQ_KINDS:
            import mldsa
            if pk is None:
                pk, _ = device_key(ep, base_dir)
            not_the_key = " (the device that answered does not hold the endorsed key)" if endorsed else ""
            if eat_format:
                import cose
                import eat
                try:
                    cose.parse(tok)                 # not an Aegis COSE_Sign1 at all: refused before any key is used
                    facts["signature"] = False
                    signed = cose.verify1(tok, pk)
                except cose.Refused as e:
                    verdict["reasons"].append("EAT evidence refused: %s%s" % (
                        e, not_the_key if "signature" in facts else ""))
                    return verdict
                signed_bytes = signed.tbs           # the COSE Sig_structure: what the ML-DSA-65 signature covers
            else:
                facts["signature"] = False
                if not mldsa.verify(pk, PQ_LABEL, tok, sig):
                    verdict["reasons"].append("ML-DSA-65 quote signature invalid" + not_the_key)
                    return verdict
                signed_bytes = tok
            facts["signature"] = True
            verdict["pq_signature"] = "ML-DSA-65 valid"
            verdict["device_pk_sha256"] = hashlib.sha256(pk).hexdigest()
            # the quote as signed, for the transcript a session of this cycle must continue (provision()); both
            # values went over the network in the clear. For standard evidence the signed bytes are the COSE
            # Sig_structure of the evidence (docs/evidence-format.md, "The transcript").
            verdict["quote"] = {"challenge": challenge.hex(), "token_sha3_256": _sha3(signed_bytes).hex()}
            if eat_format:
                ev = eat.read_evidence(signed.payload, pk)
                facts.update(ueid=ev["ueid"], dbgstat=ev["dbgstat"])
                if (ev["components"] is None) != (kind not in PLAIN_KINDS):
                    verdict["reasons"].append("EAT evidence refused: an endpoint of kind %s reports %s" % (kind, (
                        "the platform's token, not measurements" if kind in PLAIN_KINDS else
                        "measurements, not the platform's token")))
                    return verdict
                tok = ev["platform_token"]          # kind aegis-pq: TF-M's token, nested; None otherwise
        if kind in PLAIN_KINDS:
            if ev is not None:
                claims = {"profile": ev["platform"], "challenge": ev["nonce"], "instance_id": ev["ueid"],
                          "sw_components": ev["components"]}
            else:
                claims = psa_token.parse_plain(tok)
            profile = claims.get("profile")
            accepted = PLAIN_KINDS[kind]
            if profile not in accepted:
                verdict["reasons"].append("profile is not %s" % " or ".join(sorted(accepted)))
                return verdict
            # The RW612 derives the same key under either firmware, so the policy pins the profile it expects (now
            # mandatory, policy_errors()): without the pin, the single-image prover could pass as the TrustZone one.
            if profile != ep["profile"]:
                verdict["reasons"].append("profile %s, policy requires %s" % (profile, ep["profile"]))
                return verdict
            verdict["trust"] = accepted[profile]
            if profile in DEV_PROFILES:
                verdict["warning"] = ("development profile %s admitted only because allow_dev_profile is set: "
                                      "its key is the same on every chip" % profile)
        elif ep.get("iak_pub_pem"):
            facts.setdefault("signature", False)    # kind psa: the ES256 signature is the only one
            with open(_path(base_dir, ep["iak_pub_pem"]), "rb") as f:
                claims = psa_token.verify(tok, f.read(), ecdsa_verify)
            facts["signature"] = True
        else:
            # aegis-pq without an ES256 key: the ML-DSA-65 signature over the whole token was verified above
            claims = psa_token.parse(tok)[3]
    except (psa_token.TokenError, ValueError, OSError) as e:
        verdict["reasons"].append(str(e))
        return verdict
    except Exception as e:  # noqa: BLE001 - nothing an endpoint sends may stop the fleet loop
        verdict["reasons"].append("token not usable: %s: %s" % (type(e).__name__, e))
        return verdict
    facts["stage"] = "appraised"
    try:
        # standard evidence that nests the platform's token carries the challenge twice: both must be this cycle's
        if claims.get("challenge") != challenge or (ev is not None and ev["nonce"] != challenge):
            verdict["reasons"].append("challenge mismatch (replayed or stale token)")
        why = check_components(claims, ep.get("allowed", []))
        if endorsed:
            why += endorsed_components(claims, endorsed["measurements"])
        verdict["reasons"] += why
        facts["components_ok"] = not why
        if isinstance(claims.get("challenge"), bytes):
            facts["nonce"] = claims["challenge"]
        if isinstance(claims.get("profile"), str):
            facts["platform"] = claims["profile"]
        s = psa_token.summary(claims)
        facts["components"] = [c for c in s["sw_components"] if isinstance(c.get("measurement_type"), str)
                               and isinstance(c.get("measurement_value"), str)
                               and len(c["measurement_value"]) == 64] or None
        verdict["measurements"] = {c.get("measurement_type"): c.get("measurement_value") for c in s["sw_components"]}
        verdict["instance_id"] = s.get("instance_id")
    except Exception as e:  # noqa: BLE001 - malformed but signed claims: refuse, do not crash
        verdict["reasons"].append("claims not usable: %s: %s" % (type(e).__name__, e))
    verdict["admitted"] = not verdict["reasons"]
    return verdict


def admit_ttl(policy, interval):
    """Seconds an admission lives in the enforcement set unless the next cycle refreshes it (aegis.nft, set timeout).
    One cycle is the sleep plus, per endpoint, at most timeout_s for the quote and 40 s for provisioning and the
    heartbeat, and for an entry with "transcript" the retry after a refused exchange (credential_step): the pause, a
    second quote and a second provisioning. The TTL is two sleeps plus that, so a working loop always refreshes in
    time, while a gateway whose loop has stopped (crash, hang, service stopped) drops every endpoint within minutes.
    "admit_ttl_s" overrides it."""
    try:
        if policy.get("admit_ttl_s"):
            return max(int(policy["admit_ttl_s"]), 1)
    except (TypeError, ValueError):
        pass            # a malformed override must not stop the loop: use the derived value
    per_ep = float(policy.get("timeout_s", 10))
    retry = BUSY_BACKOFF_S[1] + per_ep + 40

    def one(ep):
        if not ep.get("provision"):
            return per_ep
        return per_ep + 40 + (retry if ep.get("transcript") is not None else 0)
    cycle = sum(one(ep) for ep in policy.get("endpoints", []))
    return max(int(2 * float(interval) + cycle + 0.999), 60)


def enforce(policy, verdict, ttl=None):
    """Run the policy's enforcement hook; returns None without one, else {"rc", "stderr", "failed"}. A hook that
    exits non-zero, cannot be started or hangs is a failure: the verdict did not reach the network."""
    cmd = policy.get("enforce_cmd")
    if not cmd:
        return None
    action = "admit" if verdict["admitted"] else "quarantine"
    env = dict(os.environ)
    if ttl:
        env["AEGIS_ADMIT_TTL"] = str(int(ttl))
    try:
        r = subprocess.run(list(cmd) + [verdict["endpoint"], action], capture_output=True, text=True, env=env,
                           timeout=ENFORCE_TIMEOUT_S)
        rc, err = r.returncode, (r.stderr or "").strip()
    except subprocess.TimeoutExpired:
        rc, err = None, "hook did not finish in %d s" % ENFORCE_TIMEOUT_S
    except OSError as e:
        rc, err = None, "hook could not be started: %s" % e
    return {"rc": rc, "stderr": err, "failed": rc != 0}


def record_enforcement(verdict, result):
    """Copy the hook's result into the verdict (state file) and return the journal suffix."""
    if result is None:
        verdict["enforce_rc"] = None
        return ""
    verdict["enforce_rc"] = result["rc"]
    if not result["failed"]:
        verdict["enforcement"] = "ok"
        return ""
    first = result["stderr"].splitlines()[0] if result["stderr"] else "no message"
    verdict["enforcement"] = "FAILED"
    verdict["enforce_error"] = result["stderr"]
    return " [enforcement FAILED rc=%s: %s]" % ("none" if result["rc"] is None else result["rc"], first)


def log(msg, priority=None, file=None):
    """One journal line. Under systemd (JOURNAL_STREAM set) a "<N>" prefix sets the syslog priority, so
    `journalctl -p warning` shows failed enforcement and development-profile admissions."""
    if priority is not None and os.environ.get("JOURNAL_STREAM"):
        msg = "\n".join("<%d>%s" % (priority, m) for m in msg.split("\n"))
    print(msg, file=file or sys.stdout, flush=True)


LOG_ERR, LOG_WARNING = 3, 4


def journal_line(v):
    """The watch loop's line for one verdict; returns (text, priority or None)."""
    line = "%s %s %s %s%s" % (time.strftime("%H:%M:%S"), v["endpoint"],
                              ("ADMITTED" if v["admitted"] else "QUARANTINED") +
                              (" (%s trust)" % v["trust"] if v.get("trust") else "") + v.get("enforce_note", ""),
                              "; ".join(v["reasons"]),
                              (" [credential: %s]" % v["credential"]) if v.get("credential") else "")
    if v["admitted"] and v.get("enrolment") == ENDORSED:
        line += " [endorsed by %s]" % v.get("endorsement", {}).get("endorser_name", "?")
    elif v["admitted"] and v.get("enrolment") == TOFU:
        # every cycle's line says so in three words; the sentence is in the line the loop prints when it starts
        line += " [trust on first use]"
    if v.get("enforcement") == "FAILED":
        return line, LOG_ERR
    if v["admitted"] and v.get("warning"):
        return line + " WARNING: " + v["warning"], LOG_WARNING
    return line, None


GATEWAY_STATE = "/var/lib/aegis"
SYSSERV_DEVICE = "/dev/mpfs_generic_service"   # gateway/sysserv/aegis_sysserv.py DEVICE


def detect_platform():
    """polarfire on the gateway (its system-controller device, or a RISC-V machine), linux anywhere else; the same
    rule as aegisd.pick_platform."""
    return "polarfire" if (os.path.exists(SYSSERV_DEVICE) or os.uname().machine == "riscv64") else "linux"


def default_state_dir(platform):
    """$AEGIS_STATE_DIR; else /var/lib/aegis on the gateway or for root; else the user's state directory
    ($XDG_STATE_HOME/aegis, ~/.local/state/aegis), so an ordinary Linux user can run the loop."""
    if os.environ.get("AEGIS_STATE_DIR"):
        return os.environ["AEGIS_STATE_DIR"]
    if platform == "polarfire" or os.geteuid() == 0:
        return GATEWAY_STATE
    base = os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state")
    return os.path.join(base, "aegis")


def load_gateway_identity(state=GATEWAY_STATE):
    """This verifier's ML-DSA-65 identity, as aegisd.py init made it in STATE: (secret key, identity sha256)."""
    import keystore   # identity.sk, or sealed to this host's TPM (identity.tpm.json)
    import wire
    with open(os.path.join(state, "identity.json")) as f:
        rec = json.load(f)
    pk = rec["body"].get("pk")
    sk, _ = keystore.load(state, bytes.fromhex(pk) if pk else None)
    return sk, wire.digest(rec["body"])


load_verifier_identity = load_gateway_identity


def verifier_pk_sha256(state):
    """SHA-256 of this verifier's ML-DSA-65 public key: the value tools/gen_gateway_pin.py prints for the key it pins
    in endpoint firmware, and what a policy entry names in "verifier_pin_sha256". None without an identity."""
    import hashlib
    try:
        with open(os.path.join(state, "identity.json")) as f:
            return hashlib.sha256(bytes.fromhex(json.load(f)["body"]["pk"])).hexdigest()
    except (OSError, ValueError, KeyError, TypeError):
        return None


def issuer_refusal(ep, state, require_pin):
    """Why this verifier must not provision ep, or None. Every endpoint image accepts credentials only from the one
    verifier key pinned in it (gateway_pk.h); a credential signed by another key is refused, and its PQKEMINIT would
    still cancel a provisioning exchange that verifier has pending. So: with "verifier_pin_sha256" in the entry,
    provision only if it is this verifier's key; without it, provision only where require_pin is off (the gateway,
    whose key the current images pin)."""
    pin = ep.get("verifier_pin_sha256")
    if pin is None:
        if require_pin:
            return ("not issued: no verifier_pin_sha256 in the policy entry, so the endpoint's pinned verifier key is "
                    "unknown (attestation only)")
        return None
    own = verifier_pk_sha256(state)
    if own is None:
        return "not issued: no verifier identity in %s (aegisd.py --platform linux init --state %s)" % (state, state)
    if own != str(pin).lower():
        return ("not issued: the endpoint pins verifier key %s..., this verifier is %s... (attestation only)"
                % (str(pin)[:16], own[:16]))
    return None


def _binding(tr):
    return "transcript-%s" % tr if tr else "unbound"


def _unbound_tail(tr):
    return "" if tr else " [%s]" % UNBOUND_NOTE


# what attest() puts into a verdict from the quote it asked for: the parts a later quote of the same cycle replaces
QUOTE_FIELDS = ("time", "elapsed_s", "evidence_format", "enrolment", "endorsement", "pq_signature", "device_pk_sha256",
                "quote", "trust", "warning", "measurements", "instance_id")


def _adopt_quote(verdict, again):
    """Make verdict speak of the quote of the verdict again (a second quote of the cycle): every QUOTE_FIELDS value
    is again's, or absent if again has none."""
    for k in QUOTE_FIELDS:
        if k in again:
            verdict[k] = again[k]
        elif k != "time":                   # a verdict always has a time
            verdict.pop(k, None)


def credential_step(ep, verdict, base_dir, state=GATEWAY_STATE, require_pin=False, requote=None, endorsers=None):
    """Zero trust: admitted aegis-pq endpoints with "provision": true get (or keep) a fresh
    credential; quarantined ones lose it. Endpoints that would not accept this verifier's credential
    (issuer_refusal) are left alone: no KEM exchange, no heartbeat.
    With "transcript": "v2" in the entry a session is issued only as the continuation of this verdict's quote
    (provision()), and a stored session that was not made that way is not kept alive by heartbeats: it is replaced.
    An endpoint keeps one quote to continue, the last it signed, so a quote asked by another verifier between this
    cycle's quote and its exchange makes the exchange fail. requote, if given, is called once then: it must return a
    new verdict (attest() again). The exchange is tried once more with that quote only if the new verdict is admitted
    and reports the same measurements, so the session is still bound to a quote appraised in this cycle with the
    result this cycle reports; an endpoint that restarted into other code in between gets nothing from the retry. If
    the new verdict is not admitted it is this cycle's: verdict["admitted"] becomes False, its reasons are added, the
    stored session is deleted, and run_once enforces the quarantine. When the bound exchange is refused (any answer
    that does not continue the quote), a stored session that still works is kept until it expires; one already
    unusable (failed heartbeat, another binding than the policy asks for) is deleted.
    Sets verdict["session_binding"] to "transcript-v2" or "unbound" for a session issued or kept."""
    if not ep.get("provision"):
        return None
    if not (isinstance(ep.get("name"), str) and ENTRY_NAME.match(ep["name"])):
        return "refused: the entry's name is not a file name"      # policy_errors() says so in the verdict
    refusal = issuer_refusal(ep, state, require_pin)
    if refusal:
        return refusal
    cdir = os.path.join(state, "credentials")
    os.makedirs(cdir, mode=0o700, exist_ok=True)
    meta = os.path.join(cdir, ep["name"] + ".json")
    keyf = os.path.join(cdir, ep["name"] + ".session")
    if not verdict["admitted"]:
        for f in (meta, keyf):
            if os.path.exists(f):
                os.remove(f)
        return "revoked"
    want = ep.get("transcript")
    hb_error = None
    stored_usable = False   # a stored session of the binding the policy asks for, not expired, its heartbeat not failed
    if os.path.exists(meta):
        with open(meta) as f:
            m = json.load(f)
        made_for = m.get("body", {}).get("endpoint_pq_pk_sha256")
        if made_for != verdict.get("device_pk_sha256"):
            # made for another key than the one this cycle's quote was verified with (a session from before a
            # re-enrolment, or from trust on first use before the entry required an endorsement): the endpoint that
            # holds it is not the one just appraised, so it is not kept alive, and not kept as a fallback either
            hb_error = "stored session was made for device key %s..., this cycle's quote is by %s..." % (
                str(made_for)[:16], str(verdict.get("device_pk_sha256"))[:16])
            for f in (meta, keyf):
                if os.path.exists(f):
                    os.remove(f)
        elif m.get("transcript") != want:
            # the policy now asks for another exchange than the one that made this session (the unbound one, when
            # "transcript" was added to the entry): heartbeats would keep a session alive that the policy refuses
            hb_error = "stored session is %s, the policy asks for %s" % (_binding(m.get("transcript")), _binding(want))
        elif m["body"]["expires"] - time.time() > 300:
            # the endpoint must prove it still holds the session key: fresh nonce, MAC, rising counter
            try:
                with open(keyf, "rb") as f:
                    status, ctr = heartbeat(ep, f.read())
                if ctr > m.get("hb_counter", 0):
                    m["hb_counter"] = ctr
                    m["last_status"] = status.decode(errors="replace")
                    with open(meta, "w") as f:
                        json.dump(m, f, indent=1)
                    verdict["session_binding"] = _binding(want)
                    # every cycle's line says so in a word; the sentence is in the line that issued the session
                    return "valid, heartbeat %d (%s)" % (ctr, m["last_status"]) + ("" if want else " [unbound]")
                hb_error = "counter did not rise"
            except (OSError, ValueError) as e:
                hb_error = str(e)
        else:
            # the renewal window: the session is still the one an earlier admitted quote made, until it expires
            stored_usable = m["body"]["expires"] > time.time()
    sk, gid = load_gateway_identity(state)
    second = False
    # the session goes to the key this cycle's quote was verified with, endorsed if the entry asks for that
    key = {"endorsers": endorsers, "expect_pk_sha256": verdict.get("device_pk_sha256")}
    try:
        try:
            r = provision(ep, base_dir, sk, gid, verdict.get("measurements", {}), quote=verdict.get("quote"), **key)
        except TranscriptRefused as first:
            again = requote() if requote else None
            if again is not None and not again.get("admitted"):
                # the endpoint was admitted at the start of this cycle and is not now: this cycle's verdict is the
                # later one (run_once enforces it again), and a quarantined endpoint keeps no session. What the
                # verdict says of the evidence is the second quote's too, so that the verdict, the signed result and
                # the evidence kept with it are all of one quote (run_once takes the second quote's facts)
                _adopt_quote(verdict, again)
                verdict["admitted"] = False
                verdict["reasons"] = list(verdict.get("reasons", [])) + [
                    "second quote of the cycle not admitted: %s" % "; ".join(again.get("reasons", []))]
                for f in (meta, keyf):
                    if os.path.exists(f):
                        os.remove(f)
                return "revoked: provisioning REFUSED (%s), and the second quote of the cycle was not admitted" % first
            if not (again and again.get("quote") and again.get("measurements") == verdict.get("measurements")):
                if again:
                    raise TranscriptRefused("%s; second quote of the cycle not used (%s)" % (
                        first, "other measurements" if again.get("quote") else
                        "; ".join(again.get("reasons", [])) or "no quote")) from None
                raise
            r = provision(ep, base_dir, sk, gid, verdict.get("measurements", {}), quote=again["quote"], **key)
            _adopt_quote(verdict, again)
            second = True
    except TranscriptRefused as e:
        # The endpoint did not show that the code appraised in this cycle holds the new session. A stored session that
        # still works (the binding the policy asks for, made from an earlier admitted quote, not expired, no failed
        # heartbeat) is kept until it expires: another verifier's quote in between must not cost this one its session.
        # One that is already unusable is deleted.
        if stored_usable:
            return "provisioning REFUSED: %s (stored session kept until it expires)" % e
        for f in (meta, keyf):
            if os.path.exists(f):
                os.remove(f)
        return "provisioning REFUSED: %s" % e + (" (after: %s)" % hb_error if hb_error else "")
    except (OSError, ValueError, RuntimeError) as e:
        return "provisioning failed: %s" % e + (" (after heartbeat failure: %s)" % hb_error if hb_error else "")
    fd = os.open(keyf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(r["session_key"])
    with open(meta, "w") as f:
        json.dump({"body": r["body"], "session_id": r["session_id"],
                   "credential_sha3_256": r["credential_sha3_256"], "transcript": r["transcript"],
                   "transcript_sha3_256": r["transcript_sha3_256"], "quote": r["quote"]}, f, indent=1)
    verdict["session_binding"] = _binding(r["transcript"])
    if not r["transcript"]:
        # once per session in the journal at warning priority (journal_line); the note is in every cycle's line
        verdict["warning"] = "; ".join(x for x in (verdict.get("warning"), "session issued " + UNBOUND_NOTE) if x)
    return ("issued session %s..." % r["session_id"][:12] +
            (" bound to quote %s... (transcript %s%s)" % (verdict["quote"]["token_sha3_256"][:12], r["transcript"],
                                                           ", second quote of the cycle" if second else "")
             if r["transcript"] else "") +
            (" (heartbeat failed: %s)" % hb_error if hb_error else "") + _unbound_tail(r["transcript"]))


# ---- attestation results and the evidence pack (docs/evidence-format.md) ---------------------------------------------

def verifier_keys(state):
    """This verifier's ML-DSA-65 identity as (secret key, public key): what signs attestation results. None without
    an identity in state (aegisd.py init), or if its key cannot be loaded."""
    try:
        with open(os.path.join(state, "identity.json")) as f:
            pk = bytes.fromhex(json.load(f)["body"]["pk"])
        sk, _ = load_gateway_identity(state)
    except Exception:  # noqa: BLE001 - no identity, a sealed key that does not open: no results, the loop goes on
        return None
    return sk, pk


def attestation_result(verdict, facts, keys, policy_bytes, ttl=None, now=None):
    """The signed attestation result for one verdict: an EAR (draft-ietf-rats-ear-06) in a COSE_Sign1, ML-DSA-65, by
    this verifier's identity key (keys: verifier_keys()). facts: what attest() noted. policy_bytes: the policy file
    the verdict was reached under; the result names its SHA-256. With ttl the result expires that many seconds
    after it was issued (the admission's own lifetime, admit_ttl())."""
    import cose
    import eat
    now = int(time.time() if now is None else now)
    payload = eat.ear_payload(verdict, facts, eat.policy_id(policy_bytes), now, now + int(ttl) if ttl else None)
    return cose.sign1(keys[0], keys[1], payload)


def attestation_dir(state, name):
    return os.path.join(state, "attestation", name)


def _put(path, data):
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def keep_attestation(state, verdict, facts, result, policy_bytes):
    """Write this cycle's evidence (as received) and signed result for one endpoint to
    STATE/attestation/<name>/: evidence.cbor (standard evidence) or evidence.token and evidence.sig (the older
    format), result.cbor, and meta.json, which names each by its SHA-256, written last. What an earlier cycle left
    and this one did not produce is removed, so the directory is always one cycle's."""
    d = attestation_dir(state, verdict["endpoint"])
    os.makedirs(d, mode=0o700, exist_ok=True)
    files = {"result.cbor": result}
    if facts.get("evidence"):
        files["evidence.cbor" if facts.get("format") == EAT_COSE else "evidence.token"] = facts["evidence"]
    if facts.get("evidence_sig"):
        files["evidence.sig"] = facts["evidence_sig"]
    for name in ("evidence.cbor", "evidence.token", "evidence.sig"):
        if name not in files and os.path.exists(os.path.join(d, name)):
            os.remove(os.path.join(d, name))
    for name, data in files.items():
        _put(os.path.join(d, name), data)
    meta = {"format": PACK_FORMAT, "endpoint": verdict["endpoint"], "kind": verdict.get("kind"),
            "time": verdict.get("time"), "admitted": bool(verdict.get("admitted")),
            "evidence_format": facts.get("format"), "policy_sha256": hashlib.sha256(policy_bytes).hexdigest(),
            "files": {name: hashlib.sha256(data).hexdigest() for name, data in sorted(files.items())}}
    _put(os.path.join(d, "meta.json"), (json.dumps(meta, indent=1) + "\n").encode())
    return meta


def issue_result(verdict, facts, keys, policy_bytes, state, ttl=None):
    """Sign and keep the attestation result of one verdict; the verdict gets "attestation_result": {"status",
    "sha256", "file" (where the COSE_Sign1 is kept)}. Never raises: a result that cannot be made is reported in the verdict
    ("error"), and the verdict itself stands."""
    try:
        import eat
        if not (isinstance(verdict.get("endpoint"), str) and ENTRY_NAME.match(verdict["endpoint"])):
            raise ValueError("the entry's name is not a file name")
        if facts.get("evidence"):
            facts["evidence_sha256"] = hashlib.sha256(facts["evidence"]).digest()
        result = attestation_result(verdict, facts, keys, policy_bytes, ttl)
        keep_attestation(state, verdict, facts, result, policy_bytes)
        verdict["attestation_result"] = {"status": eat.TIER_NAMES[eat.appraisal(verdict, facts)[0]],
                                         "sha256": hashlib.sha256(result).hexdigest(),
                                         "file": os.path.join(attestation_dir(state, verdict["endpoint"]),
                                                              "result.cbor")}
    except Exception as e:  # noqa: BLE001 - the verdict and its enforcement do not depend on the result
        verdict["attestation_result"] = {"error": "%s: %s" % (type(e).__name__, e)}


def export_evidence(policy, policy_bytes, base_dir, state, name, out, with_policy=False):
    """The evidence pack of one endpoint, written to the new directory out: the last cycle's evidence and signed
    attestation result (keep_attestation), the entry's endorsement record, the public keys as COSE_Key files and
    manifest.json, which names every file by its SHA-256 and the policy by its hash. tools/verify_evidence.py checks
    a pack with third-party libraries only. The keys in a pack are for convenience: whoever relies on it compares
    their thumbprints with the keys they trust. Raises ValueError or OSError; returns the manifest."""
    import cose
    import eat
    eps = [e for e in policy.get("endpoints", []) if isinstance(e, dict) and e.get("name") == name]
    if len(eps) != 1 or not ENTRY_NAME.match(str(name)):
        raise ValueError("the policy has %s entry named %r" % ("no" if not eps else "more than one", str(name)[:40]))
    ep = effective_entry(policy, eps[0])
    d = attestation_dir(state, name)
    try:
        with open(os.path.join(d, "meta.json")) as f:
            meta = json.load(f)
    except FileNotFoundError:
        raise ValueError("no attestation of %s is kept in %s (the loop has not appraised it yet, or this verifier "
                         "has no identity to sign results with)" % (name, d)) from None
    files = {}
    for fname, digest in meta["files"].items():
        with open(os.path.join(d, os.path.basename(fname)), "rb") as f:
            data = f.read()
        if hashlib.sha256(data).hexdigest() != digest:
            raise ValueError("%s changed while it was read (the loop is writing a new cycle): run the command again"
                             % fname)
        files["attestation-result.cbor" if fname == "result.cbor" else fname] = data
    keys = verifier_keys(state)
    if keys is None:
        raise ValueError("no verifier identity in %s" % state)
    result = eat.read_ear(files["attestation-result.cbor"], keys[1])    # it is this verifier's, and intact
    files["keys/verifier.cosekey"] = cbor_key(keys[1])
    kind = ep.get("kind", "psa")
    if kind in PQ_KINDS and ep.get("pq_pub_file"):
        with open(_path(base_dir, ep["pq_pub_file"])) as f:
            files["keys/device.cosekey"] = cbor_key(bytes.fromhex(f.read().strip()))
    if ep.get("iak_pub_pem"):
        with open(_path(base_dir, ep["iak_pub_pem"]), "rb") as f:
            files["keys/device-iak.pem"] = f.read()
    if ep.get("endorsement") is not None:
        import endorsement
        with open(endorsement_file(ep, base_dir), "rb") as f:
            rec_bytes = f.read(endorsement.MAX_RECORD + 1)
        rec = endorsement.loads(rec_bytes)
        files["endorsement.cbor" if rec["format"] == endorsement.FORMAT_COSE else "endorsement.json"] = rec_bytes
        for e in endorsement.trusted(policy.get("endorsers"), base_dir).values():
            if hashlib.sha256(e["pk"]).hexdigest() == rec["body"]["endorser_pk_sha256"]:
                files["keys/endorser.cosekey"] = cbor_key(e["pk"])
    if with_policy:
        files["policy.json"] = policy_bytes
    manifest = {"format": PACK_FORMAT, "endpoint": name, "kind": kind, "exported": int(time.time()),
                "evidence_format": meta.get("evidence_format"),
                "policy_sha256": meta["policy_sha256"],
                "policy_id": eat.policy_id(policy_bytes) if hashlib.sha256(policy_bytes).hexdigest() ==
                meta["policy_sha256"] else None,
                "policy_now_sha256": hashlib.sha256(policy_bytes).hexdigest(),
                "result": {"status": result["status"], "admitted": result["admitted"], "iat": result["iat"],
                           "exp": result["exp"]},
                "key_thumbprints": {k[5:-8]: cose.key_thumbprint(cose.key_from_cose(_cbor_loads(v))).hex()
                                    for k, v in files.items() if k.endswith(".cosekey")},
                "files": {k: hashlib.sha256(v).hexdigest() for k, v in sorted(files.items())},
                "verify": "tools/verify_evidence.py pack <this directory>"}
    os.makedirs(os.path.join(out, "keys"))          # a new directory: an existing pack is never mixed with this one
    for fname, data in files.items():
        with open(os.path.join(out, fname), "wb") as f:
            f.write(data)
    with open(os.path.join(out, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")
    return manifest


def _cbor_loads(data):
    import cbor
    return cbor.loads(data)


def cbor_key(pk):
    """An ML-DSA-65 public key as a COSE_Key file (AKP, RFC 9964): what a third-party tool loads."""
    import cbor
    import cose
    return cbor.dumps(cose.cose_key(pk), sort=True)


def run_once(policy, base_dir, ecdsa_verify, credentials=True, interval=30, state=GATEWAY_STATE, require_pin=False,
             enforce_hooks=True, policy_bytes=None):
    """One cycle over every endpoint. enforce_hooks=False is observe-only: the policy's enforce_cmd is not run.
    With policy_bytes (the policy file as read) and a verifier identity in state, every verdict gets a signed
    attestation result, kept with its evidence under STATE/attestation/ (issue_result)."""
    out = []
    ttl = admit_ttl(policy, interval)
    signer = verifier_keys(state) if policy_bytes is not None else None
    for ep in policy["endpoints"]:
        ep = effective_entry(policy, ep)
        facts, second = {}, {}
        try:
            v = attest(ep, ecdsa_verify, base_dir, float(policy.get("timeout_s", 10)), policy.get("endorsers"), facts)
        except Exception as e:  # noqa: BLE001 - one endpoint must never stop the loop for the others
            v = {"endpoint": ep.get("name", "?"), "kind": ep.get("kind", "psa"), "time": int(time.time()),
                 "admitted": False, "reasons": ["attestation error: %s: %s" % (type(e).__name__, e)]}
            facts = {"stage": "error"}
        result = enforce(policy, v, ttl) if enforce_hooks else None
        note = record_enforcement(v, result)
        if note:
            v["enforce_note"] = note
            log("aegis-fleet: enforcement hook failed for %s (%s), rc=%s:\n%s" % (
                v["endpoint"], "admit" if v["admitted"] else "quarantine", result["rc"], result["stderr"] or "(no output)"),
                LOG_ERR, file=sys.stderr)
        if credentials and ep.get("provision"):
            def requote(ep=ep):
                import random
                time.sleep(random.uniform(*BUSY_BACKOFF_S))   # as for a busy endpoint: do not collide again
                second.clear()
                second["facts"] = {}
                try:
                    second["verdict"] = attest(ep, ecdsa_verify, base_dir, float(policy.get("timeout_s", 10)),
                                               policy.get("endorsers"), second["facts"])
                except Exception as e:  # noqa: BLE001 - as for the first quote of the cycle
                    second["verdict"] = {"admitted": False,
                                         "reasons": ["attestation error: %s: %s" % (type(e).__name__, e)]}
                    second["facts"] = {"stage": "error"}
                return second["verdict"]
            admitted = v["admitted"]
            try:
                cs = credential_step(ep, v, base_dir, state=state, require_pin=require_pin, requote=requote,
                                     endorsers=policy.get("endorsers"))
            except Exception as e:  # noqa: BLE001
                cs = "credential step failed: %s: %s" % (type(e).__name__, e)
            if cs:
                v["credential"] = cs
            if admitted and not v["admitted"]:
                # the second quote of the cycle was not admitted (credential_step): that is this cycle's verdict, so
                # the network must hear it too, not the admission enforced above
                for k in ("enforce_note", "enforcement", "enforce_error"):
                    v.pop(k, None)
                result = enforce(policy, v, ttl) if enforce_hooks else None
                note = record_enforcement(v, result)
                if note:
                    v["enforce_note"] = note
                    log("aegis-fleet: enforcement hook failed for %s (quarantine), rc=%s:\n%s" % (
                        v["endpoint"], result["rc"], result["stderr"] or "(no output)"), LOG_ERR, file=sys.stderr)
            again = second.get("verdict")
            if again is not None and ((admitted and not v["admitted"]) or
                                      (again.get("quote") is not None and v.get("quote") == again.get("quote"))):
                facts = second["facts"]     # the cycle's verdict rests on the second quote: that is its evidence
        if signer is not None:
            issue_result(v, facts, signer, policy_bytes, state, ttl)
        out.append(v)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Aegis fleet verifier")
    ap.add_argument("cmd", choices=["once", "watch", "enroll-pq", "enroll-endorsed", "session", "check",
                                    "export-evidence"])
    ap.add_argument("--force", action="store_true",
                    help="enroll-pq, enroll-endorsed: replace keys that are already pinned")
    ap.add_argument("policy")
    ap.add_argument("records", nargs="*", help="enroll-endorsed: endorsement records (provision/aegis_provision.py); "
                                               "export-evidence: the endpoint's name")
    ap.add_argument("--out", help="export-evidence: the directory to create (default: evidence-pack-NAME-TIME)")
    ap.add_argument("--with-policy", action="store_true",
                    help="export-evidence: put the policy file itself into the pack, not only its hash")
    ap.add_argument("--interval", type=float, default=30)
    ap.add_argument("--platform", choices=["auto", "polarfire", "linux"], default="auto",
                    help="polarfire: the gateway; linux: an ordinary Linux host (observe-only, credentials only where "
                         "verifier_pin_sha256 names this verifier). auto: polarfire on the board, linux elsewhere")
    ap.add_argument("--state-dir", help="identity and credentials (default: $AEGIS_STATE_DIR, /var/lib/aegis on the "
                                        "gateway or as root, else ~/.local/state/aegis)")
    ap.add_argument("--state", help="the verdict file watch writes (default: STATE_DIR/fleet-state.json)")
    ap.add_argument("--verifier", choices=["openssl", "cryptography"], default="openssl")
    ap.add_argument("--no-credentials", action="store_true",
                    help="attest only; do not issue, check or revoke credentials (use while the service runs)")
    ap.add_argument("--enforce", action="store_true",
                    help="--platform linux: run the policy's enforce_cmd (default there: observe-only)")
    a = ap.parse_args(argv)
    with open(a.policy, "rb") as f:
        policy_bytes = f.read()
    policy = json.loads(policy_bytes.decode())
    base = os.path.dirname(os.path.abspath(a.policy))
    platform = detect_platform() if a.platform == "auto" else a.platform
    state_dir = a.state_dir or default_state_dir(platform)
    state_file = a.state or os.path.join(state_dir, "fleet-state.json")
    on_host = platform == "linux"
    enforce_hooks = not on_host or a.enforce
    ev = psa_token.verify_with_openssl_cli if a.verifier == "openssl" else psa_token.verify_with_cryptography
    if a.records and a.cmd not in ("enroll-endorsed", "export-evidence"):
        ap.error("only enroll-endorsed takes record files")
    if a.cmd == "export-evidence":
        # the evidence pack of one endpoint, for someone who checks it without Aegis code (docs/evidence-format.md)
        if len(a.records) != 1:
            ap.error("export-evidence needs one endpoint name")
        out = a.out or "evidence-pack-%s-%s" % (a.records[0], time.strftime("%Y%m%d-%H%M%S"))
        try:
            m = export_evidence(policy, policy_bytes, base, state_dir, a.records[0], out, a.with_policy)
        except (OSError, ValueError) as e:
            print("export-evidence: %s" % e, file=sys.stderr)
            return 1
        print("evidence pack of %s in %s: %s, result %s (%s), policy sha256 %s\n  %s" % (
            m["endpoint"], out, m["evidence_format"], m["result"]["status"],
            "admitted" if m["result"]["admitted"] else "not admitted", m["policy_sha256"],
            "\n  ".join("%s  %s" % (h, n) for n, h in m["files"].items())))
        return 0
    if a.cmd == "enroll-endorsed":
        # Endorsed enrolment (docs/enrolment.md): each record is checked against this policy's trusted endorsers and
        # the entry it names, then its record and key are committed so that a failure leaves nothing trusted.
        if not a.records:
            ap.error("enroll-endorsed needs at least one endorsement record")
        bad = 0
        for path in a.records:
            try:
                name, body = install_endorsement(policy, base, path, a.force, a.policy)
            except (OSError, ValueError) as e:
                bad += 1
                print("REFUSED %s: %s (nothing was enrolled from it)" % (path, e))
                continue
            ep = next(e for e in policy["endpoints"] if e.get("name") == name)
            print("enrolled %s: ML-DSA-65 key sha256 %s, endorsed by %s -> %s, %s; %s pins record %s%s" % (
                name, body["device_pk_sha256"], body["endorser_name"], _path(base, ep["pq_pub_file"]),
                endorsement_file(ep, base), a.policy, body["record_sha256"],
                "" if ep.get("endorsement") in ENDORSEMENTS else
                ' (the entry does not say "endorsement": "required" yet: the record is not checked by the loop)'))
        return 1 if bad else 0
    if a.cmd == "enroll-pq":
        # Trust on first use: fetch the ML-DSA-65 key of each PQ endpoint that has none pinned yet. An existing pin is
        # never replaced from the network (the reply comes through the endpoint's untrusted side); --force re-enrols.
        for ep in policy["endpoints"]:
            if ep.get("kind") not in PQ_KINDS:
                continue
            if ep.get("endorsement") is not None:
                print("skipped %s: its entry requires an endorsement, so its key is not taken from the network "
                      "(provision/aegis_provision.py endorse, then fleet.py enroll-endorsed)" % ep["name"])
                continue
            path = _path(base, ep["pq_pub_file"])
            if os.path.exists(path) and not a.force:
                print("kept %s: a key is already pinned in %s (use --force to replace it)" % (ep["name"], path))
                continue
            pk = request_pq_key(ep["host"], int(ep["port"]))
            with open(path, "w") as f:
                f.write(pk.hex() + "\n")
            print("enrolled %s by trust on first use: ML-DSA-65 key sha256 %s -> %s"
                  % (ep["name"], hashlib.sha256(pk).hexdigest(), path))
        return 0
    if a.cmd == "session":
        # compare this verifier's stored credential/session with what the endpoint's secure side reports
        for ep in policy["endpoints"]:
            if not ep.get("provision"):
                continue
            meta = os.path.join(state_dir, "credentials", ep["name"] + ".json")
            mine = json.load(open(meta)) if os.path.exists(meta) else None
            try:
                sid, ch = query_session(ep)
            except (OSError, ValueError) as e:
                sid, ch = None, str(e)
            print(json.dumps({"endpoint": ep["name"], "gateway_session_id": mine and mine["session_id"],
                              "endpoint_session_id": sid, "same_session": bool(mine) and sid == mine["session_id"],
                              "same_credential": bool(mine) and ch == mine["credential_sha3_256"]}, indent=1))
        return 0
    if a.cmd == "check":
        # what the strict profile rules refuse in this policy, without contacting any endpoint
        bad = 0
        for ep in policy["endpoints"]:
            ep = effective_entry(policy, ep)
            errs, warns = policy_errors(ep), policy_warnings(ep)
            bad += bool(errs)
            print("%s %s%s" % (ep.get("name"), "REFUSED: " + "; ".join(errs) if errs else "ok",
                               "".join(" " + w for w in warns)))
            if not errs and ep.get("kind") in PQ_KINDS:
                note, refused = enrolment_note(ep, base, policy.get("endorsers"))
                bad += refused
                print("  %s" % note)
            if not errs and ep.get("provision") and not a.no_credentials:
                refusal = issuer_refusal(ep, state_dir, on_host)
                print("  credentials: %s" % (refusal or "issued by this verifier"))
                if not refusal:
                    print("  %s" % binding_note(ep))
        print("admission TTL: %d s (interval %g s)" % (admit_ttl(policy, a.interval), a.interval))
        print("platform %s, state %s, %s, this verifier's key sha256 %s" % (
            platform, state_dir, "enforcing" if enforce_hooks and policy.get("enforce_cmd") else "observe-only",
            verifier_pk_sha256(state_dir) or "(no identity)"))
        return 1 if bad else 0
    run = dict(credentials=not a.no_credentials, interval=a.interval, state=state_dir, require_pin=on_host,
               enforce_hooks=enforce_hooks)
    if verifier_keys(state_dir) is None:
        log("aegis-fleet: no verifier identity in %s: verdicts are not signed (no attestation results)" % state_dir,
            file=sys.stderr)
    if policy.get("enforce_cmd") and not enforce_hooks:
        log("aegis-fleet: observe-only on platform %s: enforce_cmd in the policy is not run (--enforce runs it)"
            % platform, file=sys.stderr)
    if a.cmd == "once":
        res = run_once(policy, base, ev, policy_bytes=policy_bytes, **run)
        for v in res:
            v.pop("enforce_note", None)
        print(json.dumps(res, indent=1))
        return 0
    os.makedirs(os.path.dirname(os.path.abspath(state_file)), mode=0o700, exist_ok=True)
    log("aegis-fleet: platform %s, %s, credentials %s, state %s" % (
        platform, "enforcing" if enforce_hooks and policy.get("enforce_cmd") else "observe-only",
        "off" if a.no_credentials else ("only where verifier_pin_sha256 names this verifier" if on_host else "on"),
        state_file))
    if not a.no_credentials:
        for ep in policy.get("endpoints", []):
            if ep.get("provision") and ep.get("transcript") not in TRANSCRIPTS and not policy_errors(ep) \
                    and not issuer_refusal(ep, state_dir, on_host):
                log("aegis-fleet: %s: %s" % (ep.get("name"), binding_note(ep)), LOG_WARNING)
    for ep in policy.get("endpoints", []):
        if ep.get("kind") in PQ_KINDS and ep.get("endorsement") is None and not policy_errors(ep):
            log("aegis-fleet: %s: enrolment: %s" % (ep.get("name"), TOFU_NOTE), LOG_WARNING)
    while True:
        try:  # reload every cycle, so policy updates apply without a restart
            with open(a.policy, "rb") as f:
                new_bytes = f.read()
            policy, policy_bytes = json.loads(new_bytes.decode()), new_bytes
        except (OSError, ValueError) as e:
            print("policy reload failed, keeping the previous one: %s" % e, flush=True)
        res = run_once(policy, base, ev, policy_bytes=policy_bytes, **run)
        lines = [journal_line(v) for v in res]
        for v in res:
            v.pop("enforce_note", None)
        tmp = state_file + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"updated": int(time.time()), "verdicts": res}, f, indent=1)
        os.replace(tmp, state_file)
        for text, prio in lines:
            log(text, prio)
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
