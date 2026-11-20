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
"""
import argparse
import json
import os
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


def request_token(host, port, challenge, timeout):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"CHAL " + challenge.hex().encode() + b"\n")
        buf = b""
        while b"\n" not in buf and len(buf) < 4096:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf += chunk
    line = buf.split(b"\n")[0].strip().decode(errors="replace")
    parts = line.split()
    if len(parts) != 4 or parts[0] != "TOKEN" or parts[3] != "END":
        raise ValueError("no token in reply: %r" % line[:40])
    tok = bytes.fromhex(parts[2])
    if len(tok) != int(parts[1]):
        raise ValueError("token length mismatch")
    return tok


def _read_line(s, limit=16384):
    buf = b""
    while b"\n" not in buf and len(buf) < limit:
        chunk = s.recv(8192)
        if not chunk:
            break
        buf += chunk
    return buf.split(b"\n")[0].strip().decode(errors="replace")


def request_pq(host, port, challenge, timeout):
    """Aegis PQ quote: returns (token, ML-DSA-65 signature)."""
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"PQCHAL " + challenge.hex().encode() + b"\n")
        line = _read_line(s)
    p = line.split()
    if len(p) != 6 or p[0] != "PQTOKEN" or p[5] != "END":
        raise ValueError("no PQ quote in reply: %r" % line[:40])
    tok, sig = bytes.fromhex(p[2]), bytes.fromhex(p[4])
    if len(tok) != int(p[1]) or len(sig) != int(p[3]):
        raise ValueError("PQ quote length mismatch")
    return tok, sig


def request_pq_key(host, port, timeout=10):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(b"PQKEY\n")
        line = _read_line(s)
    p = line.split()
    if len(p) != 4 or p[0] != "PQKEY" or p[3] != "END":
        raise ValueError("no PQ key in reply: %r" % line[:40])
    pk = bytes.fromhex(p[2])
    if len(pk) != int(p[1]):
        raise ValueError("PQ key length mismatch")
    return pk


def _exchange(host, port, line, timeout):
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.settimeout(timeout)
        s.sendall(line.encode() + b"\n")
        return _read_line(s, limit=65536)


def _sha3(*parts):
    import hashlib
    h = hashlib.sha3_256()
    for p in parts:
        h.update(p)
    return h.digest()


def provision(ep, base_dir, gw_sk, gw_identity_sha256, measurements, timeout=30.0):
    """ML-KEM-768 provisioning of an admitted aegis-pq endpoint.

    1. gateway nonce -> endpoint returns a fresh ML-KEM-768 encapsulation key, signed with its
       enrolled ML-DSA-65 key (so the key cannot be swapped on the way);
    2. gateway encapsulates (ct, K) and sends ct with a credential signed by the gateway's own
       ML-DSA-65 identity key;
    3. endpoint decapsulates and answers a key-confirmation tag; the gateway accepts only if the
       tag equals SHA3-256("aegis-confirm-v1" || K || nonce || SHA3(ct) || SHA3(credential)).
    Both sides then hold session = SHA3-256("aegis-session-v1" || K || nonce || SHA3(ct)).
    Returns a dict; raises ValueError on any failure."""
    import mldsa
    import mlkem
    import wire
    host, port = ep["host"], int(ep["port"])
    with open(_path(base_dir, ep["pq_pub_file"])) as f:
        pk = bytes.fromhex(f.read().strip())
    nonce = secrets.token_bytes(32)
    p = _exchange(host, port, "PQKEMINIT " + nonce.hex(), timeout).split()
    if len(p) != 6 or p[0] != "PQKEMEK" or p[5] != "END":
        raise ValueError("no KEM key in reply: %r" % " ".join(p)[:40])
    ek, sig = bytes.fromhex(p[2]), bytes.fromhex(p[4])
    if len(ek) != mlkem.EK_LEN or not mldsa.verify(pk, KEM_INIT_LABEL, nonce + ek, sig):
        raise ValueError("ML-KEM key not signed by the enrolled endpoint key")
    ct, k = mlkem.encaps(ek)
    now = int(time.time())
    body = {"v": 1, "type": "credential", "endpoint": ep["name"],
            "endpoint_pq_pk_sha256": __import__("hashlib").sha256(pk).hexdigest(),
            "measurements": measurements, "kem": "ML-KEM-768", "kem_ct_sha3_256": _sha3(ct).hex(), "kem_ek_sha3_256": _sha3(ek).hex(),
            "issued": now, "expires": now + CRED_LIFETIME_S, "gateway_identity_sha256": gw_identity_sha256}
    cred = wire.canonical(body) + b"\n" + mldsa.sign(gw_sk, CRED_LABEL, wire.canonical(body))
    p = _exchange(host, port, "PQKEMFIN %s %s" % (ct.hex(), cred.hex()), timeout).split()
    if len(p) != 3 or p[0] != "PQKEMOK" or p[2] != "END":
        raise ValueError("provisioning refused by endpoint: %r" % " ".join(p)[:40])
    expect = _sha3(b"aegis-confirm-v1", k, nonce, _sha3(ct), _sha3(cred))
    import hmac
    if not hmac.compare_digest(bytes.fromhex(p[1]), expect):
        raise ValueError("key confirmation failed")
    session = _sha3(b"aegis-session-v1", k, nonce, _sha3(ct))
    session_id = _sha3(b"aegis-session-id-v1", session)
    return {"credential": cred, "body": body, "session_key": session, "session_id": session_id.hex(),
            "credential_sha3_256": _sha3(cred).hex()}


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
    p = _exchange(ep["host"], int(ep["port"]), "PQHB " + nonce.hex(), timeout).split()
    if len(p) != 5 or p[0] != "PQHB" or p[4] != "END":
        raise ValueError("no heartbeat: %r" % " ".join(p)[:40])
    status, ctr, tag = bytes.fromhex(p[1]), bytes.fromhex(p[2]), bytes.fromhex(p[3])
    expect = heartbeat_tag(ep.get("heartbeat_mac"), session_key, nonce, ctr, status)
    if len(ctr) != 8 or not hmac.compare_digest(tag, expect):
        raise ValueError("heartbeat tag invalid")
    return status, int.from_bytes(ctr, "little")


def query_session(ep, timeout=10.0):
    p = _exchange(ep["host"], int(ep["port"]), "PQSESSION", timeout).split()
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


def _path(base_dir, p):
    return p if os.path.isabs(p) else os.path.join(base_dir, p)


def policy_errors(ep):
    """Reasons an endpoint entry is refused before the endpoint is even asked (strict profiles). Empty if the entry
    is acceptable."""
    kind = ep.get("kind", "psa")
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
    mac = ep.get("heartbeat_mac")
    if mac is not None and mac not in HEARTBEAT_MACS:
        errors.append("policy: unknown heartbeat_mac %r" % mac)
    return errors


def policy_warnings(ep):
    if ep.get("allow_dev_profile") is True and ep.get("profile") in DEV_PROFILES:
        return ["WARNING: %s may be admitted on development profile %s: its key is the same on every chip"
                % (ep.get("name"), ep["profile"])]
    return []


def attest(ep, ecdsa_verify, base_dir, timeout=10.0):
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
    Never raises for anything the endpoint sends."""
    kind = ep.get("kind", "psa")
    verdict = {"endpoint": ep["name"], "kind": kind, "time": int(time.time()), "admitted": False, "reasons": []}
    errors = policy_errors(ep)
    if errors:
        verdict["reasons"] += errors
        return verdict
    challenge = secrets.token_bytes(32)
    t0 = time.monotonic()
    sig = None
    try:
        if kind in PQ_KINDS:
            tok, sig = request_pq(ep["host"], int(ep["port"]), challenge, timeout)
        else:
            tok = request_token(ep["host"], int(ep["port"]), challenge, timeout)
    except (OSError, ValueError) as e:
        verdict["reasons"].append("no attestation: %s" % e)
        verdict["elapsed_s"] = round(time.monotonic() - t0, 3)
        return verdict
    verdict["elapsed_s"] = round(time.monotonic() - t0, 3)
    try:
        if kind in PQ_KINDS:
            import mldsa
            with open(_path(base_dir, ep["pq_pub_file"])) as f:
                pk = bytes.fromhex(f.read().strip())
            if not mldsa.verify(pk, PQ_LABEL, tok, sig):
                verdict["reasons"].append("ML-DSA-65 quote signature invalid")
                return verdict
            verdict["pq_signature"] = "ML-DSA-65 valid"
        if kind in PLAIN_KINDS:
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
            with open(_path(base_dir, ep["iak_pub_pem"]), "rb") as f:
                claims = psa_token.verify(tok, f.read(), ecdsa_verify)
        else:
            # aegis-pq without an ES256 key: the ML-DSA-65 signature over the whole token was verified above
            claims = psa_token.parse(tok)[3]
    except (psa_token.TokenError, ValueError, OSError) as e:
        verdict["reasons"].append(str(e))
        return verdict
    except Exception as e:  # noqa: BLE001 - nothing an endpoint sends may stop the fleet loop
        verdict["reasons"].append("token not usable: %s: %s" % (type(e).__name__, e))
        return verdict
    try:
        if claims.get("challenge") != challenge:
            verdict["reasons"].append("challenge mismatch (replayed or stale token)")
        verdict["reasons"] += check_components(claims, ep.get("allowed", []))
        s = psa_token.summary(claims)
        verdict["measurements"] = {c.get("measurement_type"): c.get("measurement_value") for c in s["sw_components"]}
        verdict["instance_id"] = s.get("instance_id")
    except Exception as e:  # noqa: BLE001 - malformed but signed claims: refuse, do not crash
        verdict["reasons"].append("claims not usable: %s: %s" % (type(e).__name__, e))
    verdict["admitted"] = not verdict["reasons"]
    return verdict


def admit_ttl(policy, interval):
    """Seconds an admission lives in the enforcement set unless the next cycle refreshes it (aegis.nft, set timeout).
    One cycle is the sleep plus, per endpoint, at most timeout_s for the quote and 40 s for provisioning and the
    heartbeat; the TTL is two sleeps plus that, so a working loop always refreshes in time, while a gateway whose loop
    has stopped (crash, hang, service stopped) drops every endpoint within minutes. "admit_ttl_s" overrides it."""
    try:
        if policy.get("admit_ttl_s"):
            return max(int(policy["admit_ttl_s"]), 1)
    except (TypeError, ValueError):
        pass            # a malformed override must not stop the loop: use the derived value
    per_ep = float(policy.get("timeout_s", 10))
    cycle = sum(per_ep + (40 if ep.get("provision") else 0) for ep in policy.get("endpoints", []))
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
    if v.get("enforcement") == "FAILED":
        return line, LOG_ERR
    if v["admitted"] and v.get("warning"):
        return line + " WARNING: " + v["warning"], LOG_WARNING
    return line, None


GATEWAY_STATE = "/var/lib/aegis"


def load_gateway_identity(state=GATEWAY_STATE):
    import wire
    with open(os.path.join(state, "identity.json")) as f:
        rec = json.load(f)
    with open(os.path.join(state, "identity.sk"), "rb") as f:
        sk = f.read()
    return sk, wire.digest(rec["body"])


def credential_step(ep, verdict, base_dir, state=GATEWAY_STATE):
    """Zero trust: admitted aegis-pq endpoints with "provision": true get (or keep) a fresh
    credential; quarantined ones lose it."""
    if not ep.get("provision"):
        return None
    cdir = os.path.join(state, "credentials")
    os.makedirs(cdir, mode=0o700, exist_ok=True)
    meta = os.path.join(cdir, ep["name"] + ".json")
    keyf = os.path.join(cdir, ep["name"] + ".session")
    if not verdict["admitted"]:
        for f in (meta, keyf):
            if os.path.exists(f):
                os.remove(f)
        return "revoked"
    if os.path.exists(meta):
        with open(meta) as f:
            m = json.load(f)
        if m["body"]["expires"] - time.time() > 300:
            # the endpoint must prove it still holds the session key: fresh nonce, MAC, rising counter
            try:
                with open(keyf, "rb") as f:
                    status, ctr = heartbeat(ep, f.read())
                if ctr > m.get("hb_counter", 0):
                    m["hb_counter"] = ctr
                    m["last_status"] = status.decode(errors="replace")
                    with open(meta, "w") as f:
                        json.dump(m, f, indent=1)
                    return "valid, heartbeat %d (%s)" % (ctr, m["last_status"])
                hb_error = "counter did not rise"
            except (OSError, ValueError) as e:
                hb_error = str(e)
        else:
            hb_error = None
    else:
        hb_error = None
    sk, gid = load_gateway_identity(state)
    try:
        r = provision(ep, base_dir, sk, gid, verdict.get("measurements", {}))
    except (OSError, ValueError, RuntimeError) as e:
        return "provisioning failed: %s" % e + (" (after heartbeat failure: %s)" % hb_error if hb_error else "")
    fd = os.open(keyf, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(r["session_key"])
    with open(meta, "w") as f:
        json.dump({"body": r["body"], "session_id": r["session_id"],
                   "credential_sha3_256": r["credential_sha3_256"]}, f, indent=1)
    return "issued session %s..." % r["session_id"][:12] + (" (heartbeat failed: %s)" % hb_error if hb_error else "")


def run_once(policy, base_dir, ecdsa_verify, credentials=True, interval=30, state=GATEWAY_STATE):
    out = []
    ttl = admit_ttl(policy, interval)
    for ep in policy["endpoints"]:
        try:
            v = attest(ep, ecdsa_verify, base_dir, float(policy.get("timeout_s", 10)))
        except Exception as e:  # noqa: BLE001 - one endpoint must never stop the loop for the others
            v = {"endpoint": ep.get("name", "?"), "kind": ep.get("kind", "psa"), "time": int(time.time()),
                 "admitted": False, "reasons": ["attestation error: %s: %s" % (type(e).__name__, e)]}
        result = enforce(policy, v, ttl)
        note = record_enforcement(v, result)
        if note:
            v["enforce_note"] = note
            log("aegis-fleet: enforcement hook failed for %s (%s), rc=%s:\n%s" % (
                v["endpoint"], "admit" if v["admitted"] else "quarantine", result["rc"], result["stderr"] or "(no output)"),
                LOG_ERR, file=sys.stderr)
        if credentials and ep.get("provision"):
            try:
                cs = credential_step(ep, v, base_dir, state=state)
            except Exception as e:  # noqa: BLE001
                cs = "credential step failed: %s: %s" % (type(e).__name__, e)
            if cs:
                v["credential"] = cs
        out.append(v)
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description="Aegis fleet verifier")
    ap.add_argument("cmd", choices=["once", "watch", "enroll-pq", "session", "check"])
    ap.add_argument("--force", action="store_true", help="enroll-pq: replace keys that are already pinned")
    ap.add_argument("policy")
    ap.add_argument("--interval", type=float, default=30)
    ap.add_argument("--state", default="/var/lib/aegis/fleet-state.json")
    ap.add_argument("--verifier", choices=["openssl", "cryptography"], default="openssl")
    ap.add_argument("--no-credentials", action="store_true",
                    help="attest only; do not issue, check or revoke credentials (use while the service runs)")
    a = ap.parse_args(argv)
    with open(a.policy) as f:
        policy = json.load(f)
    base = os.path.dirname(os.path.abspath(a.policy))
    ev = psa_token.verify_with_openssl_cli if a.verifier == "openssl" else psa_token.verify_with_cryptography
    if a.cmd == "enroll-pq":
        # Trust on first use: fetch the ML-DSA-65 key of each PQ endpoint that has none pinned yet. An existing pin is
        # never replaced from the network (the reply comes through the endpoint's untrusted side); --force re-enrols.
        for ep in policy["endpoints"]:
            if ep.get("kind") not in PQ_KINDS:
                continue
            path = _path(base, ep["pq_pub_file"])
            if os.path.exists(path) and not a.force:
                print("kept %s: a key is already pinned in %s (use --force to replace it)" % (ep["name"], path))
                continue
            pk = request_pq_key(ep["host"], int(ep["port"]))
            with open(path, "w") as f:
                f.write(pk.hex() + "\n")
            print("enrolled %s: ML-DSA-65 key sha256 %s -> %s" % (ep["name"], __import__("hashlib").sha256(pk).hexdigest(), path))
        return 0
    if a.cmd == "session":
        # compare the gateway's stored credential/session with what the endpoint's secure side reports
        for ep in policy["endpoints"]:
            if not ep.get("provision"):
                continue
            meta = os.path.join(GATEWAY_STATE, "credentials", ep["name"] + ".json")
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
            errs, warns = policy_errors(ep), policy_warnings(ep)
            bad += bool(errs)
            print("%s %s%s" % (ep.get("name"), "REFUSED: " + "; ".join(errs) if errs else "ok",
                               "".join(" " + w for w in warns)))
        print("admission TTL: %d s (interval %g s)" % (admit_ttl(policy, a.interval), a.interval))
        return 1 if bad else 0
    if a.cmd == "once":
        res = run_once(policy, base, ev, credentials=not a.no_credentials, interval=a.interval)
        for v in res:
            v.pop("enforce_note", None)
        print(json.dumps(res, indent=1))
        return 0
    while True:
        try:  # reload every cycle, so policy updates apply without a restart
            with open(a.policy) as f:
                policy = json.load(f)
        except (OSError, ValueError) as e:
            print("policy reload failed, keeping the previous one: %s" % e, flush=True)
        res = run_once(policy, base, ev, interval=a.interval)
        lines = [journal_line(v) for v in res]
        for v in res:
            v.pop("enforce_note", None)
        tmp = a.state + ".tmp"
        with open(tmp, "w") as f:
            json.dump({"updated": int(time.time()), "verdicts": res}, f, indent=1)
        os.replace(tmp, a.state)
        for text, prio in lines:
            log(text, prio)
        time.sleep(a.interval)


if __name__ == "__main__":
    sys.exit(main())
