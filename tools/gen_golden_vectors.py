#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Synthetic golden vectors of Aegis' data formats (tests/vectors/aegis-1.2/, docs/data-formats.md).

  tools/gen_golden_vectors.py [OUT]       write the vectors into OUT (default tests/vectors/aegis-1.2), which must
                                          not exist yet or be a directory this tool wrote before (it is replaced)

Everything is made in this process by the repository's own writers, with no network, no board and no bench data:
simulated devices answer the fleet verifier (gateway/aegisd/fleet.py) in place of its TCP requests, and the files are
what the verifier writes: the verdicts of one cycle (fleet-state.json), the evidence pack of every entry
(export_evidence, as `fleet.py export-evidence`), the endorsement records (common/endorsement.py, installed with
`enroll-endorsed`'s function), the signed policy and its signers file (common/signed_policy.py), and the audit log
of a few cycles with an anchor (fleet.py AuditTrail, common/audit.py).

Fixed, so that two runs agree: every key (ML-DSA-65 from a 32-byte seed, P-256 from a scalar, both derived from the
names below: anyone can make the secret keys again, which is the point of a test vector and why none is a real one),
every challenge and random identifier (a SHAKE-256 stream in place of secrets.token_bytes), the clock (time.time and
time.monotonic), and the PSA tokens (ECDSA with RFC 6979 nonces). Not fixed: every ML-DSA-65 signature. ML-DSA signing
is hedged (FIPS 204, fresh randomness in each signature) and neither OpenSSL's interface in the cryptography package
nor the repository's mldsa.py offers the deterministic variant. So every COSE object, detached signature and
endorsement record differs from one run to the next, and with them every hash over one of them (the files' SHA-256 in
a manifest, the record's name a policy pins, the policy's own hash, the audit log's chain). The test
(tests/host/test_golden_vectors.py) therefore compares a fresh run with the committed files by structure and checks
that both verify, rather than comparing bytes; the claims inside the device evidence are the same in every run.

Needs the cryptography package with ML-DSA (version 47 or later, OpenSSL 3.5 or later), as the verifier on a PC does.
"""
import argparse
import hashlib
import json
import os
import secrets
import shutil
import sys
import tempfile
import time
from unittest import mock

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
for _p in ("common", "gateway/aegisd"):
    sys.path.insert(0, os.path.join(ROOT, _p))

import cbor  # noqa: E402
import cose  # noqa: E402
import eat  # noqa: E402
import endorsement  # noqa: E402
import fleet  # noqa: E402
import psa_token  # noqa: E402
import signed_policy  # noqa: E402

DEFAULT_OUT = os.path.join(ROOT, "tests", "vectors", "aegis-1.2")
MARKER = ".generated-by-gen_golden_vectors"
SEED_PREFIX = b"aegis-golden-vectors-1.2/"     # every key and random byte below is derived from this and a name
T0 = 1795000000             # 2026-11-18 08:53:20 UTC: the clock of the first cycle
INTERVAL = 30               # the loop's interval, seconds
STATE_NAME = "/var/lib/aegis"   # what the state file calls the verifier's state directory (the gateway's default)
FLEET = "golden-fleet"          # the signed policy's audience
POLICY_VERSION = 1
POLICY_SIGNER = "golden-policy-signer"
ENDORSER = "golden-endorser"
WITH_POLICY = "pq-eat"          # the one pack exported with --with-policy

GOOD_SPE, GOOD_NSPE, GOOD_SIGNER = "11" * 32, "22" * 32, "33" * 32
TFM_VERSION = "2.3.0"


# ---- what is fixed -----------------------------------------------------------------------------------------------------

def derive(name, n=32):
    return hashlib.shake_256(SEED_PREFIX + name.encode()).digest(n)


def mldsa_keys(name):
    """(public key, secret key) of an ML-DSA-65 key from its 32-byte seed: the secret key is the seed, as the OpenSSL
    backend of common/mldsa.py keeps it."""
    from cryptography.hazmat.primitives.asymmetric import mldsa
    seed = derive("mldsa/" + name)
    return mldsa.MLDSA65PrivateKey.from_seed_bytes(seed).public_key().public_bytes_raw(), seed


def p256_key(name):
    from cryptography.hazmat.primitives.asymmetric import ec
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    return ec.derive_private_key(int.from_bytes(derive("p256/" + name, 48), "big") % (n - 1) + 1, ec.SECP256R1())


class Stream:
    """secrets.token_bytes for this run: a SHAKE-256 stream, one draw after the other."""

    def __init__(self):
        self.n = 0

    def __call__(self, n=32):
        self.n += 1
        return derive("random/%d" % self.n, n)


class Clock:
    def __init__(self, now):
        self.now = now

    def time(self):
        return float(self.now)

    def monotonic(self):
        return 1000.0           # one value: every elapsed time is 0.0


# ---- simulated devices ------------------------------------------------------------------------------------------------

def psa_tfm_token(iak, challenge, nspe=GOOD_NSPE):
    """A PSA initial attestation token as TF-M makes one (PSA profile 1 claim numbers; COSE_Sign1, ES256)."""
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
    point = iak.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    claims = {
        -75000: "PSA_IOT_PROFILE_1",
        -75001: -1,
        -75002: 0x3000,
        -75003: derive("implementation-id"),
        -75004: derive("boot-seed"),
        -75006: [
            {1: "SPE", 2: bytes.fromhex(GOOD_SPE), 4: TFM_VERSION, 5: bytes.fromhex(GOOD_SIGNER), 6: "SHA256"},
            {1: "NSPE", 2: bytes.fromhex(nspe), 4: "0.4.0", 5: bytes.fromhex(GOOD_SIGNER), 6: "SHA256"},
        ],
        -75008: challenge,
        -75009: psa_token.instance_id_for(point),
        -75010: "www.trustedfirmware.org",
    }
    protected = cbor.dumps({1: -7})
    payload = cbor.dumps(claims)
    tbs = cbor.dumps(["Signature1", protected, b"", payload])
    r, s = decode_dss_signature(iak.sign(tbs, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    return cbor.dumps(cbor.Tag(18, [protected, {}, payload, r.to_bytes(32, "big") + s.to_bytes(32, "big")]))


class Device:
    """One simulated endpoint. kind psa answers CHAL with TF-M's token; aegis-pq answers PQCHAL with that token and an
    ML-DSA-65 signature, PQEAT with an EAT that nests it; the plain-claims kinds answer PQCHAL with the claims map the
    Prover SDK makes (sdk/src/aegis_proto.c make_claims, key order as it writes them) and PQEAT with an EAT that
    carries the measurements. online=False: no answer (connection refused)."""

    def __init__(self, name, kind, profile=None, comps=None, iak=None, version="1.0.0", online=True):
        self.name, self.kind, self.profile, self.iak, self.version = name, kind, profile, iak, version
        self.comps = comps or []            # [(name, digest hex, description)]
        self.online = online
        self.pk, self.sk = mldsa_keys("device/" + name) if kind != "psa" else (None, None)

    def _check(self):
        if not self.online:
            raise ConnectionRefusedError(111, "Connection refused")

    def token(self, challenge):
        self._check()
        return psa_tfm_token(self.iak, challenge)

    def claims(self, challenge):
        """The older claims of the Prover SDK: a CBOR map, PSA profile 1 claim numbers, not sorted."""
        swc = [{1: n, 2: bytes.fromhex(d), 4: self.version, 5: bytes(32), 6: desc} for n, d, desc in self.comps]
        inst = b"\x02" + hashlib.sha256(self.pk).digest()
        return cbor.dumps({-75000: self.profile, -75008: challenge, -75009: inst, -75006: swc})

    def pq(self, challenge):
        self._check()
        import mldsa
        tok = self.token(challenge) if self.kind == "aegis-pq" else self.claims(challenge)
        return tok, mldsa.sign(self.sk, fleet.PQ_LABEL, tok)

    def eat(self, challenge):
        self._check()
        if self.kind == "aegis-pq":
            payload = eat.evidence_payload(challenge, self.pk, platform_token=self.token(challenge))
        else:
            payload = eat.evidence_payload(challenge, self.pk, [(n, bytes.fromhex(d), self.version)
                                                                for n, d, _ in self.comps], platform=self.profile)
        return cose.sign1(self.sk, self.pk, payload)

    def quote_hash(self, challenge, fmt):
        """(token_sha3_256, components as an endorsement names them) of a quote made now: what the endorser saw."""
        if fmt == fleet.EAT_COSE:
            tbs = cose.parse(self.eat(challenge)).tbs
            comps = [{"type": "SPE", "measurement_value": GOOD_SPE, "signer_id": GOOD_SIGNER},
                     {"type": "NSPE", "measurement_value": GOOD_NSPE, "signer_id": GOOD_SIGNER}] \
                if self.kind == "aegis-pq" else [{"type": n, "measurement_value": d} for n, d, _ in self.comps]
            return hashlib.sha3_256(tbs).hexdigest(), comps
        tok, _ = self.pq(challenge)
        comps = [{"type": "SPE", "measurement_value": GOOD_SPE, "signer_id": GOOD_SIGNER},
                 {"type": "NSPE", "measurement_value": GOOD_NSPE, "signer_id": GOOD_SIGNER}] \
            if self.kind == "aegis-pq" else \
            [{"type": n, "measurement_value": d, "signer_id": "00" * 32} for n, d, _ in self.comps]
        return hashlib.sha3_256(tok).hexdigest(), comps


def digest(label):
    return hashlib.sha256(SEED_PREFIX + b"measurement/" + label.encode()).hexdigest()


def fleet_devices():
    iak = p256_key("iak/tfm")
    tfm = [("SPE", digest("rw612-spe"), "SHA256 of the secure image"),
           ("NSPE", digest("rw612-nspe"), "SHA256 of the non-secure image")]
    return [
        Device("psa-tfm", "psa", iak=iak),
        Device("pq-quote", "aegis-pq", iak=iak),
        Device("pq-eat", "aegis-pq", iak=iak),
        Device("rw612-tfm-eat", "aegis-device", fleet.DEVICE_TFM_PROFILE, tfm),
        Device("rw612-els-quote", "aegis-device", fleet.DEVICE_PROFILE,
               [("APP", digest("rw612-app"), "SHA256 of the image in flash")]),
        Device("zynqmp-devhuk-eat", "aegis-tee", fleet.TEE_DEVHUK_PROFILE,
               [("TA", digest("zynqmp-ta"), "SHA256 of the trusted application")]),
        Device("zynqmp-optee-quote", "aegis-tee", fleet.TEE_PROFILE,
               [("TA", digest("zynqmp-ta-unknown"), "SHA256 of the trusted application")]),
        Device("linux-host", "aegis-linux", fleet.LINUX_PROFILE,
               [("PROVER", digest("linux-prover"), "SHA256 of aegis_linux_prover.py"),
                ("KERNEL", digest("linux-kernel"), "SHA256 of vmlinuz")]),
        Device("offline-eat", "aegis-device", fleet.DEVICE_TFM_PROFILE, tfm, online=False),
    ]


# ---- the policy ---------------------------------------------------------------------------------------------------------

def allowed_of(dev):
    if dev.kind in ("psa", "aegis-pq"):
        return [{"type": "SPE", "measurement_value": GOOD_SPE, "signer_id": GOOD_SIGNER, "image": "TF-M " + TFM_VERSION},
                {"type": "NSPE", "measurement_value": GOOD_NSPE, "signer_id": GOOD_SIGNER, "image": "prover-ns 0.4.0"}]
    if dev.name == "zynqmp-optee-quote":          # the device reports another TA than the one allowed: refused
        return [{"type": "TA", "measurement_value": digest("zynqmp-ta")}]
    return [{"type": n, "measurement_value": d} for n, d, _ in dev.comps]


def policy_entries(devs, verifier_pk):
    """The policy's entries: one per device, each kind and evidence format, and most of the keys an entry can have."""
    out = []
    for i, dev in enumerate(devs):
        e = {"name": dev.name, "kind": dev.kind, "host": "192.0.2.%d" % (10 + i), "port": 7444}
        if dev.kind == "psa":
            e.update(iak_pub_pem="keys/tfm-iak.pub.pem")
        else:
            e["pq_pub_file"] = "keys/%s.mldsa65.pub" % dev.name
            e["pq_pub_sha256"] = hashlib.sha256(dev.pk).hexdigest()
        if dev.kind == "aegis-pq":
            e["iak_pub_pem"] = "keys/tfm-iak.pub.pem"
        if dev.profile is not None:
            e["profile"] = dev.profile
        e["allowed"] = allowed_of(dev)
        if dev.name.endswith("-eat"):
            e["evidence_format"] = fleet.EAT_COSE
        out.append(e)
    by = {e["name"]: e for e in out}
    by["pq-quote"].update(endorsement="required", transcript="v2", provision=True, heartbeat_mac="kmac256",
                          note="the older quote (PQCHAL), endorsed by a JSON record; a session would be bound to "
                               "the attestation (transcript v2)")
    by["pq-eat"].update(endorsement="required", endorsement_file="endorsements/pq-eat.cbor",
                        note="standard evidence (PQEAT) nesting TF-M's token, endorsed by a COSE record")
    by["rw612-tfm-eat"].update(endorsement="required", endorsement_file="endorsements/rw612-tfm-eat.cbor",
                               max_endorsement_age_s=31536000)
    by["zynqmp-devhuk-eat"].update(allow_dev_profile=True,
                                   note="development profile: one key for every chip, admitted with a warning")
    by["zynqmp-optee-quote"]["note"] = "reports a trusted application the policy does not allow: refused"
    by["linux-host"].update(heartbeat_mac="sha3-256", verifier_pin_sha256=hashlib.sha256(verifier_pk).hexdigest())
    by["offline-eat"]["note"] = "does not answer: nothing to appraise"
    return out


def save_policy(path, policy):
    with open(path, "w") as f:
        f.write(json.dumps(policy, indent=1) + "\n")
    with open(path, "rb") as f:
        return f.read()


def write_hex(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(data.hex() + "\n")


def endorse(policy, pol_path, base, dev, ep, endorser_pk, endorser_sk, scratch, fmt):
    """An endorsement record for dev, signed as provision/aegis_provision.py endorse signs one (JSON or COSE), then
    installed and pinned as `fleet.py enroll-endorsed` does it."""
    challenge = secrets.token_bytes(32)
    token_hash, comps = dev.quote_hash(challenge, ep.get("evidence_format"))
    body = {"v": 1, "type": "endorsement", "device": dev.name, "kind": dev.kind, "device_pk_alg": endorsement.PK_ALG,
            "device_pk_sha256": hashlib.sha256(dev.pk).hexdigest(),
            "measurements": sorted(comps, key=lambda m: m["type"]),
            "evidence": {"challenge": challenge.hex(), "token_sha3_256": token_hash},
            "device_state": "closed" if dev.kind == "aegis-device" else "development", "endorser": ENDORSER,
            "endorser_pk_sha256": hashlib.sha256(endorser_pk).hexdigest(), "issued": int(time.time()) - 86400,
            "serial": "GOLDEN-%s" % dev.name.upper()}
    if dev.profile is not None:
        body["profile"] = dev.profile
    if fmt == "cose":
        body.update(expires=body["issued"] + 2 * 31536000, instance_id=eat.ueid_for(dev.pk).hex(),
                    notes="synthetic: tools/gen_golden_vectors.py")
        data = endorsement.sign_cose(body, endorser_sk, endorser_pk, dev.pk)
    else:
        data = endorsement.dumps(endorsement.sign(body, endorser_sk, dev.pk))
    rec = os.path.join(scratch, "%s.record" % dev.name)
    with open(rec, "wb") as f:
        f.write(data)
    fleet.install_endorsement(policy, base, rec, policy_path=pol_path)
    with open(pol_path) as f:
        policy.clear()
        policy.update(json.load(f))


# ---- the run ------------------------------------------------------------------------------------------------------------

def _answer(devs, what):
    by = {}

    def fn(host, port, challenge, timeout):
        dev = by[(host, int(port))]
        return getattr(dev, what)(challenge)
    return by, fn


def _clean_paths(v, state):
    """The verifier's temporary state directory, as the gateway's own one."""
    if isinstance(v, str):
        return v.replace(state, STATE_NAME)
    if isinstance(v, dict):
        return {k: _clean_paths(x, state) for k, x in v.items()}
    if isinstance(v, list):
        return [_clean_paths(x, state) for x in v]
    return v


def generate(out):
    """Write every vector into out (a new directory). Returns a summary for the README."""
    clock, stream = Clock(T0), Stream()
    with mock.patch("time.time", clock.time), mock.patch("time.monotonic", clock.monotonic), \
            mock.patch.object(secrets, "token_bytes", stream), tempfile.TemporaryDirectory() as tmp:
        return _generate(out, clock, os.path.join(tmp, "state"), os.path.join(tmp, "scratch"))


def _generate(out, clock, state, scratch):
    from cryptography.hazmat.primitives import serialization
    os.makedirs(scratch)
    os.makedirs(state, mode=0o700)
    base = os.path.join(out, "policy")
    os.makedirs(os.path.join(base, "keys"))
    devs = fleet_devices()

    # the verifier: an identity as aegisd.py init makes one (the secret key stays in the temporary state)
    vpk, vsk = mldsa_keys("verifier")
    with open(os.path.join(state, "identity.json"), "w") as f:
        json.dump({"body": {"v": 1, "type": "identity", "pk": vpk.hex()}}, f)
    with open(os.path.join(state, "identity.sk"), "wb") as f:
        f.write(vsk)

    # the keys the policy names
    with open(os.path.join(base, "keys", "tfm-iak.pub.pem"), "wb") as f:
        f.write(devs[0].iak.public_key().public_bytes(serialization.Encoding.PEM,
                                                      serialization.PublicFormat.SubjectPublicKeyInfo))
    epk, esk = mldsa_keys("endorser")
    write_hex(os.path.join(base, "endorsers", ENDORSER + ".mldsa65.pub"), epk)
    ppk, psk = mldsa_keys("policy-signer")

    policy = {
        "note": "Synthetic golden vectors (tools/gen_golden_vectors.py): every key is derived from a published seed. "
                "Not a policy for any real fleet.",
        "timeout_s": 5,
        "attestation_results": True,
        "audit_log": {"checkpoint_s": 3600, "min_interval_s": 0, "segment_bytes": 1048576, "max_segments": 0},
        "enforce_cmd": ["true"],
        "max_endorsement_age_s": 63072000,
        "endorsers": [{"name": ENDORSER, "pk_file": "endorsers/%s.mldsa65.pub" % ENDORSER,
                       "pk_sha256": hashlib.sha256(epk).hexdigest()}],
        "endpoints": policy_entries(devs, vpk),
    }
    pol_path = os.path.join(base, "fleet.json")
    save_policy(pol_path, policy)
    by_name = {e["name"]: e for e in policy["endpoints"]}
    for dev in devs:
        e = by_name[dev.name]
        if dev.kind != "psa" and e.get("endorsement") is None:
            write_hex(os.path.join(base, e["pq_pub_file"]), dev.pk)          # pinned on first use (enroll-pq)
    endorse(policy, pol_path, base, devs[1], by_name["pq-quote"], epk, esk, scratch, "json")
    for name in ("pq-eat", "rw612-tfm-eat"):
        dev = next(d for d in devs if d.name == name)
        endorse(policy, pol_path, base, dev, {e["name"]: e for e in policy["endpoints"]}[name], epk, esk, scratch,
                "cose")
    with open(pol_path, "rb") as f:
        policy_json = f.read()
    for leftover in os.listdir(base):
        if leftover.endswith(".bak"):
            os.remove(os.path.join(base, leftover))     # install_endorsement keeps the policy before as POLICY.bak

    # the signed policy (provision/aegis_provision.py policy-sign) and the verifier's signers file
    with open(os.path.join(base, "fleet.cose"), "wb") as f:
        f.write(signed_policy.sign(psk, ppk, policy_json, POLICY_VERSION, POLICY_SIGNER, T0 - 3600, FLEET))
    signers = signed_policy.signers_file([(POLICY_SIGNER, ppk)], FLEET)
    with open(os.path.join(base, "policy-signers.json"), "wb") as f:
        f.write(signers)
    with open(os.path.join(state, "policy-signers.json"), "wb") as f:
        f.write(signers)

    # the loop, as `fleet.py watch` runs it from the signed policy, its requests answered by the devices
    pol, pol_bytes, pinfo = fleet.load_policy(os.path.join(base, "fleet.cose"), state, remember=True)
    assert pol_bytes == policy_json
    addr = {}
    for e in pol["endpoints"]:
        addr[(e["host"], e["port"])] = next(d for d in devs if d.name == e["name"])
    patches = []
    for what, fn_name in (("token", "request_token"), ("pq", "request_pq"), ("eat", "request_eat")):
        by, fn = _answer(devs, what)
        by.update(addr)
        patches.append(mock.patch.object(fleet, fn_name, fn))
    for p in patches:
        p.start()
    try:
        run = dict(credentials=False, interval=INTERVAL, state=state, require_pin=False, enforce_hooks=True,
                   policy_bytes=pol_bytes)
        started = {"platform": "linux", "enforcing": True, "credentials": False, "verifier": "aegis-fleet-verifier 1",
                   "cmd": "watch"}
        grace = fleet.admit_ttl(pol, INTERVAL)
        trail = fleet.open_audit(pol, state, None, grace, True, started, [None])
        heads = []

        def cycle():
            trail.policy(pinfo, pol)
            verdicts = fleet.run_once(pol, base, psa_token.verify_with_cryptography, audit=trail, **run)
            for v in verdicts:
                v.pop("enforce_note", None)
            for b in trail.flush():
                heads.append((b.batch, b.head.hex(), clock.now))
            return verdicts

        # cycle 1: every decision is logged, every verdict gets its signed result: the packs and the state file
        verdicts = cycle()
        os.makedirs(os.path.join(out, "packs"))
        manifests = {}
        for e in pol["endpoints"]:
            manifests[e["name"]] = fleet.export_evidence(pol, pol_bytes, base, state, e["name"],
                                                         os.path.join(out, "packs", e["name"]),
                                                         with_policy=e["name"] == WITH_POLICY)
        with open(os.path.join(out, "fleet-state.json"), "w") as f:
            json.dump(_clean_paths({"updated": int(clock.time()), "verdicts": verdicts}, state), f, indent=1)
            f.write("\n")
        # cycle 2: nothing changed, nothing is written
        clock.now += INTERVAL
        cycle()
        # cycle 3: the Linux host does not answer: a "refuse" entry. The anchor is taken here, as `fleet.py audit
        # --out` takes one
        clock.now += INTERVAL
        next(d for d in devs if d.name == "linux-host").online = False
        cycle()
        _, anchor = fleet.audit_report(state, now=clock.now)
        anchor_batch = cbor.loads(cose.parse(anchor).payload)[3]
        # cycle 4: it answers again: an "admit" entry
        clock.now += INTERVAL
        next(d for d in devs if d.name == "linux-host").online = True
        cycle()
        # an hour later: nothing changed, but the promise of the last batch is about to lapse: an empty batch
        clock.now += 3600
        cycle()
        checked_at = clock.now
        report, _ = fleet.audit_report(state, entries=True, now=checked_at)
    finally:
        for p in patches:
            p.stop()

    # the audit log: its one segment, the anchor, the verifier's key, and what `fleet.py audit --entries` reports
    adir = os.path.join(out, "audit")
    os.makedirs(adir)
    segs = sorted(n for n in os.listdir(os.path.join(state, "audit")) if n.startswith("audit-"))
    for n in segs:
        shutil.copy(os.path.join(state, "audit", n), os.path.join(adir, n))
    with open(os.path.join(adir, "anchor.cbor"), "wb") as f:
        f.write(anchor)
    write_hex(os.path.join(adir, "verifier.mldsa65.pub"), vpk)
    with open(os.path.join(adir, "audit-report.json"), "w") as f:
        json.dump(_clean_paths(dict(fleet._jsonable(report), verified=True), state), f, indent=1)
        f.write("\n")
    with open(os.path.join(out, MARKER), "w") as f:
        f.write("tools/gen_golden_vectors.py writes this directory; it replaces it as a whole\n")
    summary = {"verdicts": verdicts, "manifests": manifests, "segments": segs, "anchor_batch": anchor_batch,
               "heads": heads, "checked_at": checked_at, "keys": {
                   "verifier": cose.key_thumbprint(vpk).hex(), "endorser": cose.key_thumbprint(epk).hex(),
                   "policy-signer": cose.key_thumbprint(ppk).hex()},
               "devices": {d.name: cose.key_thumbprint(d.pk).hex() for d in devs if d.pk is not None}}
    write_readme(out, summary)
    return summary


# ---- the README ---------------------------------------------------------------------------------------------------------

PACK_NOTES = {
    "psa-tfm": "kind `psa`: TF-M's PSA token alone (`evidence.token`, ES256, checked with `keys/device-iak.pem`, not "
               "by the standalone checker). The key is pinned, not endorsed: `warning` (instance identity -33)",
    "pq-quote": "kind `aegis-pq`, the older quote: TF-M's token and a detached ML-DSA-65 signature "
                "(`evidence.token`, `evidence.sig`); endorsed by a JSON record (`endorsement.json`): `affirming`, "
                "trust `trustzone`",
    "pq-eat": "kind `aegis-pq`, standard evidence: an EAT nesting TF-M's token (`evidence.cbor`); endorsed by a COSE "
              "record (`endorsement.cbor`); exported with `--with-policy` (`policy.json`): `affirming`",
    "rw612-tfm-eat": "kind `aegis-device`, profile `aegis-rw612-tfm-v1`, standard evidence with measured components; "
                     "endorsed (COSE record with a UEID, an expiry and notes): `affirming`, trust `trustzone`",
    "rw612-els-quote": "kind `aegis-device`, profile `aegis-rw612-els-v1`, the older claims map; trust on first use: "
                       "`warning` (-33 and executables -35), trust `device-key`",
    "zynqmp-devhuk-eat": "kind `aegis-tee`, the development profile with `allow_dev_profile`: `warning` (-34), trust "
                         "`development-shared-key`, the verdict's warning in the result's details",
    "zynqmp-optee-quote": "kind `aegis-tee`, profile `aegis-zynqmp-optee-v1`, the older claims map with a component "
                          "the policy does not allow: not admitted, `contraindicated` (executables 33)",
    "linux-host": "kind `aegis-linux`, the older claims map: `warning`, trust `software`",
    "offline-eat": "kind `aegis-device` that did not answer: no evidence in the pack, `incomplete`",
}


def write_readme(out, s):
    rows = []
    for v in s["verdicts"]:
        m = s["manifests"][v["endpoint"]]
        rows.append("| [`packs/%s/`](packs/%s/) | %s | %s | %s |" % (
            v["endpoint"], v["endpoint"], m["evidence_format"] or "none", m["result"]["status"],
            PACK_NOTES[v["endpoint"]]))
    keys = "\n".join("| %s | `%s` |" % (k, t) for k, t in sorted(s["keys"].items())) + "\n" + \
        "\n".join("| device `%s` | `%s` |" % (k, t) for k, t in sorted(s["devices"].items()))
    text = """<!-- SPDX-License-Identifier: Apache-2.0 -->
# Golden vectors, Aegis 1.2

Synthetic: written by [`tools/gen_golden_vectors.py`](../../../tools/gen_golden_vectors.py) with the repository's own
writers, in one process, with no board, no network and no bench data. Every key is derived from a published seed
(`%s` and a name, in the generator), so **none is a secret and none is a real device's or verifier's**; the
addresses are from TEST-NET-1. The formats are specified in [`docs/data-formats.md`](../../../docs/data-formats.md)
and the JSON Schemas in [`docs/schemas/`](../../../docs/schemas/); `tests/host/test_golden_vectors.py` checks that
these files still verify and still match the schemas, and that a fresh run of the generator makes the same structure.

**What is the same in every run and what is not.** The keys, the challenges, the clock (first cycle at %d), the
PSA tokens and the claims inside the device evidence are fixed. ML-DSA-65 signatures are hedged (FIPS 204), so every
COSE object, detached signature and endorsement record differs from run to run, and so does every hash over one of
them: the SHA-256 of the files in a manifest, the record names the policy pins (`endorsement_sha256`), and therefore
the policy's own hash and `ni` name, and the audit log's chain. Compare structure and verify signatures; do not
compare these bytes.

## The files

| Path | What it shows |
|---|---|
| [`policy/fleet.json`](policy/fleet.json) | the fleet policy: one entry per device, every kind and evidence format, and most keys an entry can have ([`policy.schema.json`](../../../docs/schemas/policy.schema.json)) |
| [`policy/fleet.cose`](policy/fleet.cose) | the same policy signed (COSE_Sign1, ML-DSA-65), version %d, audience `%s`, signer `%s` |
| [`policy/policy-signers.json`](policy/policy-signers.json) | the verifier's signers file for it ([`policy-signers.schema.json`](../../../docs/schemas/policy-signers.schema.json)) |
| [`policy/keys/`](policy/keys/) | the devices' ML-DSA-65 public keys in hex (`pq_pub_file`) and the TF-M attestation key (`tfm-iak.pub.pem`) |
| [`policy/endorsers/`](policy/endorsers/) | the endorser's ML-DSA-65 public key in hex (`endorsers[].pk_file`) |
| [`policy/endorsements/`](policy/endorsements/) | the installed records: `pq-quote.json` (JSON form, [`endorsement.schema.json`](../../../docs/schemas/endorsement.schema.json)), `pq-eat.cbor` and `rw612-tfm-eat.cbor` (COSE form) |
| [`fleet-state.json`](fleet-state.json) | the verdicts of the first cycle as `fleet.py watch` writes them ([`fleet-state.schema.json`](../../../docs/schemas/fleet-state.schema.json)); the state directory is named `%s` |
| `packs/<name>/` | the evidence pack of each entry after that cycle, as `fleet.py export-evidence` writes it ([`manifest.schema.json`](../../../docs/schemas/manifest.schema.json)) |
| [`audit/%s`](audit/%s) | the audit log of five cycles, one segment of %d batches |
| [`audit/anchor.cbor`](audit/anchor.cbor) | an anchor: batch %d, kept as `fleet.py audit --out` keeps one after the third cycle |
| [`audit/verifier.mldsa65.pub`](audit/verifier.mldsa65.pub) | the verifier's identity key in hex: it signs the results and the batches |
| [`audit/audit-report.json`](audit/audit-report.json) | what `fleet.py audit --entries` reports for the log at %d |

## The packs

| Pack | Evidence format | Result | What it shows |
|---|---|---|---|
%s

## The keys, by COSE Key Thumbprint

| Key | Thumbprint |
|---|---|
%s

## Checking them

    tools/verify_evidence.py pack packs/pq-eat --verifier-key %s
    tools/verify_audit.py log audit --key audit/verifier.mldsa65.pub --anchor audit/anchor.cbor --at %d
    tools/verify_audit.py policy policy/fleet.cose --key policy/policy-signers.json --audience %s

The audit log promises its next batch: checked later than its last batch's `due` without `--at` (or with
`--no-freshness`), it is reported stale, as a log whose verifier stopped is. Its batches, by the verifier's clock:

%s

Make them again: `tools/gen_golden_vectors.py` (it replaces this directory).
""" % (SEED_PREFIX.decode(), T0, POLICY_VERSION, FLEET, POLICY_SIGNER, STATE_NAME, s["segments"][0],
       s["segments"][0], len(s["heads"]), s["anchor_batch"], s["checked_at"], "\n".join(rows), keys,
       s["keys"]["verifier"], s["checked_at"], FLEET,
       "\n".join("    batch %d at %d" % (b, t) for b, _, t in s["heads"]))
    with open(os.path.join(out, "README.md"), "w") as f:
        f.write(text)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("out", nargs="?", default=DEFAULT_OUT)
    a = ap.parse_args(argv)
    out = os.path.abspath(a.out)
    if os.path.exists(out):
        if not os.path.exists(os.path.join(out, MARKER)):
            ap.error("%s exists and was not written by this tool: not replaced" % out)
        shutil.rmtree(out)
    s = generate(out)
    print("golden vectors in %s: %d packs (%s), %d audit batches, a signed policy" % (
        out, len(s["manifests"]), ", ".join("%s %s" % (n, m["result"]["status"]) for n, m in s["manifests"].items()),
        len(s["heads"])))
    return 0


if __name__ == "__main__":
    sys.exit(main())
