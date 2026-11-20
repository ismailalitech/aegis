#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Aegis provisioning tool: endorse a device's identity key at the bench (docs/enrolment.md).

  aegis_provision.py init    --name NAME [--state DIR] [--key-store auto|tpm|software] [--tpm-pcrs 7]
  aegis_provision.py show    [--state DIR]
  aegis_provision.py export  DIR [--state DIR]        the endorser's public key, for a policy's "endorsers"
  aegis_provision.py endorse POLICY DEVICE [DEVICE...] [--state DIR] [--out DIR] [--serial S] [--notes TEXT]
                             [--valid-days N] [--device-state development|closed]

Run it on the bench PC, with the device on a cable or LAN that nobody else can answer on: that is the one thing the
tool cannot check and the whole of what an endorsement rests on.

endorse does, for each DEVICE (an entry of POLICY, whose "allowed" list is the reference this endorser appraises
against):
  1. asks the device for its ML-DSA-65 identity key (PQKEY) and for a quote over a fresh challenge (PQCHAL): the
     commands every Aegis endpoint already has, so no firmware changes for this (three requests in all, with the
     second quote of step 4);
  2. appraises the quote with the verifier's own code (fleet.attest): signed by that key, for this challenge, of the
     entry's kind and profile, every component in the reference;
  3. signs an endorsement record (common/endorsement.py) naming the device, the key's hash, the family, the
     components it reported, the quote, this endorser and the time;
  4. checks the finished record as a verifier will: the bytes that will be written, parsed again, against this
     endorser's public key; and then the whole of it, by asking the device for a second quote and running the
     verifier's attestation with "endorsement": "required" on that record. A record that would not admit the device
     it was made from is not written;
  5. logs it in the endorser's ledger (STATE/issued.jsonl) and only then writes it, under a temporary name first,
     to OUT/<device>.json.
Any failure before step 5 leaves no record. The record alone changes nothing at a verifier: `fleet.py enroll-endorsed
POLICY RECORD` installs it there, with its own checks.

The endorser's key is ML-DSA-65, made by init and kept like a verifier's identity (common/keystore.py): sealed to this
machine's TPM 2.0 when one is usable, else a 0600 file. STATE defaults to $AEGIS_ENDORSER_DIR, else
~/.local/state/aegis-endorser. Whoever can use that key can make any key a trusted device key at every verifier that
lists it.
"""
import argparse
import hashlib
import json
import os
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for p in ("../common", "../gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, p)))
import endorsement  # noqa: E402
import fleet  # noqa: E402
import keystore  # noqa: E402
import mldsa  # noqa: E402
import psa_token  # noqa: E402
import wire  # noqa: E402

RECORD = "endorser.json"
LEDGER = "issued.jsonl"


def default_state():
    return os.environ.get("AEGIS_ENDORSER_DIR") or os.path.join(
        os.environ.get("XDG_STATE_HOME") or os.path.join(os.path.expanduser("~"), ".local", "state"), "aegis-endorser")


class Endorser:
    """The endorser's name and key pair, loaded from its state directory. The secret key is loaded (from the TPM,
    if it is sealed there) when it is first used: show and export never touch it."""

    def __init__(self, state, tcti=None):
        self.state, self._tcti, self._sk = state, tcti, None
        with open(os.path.join(state, RECORD)) as f:
            rec = json.load(f)
        body = rec["body"]
        self.pk = bytes.fromhex(body["pk"])
        if body.get("type") != "endorser" or not mldsa.verify(self.pk, endorsement.ENDORSER_LABEL,
                                                              wire.canonical(body), bytes.fromhex(rec["sig"])):
            raise ValueError("%s is not a self-signed endorser record" % os.path.join(state, RECORD))
        self.name, self.body = body["name"], body
        self.pk_sha256 = endorsement.pk_sha256(self.pk)

    @property
    def sk(self):
        if self._sk is None:
            self._sk, _ = keystore.load(self.state, self.pk, self._tcti)
        return self._sk

    @sk.setter
    def sk(self, value):
        self._sk = value

    def trust(self):
        """This endorser as a verifier's trust list: what the finished record is checked against before it is
        written."""
        return {self.pk_sha256: {"name": self.name, "pk": self.pk, "revoked": False}}

    def policy_entry(self):
        return {"name": self.name, "pk_file": "endorsers/%s.mldsa65.pub" % self.name, "pk_sha256": self.pk_sha256}


def init(state, name, key_store="auto", pcrs=None, force=False, tcti=None):
    """Make the endorser's key and its self-signed record. Returns the record's body."""
    if not endorsement._is_text(name, 64) or any(c in name for c in "/\\ \t\n") or name.startswith("."):
        raise SystemExit("the endorser's name must be a short word (it becomes a file name)")
    os.makedirs(state, mode=0o700, exist_ok=True)
    if keystore.stored_where(state) and not force:
        raise SystemExit("an endorser key exists in %s (--force makes a new one; verifiers then need the new key)"
                         % state)
    store, why = keystore.SOFTWARE, "--key-store software"
    if key_store != "software":
        ok, why, _ = keystore.tpm_status(tcti)
        if ok:
            store, why = keystore.TPM, ""
        elif key_store == "tpm":
            raise SystemExit("no usable TPM: %s" % why)
    pk, sk = mldsa.keypair()
    where = keystore.save(state, sk, pk, store, pcrs, tcti)
    body = {"v": 1, "type": "endorser", "name": name, "pk_alg": endorsement.PK_ALG, "pk": pk.hex(),
            "key_store": where["key_store"], "created": int(time.time())}
    if where["key_store"] == keystore.TPM:
        body["key_store_tpm"] = where["tpm"]
    else:
        body["key_storage"] = "software, file mode 0600 (no TPM: %s)" % why
    rec = {"body": body, "sig": mldsa.sign(sk, endorsement.ENDORSER_LABEL, wire.canonical(body)).hex()}
    endorsement.write_atomic(os.path.join(state, RECORD), (json.dumps(rec, indent=1) + "\n").encode(), 0o600)
    return body


def _reference_entry(reference, typ, value):
    """The reference entry a reported component matched, as the record's measurement. The signer is named where the
    reference names one (attest() has checked it then)."""
    hits = [r for r in reference if r.get("type") == typ and r.get("measurement_value") == value]
    signers = {r.get("signer_id") for r in hits}
    if not hits or len(signers) != 1:
        raise endorsement.Refused("component %s matches %d reference entries with different signers" % (typ, len(hits)))
    m = {"type": typ, "measurement_value": value}
    if hits[0].get("signer_id"):
        m["signer_id"] = hits[0]["signer_id"]
    return m


def appraise(ep, base_dir, timeout, ecdsa_verify):
    """Steps 1 and 2: the device's key and the verdict of the verifier's own attestation with that key. Returns
    (public key, verdict); the verdict is admitted or carries the reasons."""
    errors = fleet.policy_errors({k: v for k, v in ep.items() if k != "endorsement"})
    if ep.get("kind") not in fleet.PQ_KINDS:
        errors.append("kind %s has no post-quantum key to endorse" % ep.get("kind", "psa"))
    if ep.get("profile") in fleet.DEV_PROFILES:
        errors.append("profile %s has one key for every chip: an endorsement cannot tie it to one device"
                      % ep["profile"])
    if not ep.get("allowed"):
        errors.append('the entry has no reference measurements ("allowed")')
    if errors:
        return None, {"admitted": False, "reasons": errors}
    try:
        pk = fleet.request_pq_key(ep["host"], int(ep["port"]), timeout)
    except (OSError, ValueError) as e:
        return None, {"admitted": False, "reasons": ["no identity key: %s" % e]}
    if len(pk) != mldsa.PK_LEN:
        return None, {"admitted": False, "reasons": ["the identity key is not an ML-DSA-65 public key"]}
    with tempfile.TemporaryDirectory() as tmp:
        keyf = os.path.join(tmp, "device.pub")
        with open(keyf, "w") as f:
            f.write(pk.hex() + "\n")
        # the entry as a verifier would hold it after this enrolment, minus the endorsement being made; relative
        # paths in it (the ES256 key of an aegis-pq token) still resolve against the policy
        entry = {k: v for k, v in ep.items() if k not in ("endorsement", "endorsement_file")}
        entry["pq_pub_file"] = keyf
        return pk, fleet.attest(entry, ecdsa_verify, base_dir, timeout)


def confirm(endorser, ep, base_dir, data, pk, timeout, ecdsa_verify):
    """Step 4's second half: the verifier's own attestation of the device, with the finished record required. Returns
    the reasons it was not admitted (empty: it was)."""
    with tempfile.TemporaryDirectory() as tmp:
        files = {"device.pub": pk.hex().encode(), "record.json": data, "endorser.pub": endorser.pk.hex().encode()}
        for name, content in files.items():
            with open(os.path.join(tmp, name), "wb") as f:
                f.write(content)
        entry = {k: v for k, v in ep.items() if k not in ("provision", "transcript", "endorsement_sha256")}
        entry.update(endorsement="required", pq_pub_file=os.path.join(tmp, "device.pub"),
                     endorsement_file=os.path.join(tmp, "record.json"))
        trust = [{"name": endorser.name, "pk_file": os.path.join(tmp, "endorser.pub"),
                  "pk_sha256": endorser.pk_sha256}]
        v = fleet.attest(entry, ecdsa_verify, base_dir, timeout, trust)
    if v["admitted"] and v.get("enrolment") == fleet.ENDORSED:
        return []
    return v["reasons"] or ["not admitted"]


def endorse(endorser, ep, base_dir, out_dir, serial=None, notes=None, valid_days=None, device_state="development",
            timeout=20.0, ecdsa_verify=psa_token.verify_with_openssl_cli):
    """Endorse one device (the module text has the steps). Returns a result dict; "endorsed" is True only when the
    record is in out_dir. Never leaves a partial record."""
    t0 = time.monotonic()
    name = ep.get("name")
    res = {"device": name, "endorsed": False}
    pk, v = appraise(ep, base_dir, timeout, ecdsa_verify)
    if not v.get("admitted"):
        res["reasons"] = v.get("reasons", [])
        return res
    kind = ep["kind"]
    profile = ep.get("profile") if kind in fleet.PLAIN_KINDS else None
    try:
        now = int(time.time())
        body = {"v": 1, "type": "endorsement", "device": name, "kind": kind,
                "device_pk_alg": endorsement.PK_ALG, "device_pk_sha256": endorsement.pk_sha256(pk),
                "measurements": sorted((_reference_entry(ep["allowed"], t, m) for t, m in v["measurements"].items()),
                                       key=lambda m: m["type"]),
                "evidence": v["quote"], "device_state": device_state,
                "endorser": endorser.name, "endorser_pk_sha256": endorser.pk_sha256, "issued": now}
        if profile:
            body["profile"] = profile
        if v.get("instance_id"):
            body["instance_id"] = v["instance_id"]
        if serial:
            body["serial"] = serial
        if notes:
            body["notes"] = notes
        if valid_days:
            body["expires"] = now + int(valid_days * 86400)
        rec = endorsement.sign(body, endorser.sk, pk)
        data = endorsement.dumps(rec)
        # verify before commit: the bytes that will be written, read as a verifier reads them
        endorsement.check(endorsement.loads(data), endorser.trust(), name, kind, profile, pk, now)
    except (ValueError, TypeError, KeyError, RuntimeError) as e:
        res["reasons"] = ["no record made: %s" % e]
        return res
    refused = confirm(endorser, ep, base_dir, data, pk, timeout, ecdsa_verify)
    if refused:
        res["reasons"] = ["no record made: a verifier with this record would not admit the device: %s"
                          % "; ".join(refused)]
        return res
    path = os.path.join(out_dir, "%s.json" % name)
    res.update({"device_pk_sha256": body["device_pk_sha256"], "record_sha256": endorsement.record_sha256(rec),
                "family": endorsement.family(kind, profile), "measurements": body["measurements"],
                "device_state": device_state})
    try:
        ledger(endorser.state, dict(res, time=now, serial=serial, host=ep.get("host")))
        endorsement.write_atomic(path, data)
    except OSError as e:
        res["reasons"] = ["record not written: %s" % e]
        return res
    res.update({"endorsed": True, "record": path, "elapsed_s": round(time.monotonic() - t0, 3)})
    return res


def ledger(state, entry):
    """One line per signature this endorser made, appended and flushed to disk before the record is handed out."""
    entry = {k: v for k, v in entry.items() if k != "endorsed" and v is not None}
    fd = os.open(os.path.join(state, LEDGER), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a") as f:
        f.write(json.dumps(entry, sort_keys=True) + "\n")
        f.flush()
        os.fsync(f.fileno())


def main(argv=None):
    ap = argparse.ArgumentParser(description="Aegis provisioning tool (endorser)")
    ap.add_argument("cmd", choices=["init", "show", "export", "endorse"])
    ap.add_argument("args", nargs="*", help="export: DIR; endorse: POLICY DEVICE [DEVICE...]")
    ap.add_argument("--state", default=default_state())
    ap.add_argument("--name", help="init: the endorser's name")
    ap.add_argument("--key-store", choices=["auto", "tpm", "software"], default="auto",
                    help="init: where the endorser's key lives (auto: the TPM if usable, else a 0600 file)")
    ap.add_argument("--tpm-pcrs", default="", help="init with the TPM: comma-separated sha256 PCRs the seal requires")
    ap.add_argument("--force", action="store_true", help="init: replace the endorser's key")
    ap.add_argument("--out", help="endorse: where the records go (default: STATE/issued)")
    ap.add_argument("--serial", help="endorse: the board's serial number or label (one DEVICE per call then)")
    ap.add_argument("--notes", help="endorse: free text for the record")
    ap.add_argument("--valid-days", type=float, help="endorse: the record expires after this many days (default: "
                    "it does not expire)")
    ap.add_argument("--device-state", choices=endorsement.DEVICE_STATES, default="development",
                    help="endorse: the device's lifecycle as the operator knows it (default: development, which is "
                         "every board on this bench)")
    ap.add_argument("--timeout", type=float, default=20.0)
    a = ap.parse_args(argv)
    if a.cmd == "init":
        if not a.name or a.args:
            ap.error("init needs --name and nothing else")
        body = init(a.state, a.name, a.key_store, [int(p) for p in a.tpm_pcrs.split(",") if p.strip()], a.force)
        print("endorser %s created in %s, public key sha256 %s" % (a.name, a.state, hashlib.sha256(
            bytes.fromhex(body["pk"])).hexdigest()))
        print("key store: %s" % (body.get("key_storage") or "TPM 2.0, sealed (%s)" % body["key_store"]))
        return 0
    try:
        endorser = Endorser(a.state)
    except (OSError, ValueError, KeyError) as e:
        raise SystemExit("no usable endorser in %s (aegis_provision.py init --name NAME): %s" % (a.state, e))
    if a.cmd == "show":
        print(json.dumps({"endorser": endorser.name, "pk_sha256": endorser.pk_sha256,
                          "key_store": endorser.body["key_store"], "state": a.state,
                          "policy_entry": endorser.policy_entry()}, indent=1))
        return 0
    if a.cmd == "export":
        if len(a.args) != 1:
            ap.error("export DIR")
        path = os.path.join(a.args[0], "%s.mldsa65.pub" % endorser.name)
        endorsement.write_atomic(path, endorser.pk.hex().encode() + b"\n")
        print("%s\nadd to the policy's \"endorsers\": %s" % (path, json.dumps(endorser.policy_entry())))
        return 0
    if len(a.args) < 2:
        ap.error("endorse POLICY DEVICE [DEVICE...]")
    if a.serial and len(a.args) > 2:
        ap.error("--serial names one board: endorse one DEVICE per call with it")
    try:
        endorser.sk         # before any device is asked: a key that cannot be loaded (another TPM, a missing file)
    except (OSError, RuntimeError, ValueError) as e:
        raise SystemExit("the endorser's key in %s cannot be used: %s" % (a.state, e))
    with open(a.args[0]) as f:
        policy = json.load(f)
    base = os.path.dirname(os.path.abspath(a.args[0]))
    out = a.out or os.path.join(a.state, "issued")
    failed = 0
    for name in a.args[1:]:
        eps = [e for e in policy.get("endpoints", []) if e.get("name") == name]
        if len(eps) != 1:
            res = {"device": name, "endorsed": False, "reasons": ["the policy has %d entries of that name" % len(eps)]}
        else:
            res = endorse(endorser, eps[0], base, out, a.serial, a.notes, a.valid_days, a.device_state, a.timeout)
        failed += not res["endorsed"]
        print(json.dumps(res, indent=1), flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
