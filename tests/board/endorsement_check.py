#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Endorsed enrolment on real endpoints (docs/enrolment.md): an unendorsed or substituted key is refused.

Runs wherever a verifier's policy is: on the gateway (python3 - POLICY ENDPOINT OTHER < endorsement_check.py over
ssh, as tools/regression.sh runs the other checks) or on the PC against its own policy. ENDPOINT and OTHER are two
entries of POLICY that have been enrolled with `fleet.py enroll-endorsed` (their records and keys are in the policy's
directory); the entries need not say "endorsement": "required" yet, the check asks for it itself.

It changes nothing: every variation is an entry built in memory, with files in a temporary directory; the policy, its
keys and its records are only read. It sends quote requests only (two to ENDPOINT, two to OTHER), so the aegis-fleet
service may keep running: at worst one of its exchanges meets a quote of this check and is retried in the same cycle.

  E1  ENDPOINT as enrolled                                        admitted, enrolment "endorsed"
  E2  its record missing (a key that was only ever pinned)        refused, endpoint not asked
  E3  its key file replaced by OTHER's key                        refused: substituted key, endpoint not asked
  E4  ... and OTHER's genuine record brought along                refused: the record endorses OTHER
  E5  ... and the entry pointed at OTHER, who holds that key      refused, as E3 and E4, OTHER not asked
  E6  ENDPOINT's entry, key and record, OTHER's address           refused: the device that answers does not hold the
                                                                  endorsed key
  E7  the record altered (one measurement digit; the device
      state; the expiry)                                          refused: the signature does not verify
  E8  the same claims signed by a key made here, which the
      policy does not list; and the policy trusting nobody        refused: not a trusted endorser
  E9  control, trust on first use: the E5 substitution with
      "endorsement" removed from the entry                        ADMITTED when both devices run the same firmware
                                                                  (same kind, profile and allowed list); that is
                                                                  what the endorsement is for. Otherwise reported
                                                                  as not applicable.
  E10 ENDPOINT as enrolled, once more                             admitted: nothing was changed

Exit 0 only if every line holds; the JSON printed has each verdict's reasons.
"""
import argparse
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
for p in ("../../common", "../../gateway/aegisd", "/root/aegis/common", "/root/aegis/gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, p)) if not p.startswith("/") else p)
import endorsement  # noqa: E402
import fleet  # noqa: E402
import mldsa  # noqa: E402
import psa_token  # noqa: E402
import wire  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("policy")
ap.add_argument("endpoint")
ap.add_argument("other")
ap.add_argument("--timeout", type=float, default=40)
a = ap.parse_args()
with open(a.policy) as f:
    policy = json.load(f)
base = os.path.dirname(os.path.abspath(a.policy))
tmp = tempfile.mkdtemp(prefix="aegis-endorsement-check-")


def absolute(ep):
    """An entry that means the same from any directory, and requires its endorsement."""
    e = dict(ep, endorsement="required", pq_pub_file=fleet._path(base, ep["pq_pub_file"]),
             endorsement_file=fleet.endorsement_file(ep, base))
    if e.get("iak_pub_pem"):
        e["iak_pub_pem"] = fleet._path(base, e["iak_pub_pem"])
    for k in ("provision", "transcript"):        # attestation only: this check never starts an exchange
        e.pop(k, None)
    return e


try:
    mine, theirs = (absolute(next(e for e in policy["endpoints"] if e["name"] == n)) for n in (a.endpoint, a.other))
except StopIteration:
    sys.exit("%s has no entry %s or %s" % (a.policy, a.endpoint, a.other))
trusted = [dict(e, pk_file=fleet._path(base, e["pk_file"])) for e in policy.get("endorsers", [])]
there = {"host": theirs["host"], "port": theirs["port"]}
res = {"endpoint": a.endpoint, "other": a.other, "trusted_endorsers": [e.get("name") for e in trusted]}
ok = True


def attest(entry, endorsers=trusted):
    return fleet.attest(entry, psa_token.verify_with_openssl_cli, base, a.timeout, endorsers)


def expect(tag, v, admitted, text=None, asked=None):
    """Record one verdict. asked: whether the endpoint may have been contacted (elapsed_s is set once a quote was
    requested)."""
    global ok
    good = v["admitted"] == admitted
    if text is not None:
        good = good and any(text in r for r in v["reasons"])
    if asked is not None:
        good = good and (("elapsed_s" in v) == asked)
    res[tag] = {"admitted": v["admitted"], "enrolment": v.get("enrolment"), "reasons": v["reasons"],
                "endpoint_asked": "elapsed_s" in v, "as_expected": good}
    ok = ok and good
    return v


def variant(name, edit):
    """A copy of ENDPOINT's record with edit(record) applied, in the temporary directory."""
    with open(mine["endorsement_file"]) as f:
        rec = json.load(f)
    edit(rec)
    path = os.path.join(tmp, name)
    with open(path, "w") as f:
        json.dump(rec, f)
    return path


try:
    v = expect("E1_as_enrolled", attest(mine), True, asked=True)
    if not v["admitted"]:
        res["stopped"] = ("%s is not admitted as enrolled: enrol it first (docs/enrolment.md), or see the reasons"
                          % a.endpoint)
        print(json.dumps(res, indent=1))
        sys.exit(2)
    res["E1_endorsement"] = v.get("endorsement")
    expect("E2_no_record", attest(dict(mine, endorsement_file=os.path.join(tmp, "none.json"))), False,
           "no endorsement record", asked=False)
    swapped = dict(mine, pq_pub_file=theirs["pq_pub_file"])
    expect("E3_substituted_key", attest(swapped), False, "substituted key", asked=False)
    with_record = dict(swapped, endorsement_file=theirs["endorsement_file"])
    expect("E4_substituted_key_and_its_record", attest(with_record), False,
           "the record endorses device %r, not %r" % (a.other, a.endpoint), asked=False)
    expect("E5_substituted_key_at_its_device", attest(dict(swapped, **there)), False, "substituted key", asked=False)
    expect("E5_substituted_key_and_record_at_its_device", attest(dict(with_record, **there)), False,
           "the record endorses device", asked=False)
    expect("E6_another_device_answers", attest(dict(mine, **there)), False,
           "the device that answered does not hold the endorsed key", asked=True)

    def other_digit(r):
        m = r["body"]["measurements"][0]
        m["measurement_value"] = ("0" if m["measurement_value"][0] != "0" else "1") + m["measurement_value"][1:]
    for tag, edit in (("E7_altered_measurement", other_digit),
                      ("E7_altered_device_state", lambda r: r["body"].update(device_state="closed")),
                      ("E7_altered_expiry", lambda r: r["body"].update(expires=r["body"]["issued"] + 10 ** 9))):
        expect(tag, attest(dict(mine, endorsement_file=variant(tag + ".json", edit))), False, "does not verify",
               asked=False)

    rogue_pk, rogue_sk = mldsa.keypair()

    def rogue(r):
        r["body"]["endorser_pk_sha256"] = endorsement.pk_sha256(rogue_pk)
        r["sig"] = mldsa.sign(rogue_sk, endorsement.LABEL, wire.canonical(r["body"])).hex()
    expect("E8_untrusted_endorser", attest(dict(mine, endorsement_file=variant("E8.json", rogue))), False,
           "not a trusted endorser", asked=False)
    expect("E8_no_trusted_endorsers", attest(mine, endorsers=[]), False, "no trusted endorsers", asked=False)

    same_firmware = all(mine.get(k) == theirs.get(k) for k in ("kind", "profile", "allowed", "iak_pub_pem"))
    tofu = {k: x for k, x in dict(swapped, **there).items() if k not in ("endorsement", "endorsement_file")}
    v = attest(tofu)
    res["E9_control_trust_on_first_use"] = {
        "admitted": v["admitted"], "enrolment": v.get("enrolment"), "reasons": v["reasons"],
        "same_firmware_on_both": same_firmware,
        "as_expected": v["admitted"] if same_firmware else "not applicable: the two entries differ in family or "
                                                           "reference, so the swap fails on those"}
    ok = ok and (v["admitted"] or not same_firmware)
    expect("E10_as_enrolled_again", attest(mine), True, asked=True)
finally:
    shutil.rmtree(tmp, ignore_errors=True)
res["ok"] = ok
print(json.dumps(res, indent=1))
sys.exit(0 if ok else 1)
