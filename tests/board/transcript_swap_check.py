#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""One transcript on a real endpoint (docs/architecture.md, audit finding 2): a session is finished only with the code
whose quote was appraised, in the boot that signed it (for images that follow the protocol: see the end of this
text).

Runs on the gateway, which holds the key that signs credentials, with the aegis-fleet service stopped (the service
would attest and provision in the middle of the check, and a quote of its own replaces the one under test). The
policy entry need not say "transcript": "v2" yet: the check asks for it itself. Test sessions live --lifetime seconds.

  systemctl stop aegis-fleet
  transcript_swap_check.py live  POLICY.json ENDPOINT
  transcript_swap_check.py quote POLICY.json ENDPOINT
  reset the endpoint, or flash another image that has the same key and reset
                                         (STM32, from the bench PC: STM32_Programmer_CLI -c port=SWD sn=<serial>
                                          mode=HOTPLUG -hardRst)
  transcript_swap_check.py swap  POLICY.json ENDPOINT
  systemctl start aegis-fleet            (it provisions the endpoint again in its first cycle)

live    nothing but the gateway and the running image:
  L1. a quote, then the exchange that continues it: accepted, the heartbeat under its session verifies, the endpoint
      reports the same session. If the image does not know the transcript, the gateway refuses here (that is what
      "transcript": "v2" does to an image from before it) and the check stops with exit 3.
  L2. the same quote once more: the endpoint answers the unbound exchange (a quote continues one exchange), the
      gateway refuses, the session of L1 stays
  L3. two quotes: the older one cannot be continued, the newer one can
  L4. a credential signed by the gateway that does not name the transcript, and one that names another: the endpoint
      refuses both (STM32: "ERR pq -149"; elsewhere "ERR cred other-transcript") and keeps its session
  L5. an entry without "transcript" still gets the first version's exchange from this image (endpoints and gateway
      need not be upgraded in one step)
  L6. a last full cycle, so the endpoint is left with a session made the bound way

quote   a quote is appraised and written to a file (--file): its challenge, the hash of the signed token, the
        measurements. Nothing continues it. A session is made first, only so that swap can see the reset.

live and quote need an endpoint the policy admits (as the fleet loop does before it provisions); otherwise exit 2.

swap    after the reset:
  S0. the endpoint was reset: PQSESSION answers that there has been no session. Otherwise the check stops (exit 2).
  S1. the gateway continues the recorded quote, as it would have in the cycle the quote belongs to. The endpoint has
      no quote in its RAM after the reset, so it cannot sign that transcript: the gateway refuses before it sends a
      credential, and the endpoint has no session.
  S2. the recorded challenge is sent again, so that this boot signs a quote for it, and the gateway tries once more to
      continue the RECORDED quote. If this boot's quote is another one than the recorded (another image: other
      measurements; or the STM32, whose token carries TF-M's randomized ES256 signature, so that even the same images
      never give the same token twice), the transcript is another one and the gateway must refuse. If it is the
      recorded quote byte for byte (the same image on an endpoint whose quote is its claims alone: RW612, ZynqMP,
      Linux), the transcript is the recorded one and continuing it is correct: what answers reports what was
      appraised. The check prints which case it saw and holds the endpoint to it.
  S3. a new cycle (a new quote, its exchange) with whatever runs now: a session if the policy admits it and it
      knows the transcript, none otherwise.

What this shows, and what it does not. Two firmware images that hold one device key cannot answer within one gateway
cycle on a bench without a reset in between, so the cycle is cut where the swap would happen: the quote is taken in
one boot and the exchange asked of the next. With only a reset in between (the same image), S1 shows the mechanism
on the real secure partition: the quote lives in its RAM and does not outlive the boot that signed it. With another
image flashed in between (the previous secure image, which has the same DHUK-derived key and no transcript; or
another non-secure image under the same secure one, which changes NSPE), S1 and S2 are the swap itself: the gateway
appraised image A and image B is refused the session. It does not show anything about an image that holds the key
and signs a transcript for a quote it did not make: no such image exists on the bench, and the transcript does not
stop one (docs/architecture.md says what would).
"""
import argparse
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for p in ("../../common", "../../gateway/aegisd", "/root/aegis/common", "/root/aegis/gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, p)) if not p.startswith("/") else p)
import fleet  # noqa: E402
import mldsa  # noqa: E402
import mlkem  # noqa: E402
import psa_token  # noqa: E402
import transcript  # noqa: E402
import wire  # noqa: E402

NO_SESSION = ("ERR pq -137", "ERR pq no-session")   # no session since the reset (PSA_ERROR_BAD_STATE on the STM32)

ap = argparse.ArgumentParser()
ap.add_argument("phase", choices=("live", "quote", "swap"))
ap.add_argument("policy")
ap.add_argument("endpoint")
ap.add_argument("--file", help="the recorded quote (default /tmp/aegis-transcript-swap-<endpoint>.json)")
ap.add_argument("--lifetime", type=int, default=120, help="seconds the test credentials are valid")
ap.add_argument("--wait", type=int, default=60, help="seconds to wait for the endpoint to answer after its reset")
ap.add_argument("--state", default=fleet.GATEWAY_STATE)
a = ap.parse_args()
with open(a.policy) as f:
    policy = json.load(f)
entry = next(e for e in policy["endpoints"] if e["name"] == a.endpoint)
# an entry with "endorsement": "required" is checked against the policy's trusted endorsers (docs/enrolment.md); a
# policy without them is passed on as before, so the check also runs against a fleet.py from before endorsements
TRUST = {"endorsers": policy["endorsers"]} if policy.get("endorsers") else {}
base = os.path.dirname(os.path.abspath(a.policy))
path = a.file or "/tmp/aegis-transcript-swap-%s.json" % a.endpoint
sk, gid = fleet.load_gateway_identity(a.state)
bound = dict(entry, transcript="v2")
unbound = {k: v for k, v in entry.items() if k != "transcript"}
with open(fleet._path(base, entry["pq_pub_file"])) as f:
    pk = bytes.fromhex(f.read().strip())


def ask(line):
    return fleet._exchange(entry["host"], int(entry["port"]), line, 40).strip()


def first_answer():
    """PQSESSION, once the endpoint answers: after a reset its network takes a few seconds."""
    end = time.monotonic() + a.wait
    while True:
        try:
            return ask("PQSESSION")
        except OSError:
            if time.monotonic() >= end:
                raise
            time.sleep(2)


def attest(challenge=None, admitted=True):
    """The gateway's own attestation; with challenge, for that challenge instead of a random one (S2). As in the
    fleet loop, only an admitted endpoint gets a session: unless admitted is False, a quote the policy does not admit
    ends the check (exit 2), as does an endpoint that does not answer or whose quote is not signed by its key."""
    real = fleet.secrets.token_bytes
    if challenge is not None:
        fleet.secrets.token_bytes = lambda n: challenge
    try:
        v = fleet.attest(bound, psa_token.verify_with_openssl_cli, base, timeout=40, **TRUST)
    finally:
        fleet.secrets.token_bytes = real
    if "quote" not in v or (admitted and not v["admitted"]):
        print(json.dumps({"endpoint": a.endpoint, "phase": a.phase, "not_admitted": v["reasons"]}, indent=1))
        sys.exit(2)
    return v


def provision(quote, ep=None, lines=None):
    """The gateway's own exchange with a short lifetime; the request lines it sent are added to lines."""
    real, life = fleet._exchange, fleet.CRED_LIFETIME_S

    def tap(host, port, line, timeout):
        lines.append(line.split()[0])
        return real(host, port, line, timeout)
    if lines is not None:
        fleet._exchange = tap
    fleet.CRED_LIFETIME_S = a.lifetime
    try:
        return fleet.provision(ep or bound, base, sk, gid, {}, timeout=40, quote=quote, **TRUST)
    finally:
        fleet._exchange, fleet.CRED_LIFETIME_S = real, life


def refused(quote, lines=None):
    """"refused: <why>" if the gateway refused to continue the quote, None if it did not refuse."""
    try:
        provision(quote, lines=lines)
        return None
    except fleet.TranscriptRefused as e:
        return "refused: %s" % e


def other_credential(name):
    """A quote and the exchange that continues it by hand, with a credential the gateway's code never makes: it names
    the ciphertext, the key and the endpoint, but no transcript (name None) or another one. The endpoint's reply."""
    v = attest()
    ch, th = bytes.fromhex(v["quote"]["challenge"]), bytes.fromhex(v["quote"]["token_sha3_256"])
    p = ask("PQKEMINIT " + ch.hex()).split()
    ek, sig = bytes.fromhex(p[2]), bytes.fromhex(p[4])
    t2 = transcript.kem_init(transcript.quote(ch, th), ek)
    if not mldsa.verify(pk, transcript.KEM_INIT_LABEL, t2, sig):
        return "not reached: the KEM key is not signed over the transcript"
    ct, _ = mlkem.encaps(ek)
    now = int(time.time())
    body = {"v": 1, "type": "credential", "endpoint": entry["name"],
            "endpoint_pq_pk_sha256": __import__("hashlib").sha256(pk).hexdigest(), "kem": "ML-KEM-768",
            "kem_ct_sha3_256": fleet._sha3(ct).hex(), "kem_ek_sha3_256": fleet._sha3(ek).hex(),
            "issued": now, "expires": now + a.lifetime, "gateway_identity_sha256": gid}
    if name:
        body.update({"transcript": "v2", "transcript_sha3_256": name(t2).hex()})
    cred = wire.canonical(body) + b"\n" + mldsa.sign(sk, fleet.CRED_LABEL, wire.canonical(body))
    return ask("PQKEMFIN %s %s" % (ct.hex(), cred.hex()))[:40]


def finish(res, code):
    print(json.dumps(res, indent=1))
    sys.exit(code)


res = {"endpoint": a.endpoint, "phase": a.phase}

if a.phase == "live":
    v = attest()
    try:
        r = provision(v["quote"])
    except fleet.TranscriptRefused as e:
        res["L1_bound_exchange"] = "REFUSED by the gateway: %s" % e
        res["image_knows_the_transcript"] = False
        finish(res, 3)
    status, _ = fleet.heartbeat(bound, r["session_key"])
    res["image_knows_the_transcript"] = True
    res["L1_bound_exchange"] = "accepted, session %s, bound to quote %s" % (r["session_id"][:16],
                                                                            v["quote"]["token_sha3_256"][:16])
    res["L1_heartbeat"] = status.decode(errors="replace")
    res["L1_endpoint_reports_the_same_session"] = fleet.query_session(bound) == (r["session_id"], r["credential_sha3_256"])
    ok = res["L1_endpoint_reports_the_same_session"]

    res["L2_same_quote_again"] = refused(v["quote"]) or "ACCEPTED (bad)"
    res["L2_session_kept"] = fleet.query_session(bound)[0] == r["session_id"]
    ok = ok and res["L2_same_quote_again"] != "ACCEPTED (bad)" and res["L2_session_kept"]

    older, newer = attest(), attest()
    res["L3_older_quote"] = refused(older["quote"]) or "ACCEPTED (bad)"
    try:
        r = provision(newer["quote"])
        res["L3_newer_quote"] = "accepted, session %s" % r["session_id"][:16]
    except ValueError as e:
        res["L3_newer_quote"] = "FAILED: %s" % e
    ok = ok and res["L3_older_quote"] != "ACCEPTED (bad)" and res["L3_newer_quote"].startswith("accepted")

    res["L4_credential_without_the_transcript"] = other_credential(None)
    res["L4_credential_for_another_transcript"] = other_credential(lambda t2: t2[::-1])
    res["L4_session_kept"] = fleet.query_session(bound)[0] == r["session_id"]
    ok = ok and res["L4_credential_without_the_transcript"].startswith("ERR") and \
        res["L4_credential_for_another_transcript"].startswith("ERR") and res["L4_session_kept"]

    try:
        u = provision(None, ep=unbound)
        fleet.heartbeat(unbound, u["session_key"])
        res["L5_entry_without_transcript"] = "first version's exchange accepted, session %s" % u["session_id"][:16]
    except ValueError as e:
        res["L5_entry_without_transcript"] = "FAILED: %s" % e
    ok = ok and res["L5_entry_without_transcript"].startswith("first")

    try:
        v = attest()
        r = provision(v["quote"])
        status, _ = fleet.heartbeat(bound, r["session_key"])
        res["L6_last_cycle"] = "accepted, session %s; %s" % (r["session_id"][:16], status.decode(errors="replace"))
    except ValueError as e:
        res["L6_last_cycle"] = "FAILED: %s" % e
    ok = ok and res["L6_last_cycle"].startswith("accepted")
    finish(res, 0 if ok else 1)

if a.phase == "quote":
    v = attest()
    try:
        r = provision(v["quote"])
        res["session_for_the_reset_check"] = "bound, %s" % r["session_id"][:16]
    except fleet.TranscriptRefused:
        r = provision(None, ep=unbound)       # an image from before the transcript: its quote is recorded all the same
        res["session_for_the_reset_check"] = "unbound (this image does not know the transcript), %s" % r["session_id"][:16]
    v = attest()                              # the recorded quote: appraised, never continued
    rec = {"endpoint": a.endpoint, "recorded_at": int(time.time()), "challenge": v["quote"]["challenge"],
           "token_sha3_256": v["quote"]["token_sha3_256"], "measurements": v.get("measurements")}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(rec, f)
    res.update({"quote": "admitted by the policy, token %s" % rec["token_sha3_256"][:16],
                "measurements": rec["measurements"], "file": path,
                "next": "reset the endpoint (or flash another image with the same key and reset), then: swap"})
    finish(res, 0)

with open(path) as f:
    rec = json.load(f)
if rec["endpoint"] != a.endpoint:
    sys.exit("%s is the quote of %s" % (path, rec["endpoint"]))
quote = {"challenge": rec["challenge"], "token_sha3_256": rec["token_sha3_256"]}
res.update({"recorded_s_ago": int(time.time()) - rec["recorded_at"], "recorded_measurements": rec["measurements"],
            "S0_session_after_reset": first_answer()[:40]})
if res["S0_session_after_reset"] not in NO_SESSION:
    res["S0_reset"] = "the endpoint has not been reset since the quote was recorded: reset it and run swap again"
    finish(res, 2)

lines = []
res["S1_recorded_quote_continued"] = refused(quote, lines) or "ACCEPTED (bad)"
res["S1_credential_sent"] = "PQKEMFIN" in lines
res["S1_session"] = ask("PQSESSION")[:40]
ok = res["S1_recorded_quote_continued"] != "ACCEPTED (bad)" and not res["S1_credential_sent"] and \
    res["S1_session"] in NO_SESSION

now = attest(bytes.fromhex(rec["challenge"]), admitted=False)
same = now["quote"]["token_sha3_256"] == rec["token_sha3_256"]
res["S2_measurements_now"] = now.get("measurements")
res["S2_admitted_now"] = now["admitted"] or now["reasons"]
res["S2_quote_for_the_recorded_challenge"] = (
    "the recorded quote, byte for byte: this boot reports what was appraised" if same else
    "another quote (%s...): this boot does not report what was appraised" % now["quote"]["token_sha3_256"][:16])
why = refused(quote)
res["S2_recorded_quote_continued"] = why or ("accepted: this boot signed the recorded quote again and continued it"
                                             if same else "ACCEPTED (bad)")
ok = ok and (same or why is not None)

try:
    v = attest(admitted=False)
    if not v["admitted"]:
        raise fleet.TranscriptRefused("not admitted by the policy, so no exchange: %s" % "; ".join(v["reasons"]))
    r = provision(v["quote"])
    status, _ = fleet.heartbeat(bound, r["session_key"])
    res["S3_new_cycle"] = "accepted, session %s; %s" % (r["session_id"][:16], status.decode(errors="replace"))
except fleet.TranscriptRefused as e:
    res["S3_new_cycle"] = "refused: %s" % e   # the image now running does not know the transcript: no session for it
except ValueError as e:
    res["S3_new_cycle"] = "FAILED: %s" % e
    ok = False
finish(res, 0 if ok else 1)
