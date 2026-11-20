#!/usr/bin/env python3
"""Reset and replay on a real endpoint: an exchange recorded on the network, sent again after a reset of the
endpoint, must not give the endpoint its old session back.

Without fresh randomness in the ML-KEM key, the endpoint makes the same key again for the same nonce at the same
count of exchanges since its reset; the recorded PQKEMFIN (the gateway's ciphertext and credential for that key) is
then accepted and the old session lives again, for a whole new lifetime. The STM32H573 partition did that up to the
image "...-expiry" (SPE 02549860...); from "...-freshkem" on it must not.

Runs on the gateway, which holds the key that signs credentials, with the aegis-fleet service stopped: the service
would provision in the middle of the check. The reset in between is the operator's (the gateway cannot reset a
board); each phase checks that it happened.

  systemctl stop aegis-fleet
  reset the endpoint                     (so that the recorded exchange is the first since a reset)
  reset_replay_check.py record POLICY.json ENDPOINT
  reset the endpoint                     (STM32, from the bench PC: STM32_Programmer_CLI -c port=SWD sn=<serial>
                                          mode=HOTPLUG -hardRst)
  reset_replay_check.py replay POLICY.json ENDPOINT
  systemctl start aegis-fleet            (it provisions the endpoint again in its first cycle)

record
  R. a whole exchange as the gateway makes it, and a heartbeat under its session. The two request lines, the key the
     endpoint answered with and the session's id go to a file (--file); the session key does not.
replay
  A. the endpoint was reset: PQSESSION answers that there has been no session ("ERR pq -137" from the STM32's
     non-secure prover, "ERR pq no-session" elsewhere). Otherwise the check stops (exit 2).
  B. the recorded PQKEMINIT, sent as the first, second, ... exchange since the reset (--tries): every answer is a key
     signed by the endpoint for the recorded nonce, none is the recorded key, no two are the same
  C. after each of them the recorded PQKEMFIN: refused every time (STM32: "ERR pq -149", the credential names
     another key)
  D. still no session: PQSESSION and PQHB refused
  E. a new exchange works and its heartbeat verifies; the recorded PQKEMFIN, sent once more, is refused and the new
     session stays

If the recording was not the first exchange since a reset (R says so), an image without the fix only repeats the key
at the same count: give replay at least that many --tries. An image with the fix passes whatever the count.
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

NO_SESSION = ("ERR pq -137", "ERR pq no-session")   # no session since the reset (PSA_ERROR_BAD_STATE on the STM32)

ap = argparse.ArgumentParser()
ap.add_argument("phase", choices=("record", "replay"))
ap.add_argument("policy")
ap.add_argument("endpoint")
ap.add_argument("--file", help="the recording (default /tmp/aegis-reset-replay-<endpoint>.json)")
ap.add_argument("--tries", type=int, default=4, help="replay: exchanges since the reset to try the recording at")
ap.add_argument("--lifetime", type=int, default=60, help="record: seconds the recorded credential is valid")
ap.add_argument("--wait", type=int, default=60, help="seconds to wait for the endpoint to answer after its reset")
ap.add_argument("--state", default=fleet.GATEWAY_STATE)
a = ap.parse_args()
with open(a.policy) as f:
    ep = next(e for e in json.load(f)["endpoints"] if e["name"] == a.endpoint)
base = os.path.dirname(os.path.abspath(a.policy))
path = a.file or "/tmp/aegis-reset-replay-%s.json" % a.endpoint
sk, gid = fleet.load_gateway_identity(a.state)


def ask(line):
    return fleet._exchange(ep["host"], int(ep["port"]), line, 40).strip()


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


def exchange(lifetime, lines=None):
    """A whole exchange as the gateway makes it; with lines, the request lines and their answers are added to it."""
    real, life = fleet._exchange, fleet.CRED_LIFETIME_S

    def tap(host, port, line, timeout):
        reply = real(host, port, line, timeout)
        lines.append((line, reply.strip()))
        return reply
    if lines is not None:
        fleet._exchange = tap
    fleet.CRED_LIFETIME_S = lifetime
    try:
        # with "transcript": "v2" in the entry the exchange continues a quote taken now, and the recorded PQKEMINIT
        # carries that quote's challenge. After the reset the endpoint has no such quote, so it answers the recorded
        # line with the first version's signature over the same nonce: what B checks stays as it is.
        return fleet.provision(ep, base, sk, gid, {}, timeout=40, quote=fleet.quote_to_continue(ep, base, timeout=40))
    finally:
        fleet._exchange, fleet.CRED_LIFETIME_S = real, life


def finish(res, ok):
    print(json.dumps(res, indent=1))
    sys.exit(0 if ok else 1)


if a.phase == "record":
    before = first_answer()
    lines = []
    r = exchange(a.lifetime, lines)
    status, _ = fleet.heartbeat(ep, r["session_key"])
    (init, init_reply), (fin, _) = lines
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump({"endpoint": a.endpoint, "recorded_at": int(time.time()), "kem_init": init, "kem_fin": fin,
                   "ek": init_reply.split()[2], "session_id": r["session_id"]}, f)
    finish({"endpoint": a.endpoint, "R_session": r["session_id"][:16], "R_heartbeat": status.decode(errors="replace"),
            "R_first_exchange_since_reset": before in NO_SESSION, "R_session_before": before[:40], "file": path,
            "next": "reset the endpoint, then: replay"}, True)

with open(path) as f:
    rec = json.load(f)
if rec["endpoint"] != a.endpoint:
    sys.exit("%s is the recording of %s" % (path, rec["endpoint"]))
with open(fleet._path(base, ep["pq_pub_file"])) as f:
    pk = bytes.fromhex(f.read().strip())
nonce = bytes.fromhex(rec["kem_init"].split()[1])
res = {"endpoint": a.endpoint, "recorded_s_ago": int(time.time()) - rec["recorded_at"],
       "A_session_after_reset": first_answer()[:40]}
if res["A_session_after_reset"] not in NO_SESSION:
    res["A_reset"] = "the endpoint has not been reset since its last session: reset it and run replay again"
    print(json.dumps(res, indent=1))
    sys.exit(2)

keys, signed, refusals = [], [], []
for _ in range(a.tries):
    p = ask(rec["kem_init"]).split()
    if len(p) == 6 and p[0] == "PQKEMEK" and p[5] == "END":
        keys.append(p[2])
        signed.append(mldsa.verify(pk, fleet.KEM_INIT_LABEL, nonce + bytes.fromhex(p[2]), bytes.fromhex(p[4])))
    else:
        keys.append("no key: " + " ".join(p)[:40])
        signed.append(False)
    refusals.append(ask(rec["kem_fin"])[:40])
res["B_keys_signed_by_the_endpoint"] = all(signed)
res["B_recorded_key_issued_again"] = rec["ek"] in keys
res["B_keys_all_different"] = len(set(keys)) == len(keys)
res["C_recorded_finish"] = refusals
res["C_refused_every_time"] = all(x.startswith("ERR") for x in refusals)
res["D_session"] = ask("PQSESSION")[:40]
res["D_heartbeat"] = ask("PQHB " + "00" * 32)[:40]
ok = (res["B_keys_signed_by_the_endpoint"] and not res["B_recorded_key_issued_again"] and res["B_keys_all_different"]
      and res["C_refused_every_time"] and res["D_session"] in NO_SESSION and res["D_heartbeat"] in NO_SESSION)

try:
    r = exchange(a.lifetime)
    status, _ = fleet.heartbeat(ep, r["session_key"])
    res["E_new_session"] = r["session_id"][:16]
    res["E_heartbeat"] = status.decode(errors="replace")
    res["E_recorded_finish_again"] = ask(rec["kem_fin"])[:40]
    res["E_new_session_kept"] = fleet.query_session(ep)[0] == r["session_id"] != rec["session_id"]
    fleet.heartbeat(ep, r["session_key"])
    ok = ok and res["E_recorded_finish_again"].startswith("ERR") and res["E_new_session_kept"]
except ValueError as e:
    res["E_new_exchange"] = "FAILED: %s" % e
    ok = False
finish(res, ok)
