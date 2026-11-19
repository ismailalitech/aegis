#!/usr/bin/env python3
"""The session's end on a real endpoint (docs/endpoint-expiry.md), without waiting an hour.

Runs on the gateway, which holds the key that signs credentials, with the aegis-fleet service stopped: the service
would provision again in the middle of the check.

  systemctl stop aegis-fleet
  expiry_check.py POLICY.json ENDPOINT [--lifetime 32] [--state /var/lib/aegis]
  systemctl start aegis-fleet          (it provisions the endpoint again in its first cycle)

  A. a credential with a short lifetime is accepted, and a heartbeat under it verifies
  B. half-way, a heartbeat still verifies, and its "ttl" has fallen by the time that passed on the gateway's clock
     (the endpoint's clock runs, at the right rate: the check allows 10 %)
  C. after the lifetime plus a sixteenth, PQHB and PQSESSION are refused: "ERR pq expired" (the STM32's non-secure
     prover prints the partition's code, "ERR pq -140")
  D. attestation still answers
"""
import argparse
import json
import os
import re
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
for p in ("../../common", "../../gateway/aegisd", "/root/aegis/common", "/root/aegis/gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, p)) if not p.startswith("/") else p)
import fleet  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("policy")
ap.add_argument("endpoint")
ap.add_argument("--lifetime", type=int, default=32, help="seconds; the endpoint adds a sixteenth")
ap.add_argument("--state", default=fleet.GATEWAY_STATE)
a = ap.parse_args()
with open(a.policy) as f:
    ep = next(e for e in json.load(f)["endpoints"] if e["name"] == a.endpoint)
base = os.path.dirname(os.path.abspath(a.policy))
sk, gid = fleet.load_gateway_identity(a.state)
limit = a.lifetime + a.lifetime // 16


def ask(line):
    return fleet._exchange(ep["host"], int(ep["port"]), line, 10).strip()


def ttl(status):
    m = re.search(rb";ttl=(\d+)$", status)
    return int(m.group(1)) if m else None


res = {"endpoint": a.endpoint, "lifetime_s": a.lifetime, "ends_after_s": limit}
fleet.CRED_LIFETIME_S = a.lifetime
r = fleet.provision(ep, base, sk, gid, {}, timeout=40)
t0 = time.monotonic()
s1, _ = fleet.heartbeat(ep, r["session_key"])
t1 = time.monotonic()
res["A_heartbeat"] = s1.decode(errors="replace")
time.sleep(max(0.0, limit / 2 - (time.monotonic() - t0)))
s2, _ = fleet.heartbeat(ep, r["session_key"])
t2 = time.monotonic()
res["B_heartbeat"] = s2.decode(errors="replace")
if ttl(s1) is not None and ttl(s2) is not None:
    res["B_endpoint_seconds_per_gateway_second"] = round((ttl(s1) - ttl(s2)) / (t2 - t1), 3)
    # the ttl is in whole seconds: one second of rounding at each end
    res["B_clock_runs"] = abs((ttl(s1) - ttl(s2)) - (t2 - t1)) <= 0.1 * (t2 - t1) + 2
else:
    res["B_clock_runs"] = "no ttl in the status (an image without the session's end?)"
time.sleep(max(0.0, limit * 1.1 + 2 - (time.monotonic() - t0)))    # past the end, also for a clock 10 % slow
res["C_heartbeat_after_end"] = ask("PQHB " + "00" * 32)
res["C_session_after_end"] = ask("PQSESSION")
res["C_waited_s"] = round(time.monotonic() - t0, 1)
res["D_attestation"] = ask("PQCHAL " + "00" * 32).split(" ")[0]
print(json.dumps(res, indent=1))
ended = ("ERR pq expired", "ERR pq -140")
ok = (res["B_clock_runs"] is True and res["C_heartbeat_after_end"] in ended and res["C_session_after_end"] in ended
      and res["D_attestation"] == "PQTOKEN")
sys.exit(0 if ok else 1)
