#!/usr/bin/env python3
"""Mutual-authentication checks against the real STM32 secure partition (via its TCP line port).

  A. credential signed by a key that is not the pinned gateway key      -> refused (no session)
  B. credential signed by the real gateway key but naming another
     ciphertext hash (replayed / not bound to this exchange)           -> refused
  C. after A and B, the session the gateway established earlier is still the endpoint's session
     (a failed or hostile exchange must not tear it down)
B needs the gateway's private key, so B runs on the gateway itself (this script is copied there).

  mutual_auth_checks.py pc       HOST:PORT     runs A and C from the PC
  mutual_auth_checks.py gateway  HOST:PORT     runs B on the gateway
"""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
for p in ("../../common", "../../gateway/aegisd", "/root/aegis/common", "/root/aegis/gateway/aegisd"):
    sys.path.insert(0, os.path.abspath(os.path.join(HERE, p)) if not p.startswith("/") else p)
import fleet  # noqa: E402
import mldsa  # noqa: E402

where, hp = sys.argv[1], sys.argv[2]
host, port = hp.split(":")
ep = {"name": "stm32h573-dk", "host": host, "port": int(port),
      "pq_pub_file": "/root/aegis/gateway/policy/keys/stm32h573-dk.mldsa65.pub" if where == "gateway"
      else os.path.join(HERE, "..", "..", "build", "stm32-pq.pub")}
before = fleet.query_session(ep)
res = {"session_before": before[0][:16]}
if where == "pc":
    _, wrong_sk = mldsa.keypair()
    try:
        fleet.provision(ep, "/", wrong_sk, "not-the-gateway", {}, timeout=40)
        res["A_foreign_key"] = "ACCEPTED (bad)"
    except ValueError as e:
        res["A_foreign_key"] = "refused: %s" % e
else:
    sk, gid = fleet.load_gateway_identity()
    real = fleet._sha3

    def other_ct_hash(*parts):
        if len(parts) == 1 and len(parts[0]) == 1088:
            return real(b"another exchange", parts[0])
        return real(*parts)
    fleet._sha3 = other_ct_hash
    try:
        fleet.provision(ep, "/", sk, gid, {}, timeout=40)
        res["B_unbound_credential"] = "ACCEPTED (bad)"
    except ValueError as e:
        res["B_unbound_credential"] = "refused: %s" % e
    finally:
        fleet._sha3 = real
after = fleet.query_session(ep)
res["C_session_survives"] = after == before
print(json.dumps(res, indent=1))
ok = res["C_session_survives"] and all(str(v).startswith("refused") for k, v in res.items() if k[0] in "AB")
sys.exit(0 if ok else 1)
