#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Phase 1 checks against the real gateway (needs aegisd serving on BOARD:7443
and an enrolment in host/enrolled/).

  1. fresh quote accepted
  2. old answer replayed against a new nonce: refused
  3. one measurement byte changed in transit: refused (signature)
  4. aegisd code changed on the gateway's disk: refused (measurement changed)
     -> the file is restored afterwards and a fresh quote must pass again
  5. a second identity (other key) on port 7444: refused
Each board change is undone at the end of its check.
"""
import copy
import json
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "host"))
import aegis_verify as av  # noqa: E402

BOARD = os.environ.get("BOARD") or os.environ.get("GATEWAY") or sys.exit("set BOARD or GATEWAY (see bench.env.example)")
SSH = ["ssh", "-o", "BatchMode=yes", "root@" + BOARD]
results = []


def rec(name, expect_ok, ok, reasons):
    passed = (ok == expect_ok)
    results.append({"check": name, "accepted": ok, "expected_accepted": expect_ok,
                    "reasons": reasons, "pass": passed})
    print(("PASS " if passed else "FAIL ") + name, reasons)


def ssh(cmd):
    return subprocess.run(SSH + [cmd], check=True, capture_output=True, text=True).stdout


enrolled = av.load_enrolled()

resp, nonce, el = av.fresh_quote(BOARD, 7443)
rec("fresh quote", True, *av.check_quote(enrolled, resp, nonce, el))

old = resp
_, new_nonce, el2 = av.fresh_quote(BOARD, 7443)
rec("replayed answer", False, *av.check_quote(enrolled, old, new_nonce, el2))

bad = copy.deepcopy(resp)
m = bad["body"]["measurements"]
m["design_info"] = ("00" if m["design_info"][:2] != "00" else "01") + m["design_info"][2:]
rec("measurement altered in transit", False, *av.check_quote(enrolled, bad, nonce, el))

f = "/root/aegis/gateway/aegisd/aegisd.py"
ssh("cp %s %s.orig && echo '# tampered' >> %s" % (f, f, f))
try:
    r, n, e = av.fresh_quote(BOARD, 7443)
    rec("gateway code changed on disk", False, *av.check_quote(enrolled, r, n, e))
finally:
    ssh("mv %s.orig %s" % (f, f))
r, n, e = av.fresh_quote(BOARD, 7443)
rec("after restoring the code", True, *av.check_quote(enrolled, r, n, e))

ssh("cd /root/aegis/gateway/aegisd && python3 aegisd.py init --state /tmp/aegis-other > /dev/null && "
    "(nohup python3 aegisd.py serve --state /tmp/aegis-other --port 7444 > /tmp/aegis-other.log 2>&1 &) ; sleep 2")
try:
    r, n, e = av.fresh_quote(BOARD, 7444)
    rec("other key on the same board", False, *av.check_quote(enrolled, r, n, e))
finally:
    ssh("pkill -f '[s]tate /tmp/aegis-other' ; rm -rf /tmp/aegis-other /tmp/aegis-other.log; true")

print(json.dumps({"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "board": "gateway",
                  "passed": sum(r["pass"] for r in results), "total": len(results)}, indent=1))
sys.exit(0 if all(r["pass"] for r in results) else 1)
