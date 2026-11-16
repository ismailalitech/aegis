#!/usr/bin/env python3
"""Run the command list made by acvp_commands.py with a given directory of liboqs test binaries.
Standard library only (runs on the PolarFire). Prints a JSON summary; exit 0 only if every case
returned its expected code.
  run_acvp_commands.py COMMANDS.jsonl BIN_DIR
"""
import collections
import json
import os
import subprocess
import sys
import time

cmds, bindir = sys.argv[1], sys.argv[2]
res = collections.Counter()
fails = []
t0 = time.time()
with open(cmds) as f:
    for n, line in enumerate(f):
        r = json.loads(line)
        p = subprocess.run([os.path.join(bindir, r["bin"])] + r["args"], capture_output=True)
        ok = r["expect"] is None or p.returncode == r["expect"]
        res[(r["test"], "pass" if ok else "FAIL")] += 1
        if not ok and len(fails) < 5:
            fails.append({"case": n, "test": r["test"], "rc": p.returncode, "stderr": p.stderr[-200:].decode(errors="replace")})
summary = {"cases": sum(res.values()), "failed": sum(v for (t, s), v in res.items() if s == "FAIL"),
           "by_test": {"%s %s" % k: v for k, v in sorted(res.items())}, "first_failures": fails,
           "elapsed_s": round(time.time() - t0, 1), "keccak_mode": os.environ.get("AEGIS_PQC_KECCAK", "software")}
print(json.dumps(summary, indent=1))
sys.exit(1 if summary["failed"] else 0)
