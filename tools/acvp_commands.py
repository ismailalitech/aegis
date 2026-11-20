#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Turn the NIST ACVP vectors into the exact command lines liboqs' own ACVP test runs.

liboqs (tests/test_acvp_vectors.py) checks each ACVP test case by running its
`vectors_kem` / `vectors_sig` binaries with the case's values as arguments. This script
imports that test file unchanged, replaces only (a) the download with the local, checksummed
copies in vectors/acvp and (b) the process launch with a recorder, and writes one JSON line per
test case: {"bin": "vectors_kem", "args": [...], "expect": 0}. The list can then be run
anywhere, for example on the PolarFire with the fabric doing every Keccak permutation.

  acvp_commands.py OUT.jsonl [ML-KEM-768] [ML-DSA-65]
"""
import json
import os
import sys
import types

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LIBOQS_TESTS = os.path.expanduser("~/aegis-tools/liboqs-src/tests")
VEC = os.path.join(REPO, "vectors", "acvp")
os.environ.setdefault("OQS_BUILD_DIR", os.path.expanduser("~/aegis-tools/liboqs-src/build"))
sys.path.insert(0, LIBOQS_TESTS)
os.chdir(os.path.dirname(LIBOQS_TESTS))  # liboqs helpers read src/ relative to the liboqs root

import helpers  # noqa: E402

recorded = []


def fake_run(command, working_dir=".", env=None, expected_returncode=0, input=None, ignore_returncode=False):
    recorded.append({"bin": os.path.basename(command[0]), "args": command[1:],
                     "expect": None if ignore_returncode else expected_returncode})
    return ""


def fake_get(url):
    # .../json-files/<DIR>/internalProjection.json -> vectors/acvp/<DIR>-internalProjection.json
    parts = url.rstrip("/").split("/")
    path = os.path.join(VEC, "%s-%s" % (parts[-2], parts[-1]))
    with open(path, "rb") as f:
        data = f.read()
    return types.SimpleNamespace(status_code=200, content=data)


helpers.run_subprocess = fake_run
helpers.cached_requests_get = fake_get
import test_acvp_vectors as t  # noqa: E402
t.cached_requests_get = fake_get
t.helpers.run_subprocess = fake_run


def main():
    out = sys.argv[1]
    algs = sys.argv[2:] or ["ML-KEM-768", "ML-DSA-65"]
    tests = []
    for a in algs:
        if a.startswith("ML-KEM"):
            tests += [(t.test_acvp_vec_kem_keygen, a), (t.test_acvp_vec_kem_encdec_aft, a),
                      (t.test_acvp_vec_kem_encdec_val, a)]
        else:
            tests += [(t.test_acvp_vec_ml_dsa_sig_keygen, a), (t.test_acvp_vec_ml_dsa_sig_gen, a),
                      (t.test_acvp_vec_ml_dsa_sig_ver, a)]
    counts = {}
    for fn, a in tests:
        before = len(recorded)
        fn.__wrapped__(a) if hasattr(fn, "__wrapped__") else fn(a)
        for r in recorded[before:]:
            r["test"] = fn.__name__
        counts["%s %s" % (fn.__name__, a)] = len(recorded) - before
    with open(out, "w") as f:
        for r in recorded:
            f.write(json.dumps(r) + "\n")
    print(json.dumps(counts, indent=1))


if __name__ == "__main__":
    main()
