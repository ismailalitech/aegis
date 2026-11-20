#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Holds the Prover SDK's core to the implementations it replaced, byte for byte.

Before the SDK (commit eb82532) the protocol existed twice: in the STM32H573 partition and in the RW612 prover's
aegis_proto.c. Both had a fuzz harness with a deterministic random generator. Built with -DFZ_TRACE
(tests/fuzz/fz_trace.h), a harness prints one line for every message it sends to the code under test: what went in
and a hash of every byte that came out. This tool builds the harnesses of the old commit with that file added (two
lines each, see old_sources), runs inputs through them and through today's harnesses, and compares the lines.

  tools/sdk_golden.py record [--ref eb82532]
        every seed through the old code; writes vectors/sdk-golden/{stm32-partition,line-protocol}.json
        (seed name -> SHA-256 of its trace) and the traces of a few seeds as text. Needs the commit in this
        repository's history.
  tools/sdk_golden.py check
        every seed through today's code, against the recorded hashes (what tests/host/test_sdk_golden.py does;
        needs no history).
  tools/sdk_golden.py diff --kind stm32|line --corpus DIR [--ref eb82532] [--jobs 4]
        every file of DIR (a fuzz corpus) through the old and the new build; prints the files whose traces differ.
        For the line kind only files in the first input format count (not those that start with "AEG\\x01": the old
        harness does not know them).

The kinds:
  stm32   tests/fuzz/stm32/fuzz_stm32_partition.c: PSA messages to the partition, old (its own protocol code) and new
          (the SDK's port and core); seeds tests/fuzz/stm32/seeds/*
  line    the line protocol: old tests/fuzz/fuzz_rw612_proto.c on the RW612's aegis_proto.c, new
          tests/fuzz/fuzz_sdk_core.c on the SDK's core through the reference port; seeds: the files of
          tests/fuzz/seeds in the first input format
Needs gcc and the mldsa-native / mlkem-native v2.0.0 trees (MLDSA_NATIVE_DIR, MLKEM_NATIVE_DIR)."""
import argparse
import concurrent.futures
import glob
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.environ.get("AEGIS_TOOLS", os.path.expanduser("~/aegis-tools"))
MLDSA = os.environ.get("MLDSA_NATIVE_DIR", os.path.join(TOOLS, "mldsa-native", "mldsa"))
MLKEM = os.environ.get("MLKEM_NATIVE_DIR", os.path.join(TOOLS, "mlkem-native", "mlkem"))
FUZZ = os.path.join(ROOT, "tests", "fuzz")
GOLDEN = os.path.join(ROOT, "vectors", "sdk-golden")
REF = "eb82532"
MAGIC = b"AEG\x01"
FILES = {"stm32": "stm32-partition.json", "line": "line-protocol.json"}
# seeds whose whole trace is kept as text, for a reader
SHOWN = {"stm32": ("transcript-bound-exchange", "session-expiry"), "line": ("transcript-bound-exchange", "bad-credentials")}
STANDALONE_MAIN = r'''
int main(int argc, char **argv)
{
	static uint8_t buf[65536];

	LLVMFuzzerInitialize(&argc, &argv);
	for (int i = 1; i < argc; i++) {
		FILE *f = fopen(argv[i], "rb");
		size_t n;

		if (!f) { perror(argv[i]); return 2; }
		n = fread(buf, 1, sizeof(buf), f);
		fclose(f);
		LLVMFuzzerTestOneInput(buf, n);
	}
	printf("%d inputs, no finding\n", argc - 1);
	return 0;
}
'''


def available():
    return bool(shutil.which("gcc")) and os.path.isdir(MLDSA) and os.path.isdir(MLKEM)


def gcc(args, inc):
    cmd = ["gcc", "-O2", "-D_GNU_SOURCE", '-DMLD_CONFIG_FILE="aegis_mldsa_config.h"', "-DFZ_STANDALONE", "-DFZ_TRACE",
           "-Wno-unused-function"]
    for d in inc:
        cmd += ["-I", d]
    subprocess.run(cmd + list(args), check=True)


def objects(d, inc, sources):
    objs = []
    for src in sources:
        obj = os.path.join(d, os.path.basename(src) + ".o")
        if not os.path.exists(obj):   # one directory serves several builds of the same tree
            gcc(["-c", src, "-o", obj], inc)
        objs.append(obj)
    return objs


def gateway_pin(d, inc, gen_src, mldsa_obj):
    """The STM32 harness pins a test gateway key whose secret key it holds (gen_gw_pk.c prints the header)."""
    gcc([gen_src, mldsa_obj, "-o", os.path.join(d, "gen_gw_pk")], inc)
    with open(os.path.join(d, "fz_gateway_pk.h"), "w") as f:
        subprocess.run([os.path.join(d, "gen_gw_pk")], check=True, stdout=f)


def build_new(kind, d, extra=(), name=None):
    """Today's harness of that kind, with the trace; returns the program. extra: more compiler arguments for the
    harness (a control build), which then needs a name of its own."""
    sdk = os.path.join(ROOT, "sdk")
    inc = [os.path.join(sdk, "include"), os.path.join(sdk, "src"), os.path.join(sdk, "ports", "host"),
           os.path.join(sdk, "crypto", "mldsa"), MLDSA, os.path.join(sdk, "crypto", "mlkem"), MLKEM, FUZZ, d]
    common = [os.path.join(MLDSA, "mldsa_native.c"), os.path.join(sdk, "crypto", "mlkem_unit.c"),
              os.path.join(sdk, "src", "aegis_kmac.c"), os.path.join(sdk, "src", "aegis_sha256.c")]
    exe = os.path.join(d, name or "new-" + kind)
    if kind == "stm32":
        inc += [os.path.join(ROOT, "endpoints", "stm32h573", "tfm-aegis-partition"), os.path.join(FUZZ, "stm32", "stub")]
        objs = objects(d, inc, common)
        gateway_pin(d, inc, os.path.join(FUZZ, "stm32", "gen_gw_pk.c"), objs[0])
        gcc(['-DAEGIS_GATEWAY_PK_HEADER="fz_gateway_pk.h"', os.path.join(FUZZ, "stm32", "fuzz_stm32_partition.c")]
            + list(extra) + objs + ["-o", exe], inc)
    else:
        objs = objects(d, inc, common + [os.path.join(sdk, "ports", "host", "aegis_port_host.c")])
        gcc([os.path.join(FUZZ, "fuzz_sdk_core.c")] + list(extra) + objs + ["-o", exe], inc)
    return exe


def old_sources(ref, d):
    """The tree of the old commit under d/tree, and its two harnesses with the trace added: fz_trace.h included
    after the code under test, and one call where the harness has the answer. Nothing else is changed."""
    tree = os.path.join(d, "tree")
    os.makedirs(tree)
    ar = subprocess.run(["git", "-C", ROOT, "archive", ref], check=True, capture_output=True).stdout
    subprocess.run(["tar", "-x", "-C", tree], input=ar, check=True)

    def patched(path, edits, tail=""):
        with open(os.path.join(tree, path)) as f:
            s = f.read()
        for old, new in edits:
            if s.count(old) != 1:
                raise SystemExit("%s of %s: expected one %r" % (path, ref, old))
            s = s.replace(old, new)
        out = os.path.join(d, "old-" + os.path.basename(path))
        with open(out, "w") as f:
            f.write(s + tail)
        return out

    stm32 = patched("tests/fuzz/stm32/fuzz_stm32_partition.c", [
        ('#include "aegis_pq_attest.c"\n', '#include "aegis_pq_attest.c"\n#include "fz_trace.h"\n'),
        ("\tst = aegis_pq_service_sfn(&msg);\n",
         "\tst = aegis_pq_service_sfn(&msg);\n\tfz_trace_msg((int)type, l0, l1, o0, o1, (int)st, cur.out[0], "
         "cur.out_len[0], cur.out[1], cur.out_len[1]);\n")])
    line = patched("tests/fuzz/fuzz_rw612_proto.c", [
        ('#include "aegis_proto.c"\n', '#include "aegis_proto.c"\n#include "fz_trace.h"\n'),
        ("\tr = aegis_proto_handle(line, out, AEGIS_REPLY_MAX);\n",
         "\tr = aegis_proto_handle(line, out, AEGIS_REPLY_MAX);\n\tfz_trace_line(req, n, out, r);\n")], STANDALONE_MAIN)
    return tree, {"stm32": stm32, "line": line}


def build_old(kind, ref, d):
    """The harness of that kind as it was at ref, on the protocol code of ref; returns the program."""
    tree, src = old_sources(ref, d)
    part = os.path.join(tree, "endpoints", "stm32h573", "tfm-aegis-partition")
    prover = os.path.join(tree, "endpoints", "rw612", "prover", "src")
    inc = [part, os.path.join(part, "mldsa"), MLDSA, os.path.join(part, "mlkem"), MLKEM, FUZZ, d]
    common = [os.path.join(MLDSA, "mldsa_native.c"), os.path.join(part, "mlkem_unit.c"), os.path.join(part, "aegis_kmac.c")]
    exe = os.path.join(d, "old-" + kind)
    if kind == "stm32":
        inc += [os.path.join(tree, "tests", "fuzz", "stm32", "stub")]
        objs = objects(d, inc, common)
        gateway_pin(d, inc, os.path.join(tree, "tests", "fuzz", "stm32", "gen_gw_pk.c"), objs[0])
        gcc(['-DAEGIS_GATEWAY_PK_HEADER="fz_gateway_pk.h"', src[kind]] + objs + ["-o", exe], inc)
    else:
        inc += [prover]
        objs = objects(d, inc, common + [os.path.join(prover, "sha256.c")])
        gcc([src[kind]] + objs + ["-o", exe], inc)
    return exe


def trace(exe, path):
    """The trace of one input, or None with the reason if the harness did not finish."""
    r = subprocess.run([exe, path], capture_output=True)
    if r.returncode != 0:
        return None, r.stderr.decode(errors="replace").strip().splitlines()[:1]
    return r.stdout, None


def first_format(path):
    with open(path, "rb") as f:
        return f.read(4) != MAGIC


def seeds(kind):
    if kind == "stm32":
        return sorted(glob.glob(os.path.join(FUZZ, "stm32", "seeds", "*")))
    return sorted(p for p in glob.glob(os.path.join(FUZZ, "seeds", "*")) if first_format(p))


def record(ref):
    commit = subprocess.run(["git", "-C", ROOT, "rev-parse", ref], check=True, capture_output=True, text=True).stdout.strip()
    os.makedirs(GOLDEN, exist_ok=True)
    for kind in ("stm32", "line"):
        with tempfile.TemporaryDirectory() as d:
            exe = build_old(kind, ref, d)
            out = {"ref": commit, "kind": kind, "harness": "tests/fuzz/stm32/fuzz_stm32_partition.c" if kind == "stm32"
                   else "tests/fuzz/fuzz_rw612_proto.c", "seeds": {}}
            for p in seeds(kind):
                t, why = trace(exe, p)
                if t is None:
                    raise SystemExit("%s: the harness of %s does not pass it: %s" % (p, ref, why))
                name = os.path.basename(p)
                out["seeds"][name] = hashlib.sha256(t).hexdigest()
                if name in SHOWN[kind]:
                    with open(os.path.join(GOLDEN, "%s.%s.trace.txt" % (FILES[kind][:-5], name)), "wb") as f:
                        f.write(t)
        with open(os.path.join(GOLDEN, FILES[kind]), "w") as f:
            json.dump(out, f, indent=1, sort_keys=True)
            f.write("\n")
        print("%s: %d seeds recorded from %s" % (kind, len(out["seeds"]), commit[:8]))


def check(kind, d):
    """Today's code against the recorded hashes: the seeds that differ (name, why)."""
    with open(os.path.join(GOLDEN, FILES[kind])) as f:
        want = json.load(f)["seeds"]
    exe = build_new(kind, d)
    bad = []
    have = {os.path.basename(p): p for p in seeds(kind)}
    for name in sorted(set(want) | set(have)):
        if name not in want or name not in have:
            bad.append((name, "recorded but no such seed" if name in want else "a seed in the first format that is not recorded"))
            continue
        t, why = trace(exe, have[name])
        if t is None:
            bad.append((name, "the harness stopped: %s" % why))
        elif hashlib.sha256(t).hexdigest() != want[name]:
            bad.append((name, "answers differ from the recorded ones"))
    return len(want), bad


def diff(kind, corpus, ref, jobs):
    files = sorted(p for p in glob.glob(os.path.join(corpus, "*")) if os.path.isfile(p))
    if kind == "line":
        files = [p for p in files if first_format(p)]
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "o"))
        os.makedirs(os.path.join(d, "n"))
        old, new = build_old(kind, ref, os.path.join(d, "o")), build_new(kind, os.path.join(d, "n"))

        def one(p):
            a, wa = trace(old, p)
            b, wb = trace(new, p)
            if a is None or b is None:
                return p, "old: %s; new: %s" % (wa or "finished", wb or "finished")
            return (p, "answers differ") if a != b else None
        with concurrent.futures.ThreadPoolExecutor(jobs) as ex:
            res = [r for r in ex.map(one, files) if r]
    for p, why in res:
        print("DIFF %s: %s" % (p, why))
    print("%s: %d inputs through %s and today's code, %d differ" % (kind, len(files), ref, len(res)))
    return 1 if res else 0


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("record").add_argument("--ref", default=REF)
    sub.add_parser("check")
    dp = sub.add_parser("diff")
    dp.add_argument("--kind", choices=("stm32", "line"), required=True)
    dp.add_argument("--corpus", required=True)
    dp.add_argument("--ref", default=REF)
    dp.add_argument("--jobs", type=int, default=4)
    a = ap.parse_args()
    if not available():
        raise SystemExit("needs gcc and the mldsa-native / mlkem-native trees")
    if a.cmd == "record":
        record(a.ref)
        return 0
    if a.cmd == "diff":
        return diff(a.kind, a.corpus, a.ref, a.jobs)
    rc = 0
    for kind in ("stm32", "line"):
        with tempfile.TemporaryDirectory() as d:
            n, bad = check(kind, d)
        for name, why in bad:
            print("DIFF %s %s: %s" % (kind, name, why))
        print("%s: %d recorded seeds, %d differ" % (kind, n, len(bad)))
        rc |= bool(bad)
    return rc


if __name__ == "__main__":
    sys.exit(main())
