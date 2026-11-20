#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The deepest stack path of the STM32H573 Aegis partition, from GCC's own figures.

  tools/stack_estimate.py <TF-M build directory> [--root NAME ...] [--edge CALLER:CALLEE ...] [--top N]

The partition is compiled with -fstack-usage (endpoints/stm32h573/tfm-aegis-partition/CMakeLists.txt), which writes
each function's frame size to a .su file next to its object. This script reads them, takes the call graph from the
disassembly of the linked secure image (bin/tfm_s.axf: direct calls and tail calls), and adds the frames up along the
deepest path from each root: the service function (every message) and the partition's initialisation (the key
generation).

What the disassembly cannot show is added by hand:
  - calls through a pointer. The SDK's core reaches the platform through struct aegis_platform; the edges for this
    port's functions are listed in INDIRECT below (--edge adds more). A "blx <register>" in a function on a path
    that has no listed edge is reported.
  - functions compiled without -fstack-usage (TF-M's own code, the C library). Their frame is read from the
    prologue in the disassembly (push, vpush, sub sp) and marked "~" in the output.

The figure is the partition's own frames. The boards report a little more in the heartbeat status (sstack=): the
service is entered through TF-M's secure function wrapper, and psa_call, psa_read and psa_write run on this stack
as far as TF-M's thread-mode veneers. For the image before the SDK the difference was 168 bytes (18712 here against
the 18880 the boards report): add it to compare a new figure with the stack's size (0x6800 = 26624).
"""
import argparse
import collections
import glob
import os
import re
import subprocess
import sys

# the platform functions the core calls through struct aegis_platform in this port
INDIRECT = {
    "sweep": ["s_clock"],
    "sign_work": ["s_random"],
    "kem_coins": ["s_random"],
    "quote": ["s_evidence"],
    "aegis_prover_quote": ["s_evidence"],   # quote() is part of its callers' frames
    "aegis_prover_handle_line": ["s_evidence"],
    "aegis_prover_init": [],                # identity_public_key: this port sets none, the core holds the key
}
ROOTS = ["aegis_pq_service_sfn", "aegis_pq_init"]


def find_objdump():
    if os.environ.get("OBJDUMP"):
        return os.environ["OBJDUMP"]
    for pat in ("~/st/stm32cubeide_*/plugins/*gnu-tools-for-stm32*/tools/bin/arm-none-eabi-objdump",
                "~/aegis-tools/arm-gnu-toolchain-*/bin/arm-none-eabi-objdump"):
        hits = sorted(glob.glob(os.path.expanduser(pat)))
        if hits:
            return hits[-1]
    return "arm-none-eabi-objdump"


def read_su(build):
    """name -> (bytes, qualifier, file); a name defined in several files keeps its largest frame."""
    frames, dup = {}, set()
    pattern = os.path.join(build, "secure_fw", "partitions", "partitions", "tfm-aegis-partition*", "**", "*.su")
    files = glob.glob(pattern, recursive=True)
    for path in files:
        for line in open(path):
            where, size, qual = line.rstrip("\n").split("\t")
            name = where.split(":")[-1]
            if name in frames:
                dup.add(name)
                if int(size) <= frames[name][0]:
                    continue
            frames[name] = (int(size), qual, os.path.basename(path))
    return frames, dup, len(files)


def base(name):
    """GCC's clones (f.constprop.0, f.isra.0, f.part.0) have the frame the .su file gives under the clone's name, or
    under the function's."""
    return re.sub(r"\.(constprop|isra|part|cold)\.\d+", "", name)


def prologue_frame(lines):
    """Frame of a function without a .su entry: what its first instructions push and subtract."""
    total = 0
    for ins in lines[:12]:
        m = re.search(r"\b(?:push|stmdb\s+sp!,)\s*\{([^}]*)\}", ins)
        if m:
            regs = 0
            for r in m.group(1).split(","):
                r = r.strip()
                if "-" in r:
                    a, b = r.split("-")
                    regs += int(b[1:]) - int(a[1:]) + 1
                elif r:
                    regs += 1
            total += 4 * regs
        m = re.search(r"\bvpush\s*\{([^}]*)\}", ins)
        if m:
            r = m.group(1).split("-")
            n = int(r[-1].strip()[1:]) - int(r[0].strip()[1:]) + 1
            total += (8 if r[0].strip()[0] == "d" else 4) * n
        m = re.search(r"\bsub(?:\.w|w)?\s+sp,\s*(?:sp,\s*)?#(\d+)", ins)
        if m:
            total += int(m.group(1))
    return total


def read_graph(objdump, elf):
    out = subprocess.run([objdump, "-d", "--no-show-raw-insn", elf], check=True, capture_output=True, text=True).stdout
    calls, body, indirect = collections.defaultdict(set), collections.defaultdict(list), set()
    cur = None
    for line in out.splitlines():
        m = re.match(r"^[0-9a-f]+ <([^>]+)>:$", line)
        if m:
            cur = m.group(1)
            continue
        if cur is None or "\t" not in line:
            continue
        ins = line.split("\t", 1)[1]
        body[cur].append(ins)
        m = re.match(r"(bl|blx|b|b\.w|b\.n|b[a-z]{2}(?:\.[wn])?|cbz|cbnz)\s+(?:[^<]*)<([^>+]+)>\s*$", ins)
        if m and m.group(2) != cur:
            calls[cur].add(m.group(2))
        elif re.match(r"blx\s+r\d+", ins) or re.match(r"bx\s+r(?!14)\d+", ins):
            indirect.add(cur)
    return calls, body, indirect


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("build", help="TF-M build directory (build_tfm.sh's OUT)")
    ap.add_argument("--root", action="append", help="start of a path (default: %s)" % ", ".join(ROOTS))
    ap.add_argument("--edge", action="append", default=[], help="CALLER:CALLEE, a call through a pointer")
    ap.add_argument("--top", type=int, default=0, help="also list the N largest frames")
    args = ap.parse_args()
    frames, dup, files = read_su(args.build)
    if not frames:
        sys.exit("no .su files under %s: was the partition built with -fstack-usage?" % args.build)
    elf = os.path.join(args.build, "bin", "tfm_s.axf")
    calls, body, indirect = read_graph(find_objdump(), elf)
    extra = {k: list(v) for k, v in INDIRECT.items()}
    for e in args.edge:
        a, b = e.split(":")
        extra.setdefault(a, []).append(b)
    for a, bs in extra.items():
        for name in list(body):
            if base(name) == a:
                calls[name].update(b for b in bs if b in body)

    def frame(name):
        for key in (name, base(name)):
            if key in frames:
                return frames[key][0], ""
        return prologue_frame(body.get(name, [])), "~"

    memo, stack = {}, []

    def deepest(name):
        if name in memo:
            return memo[name]
        if name in stack:
            sys.exit("recursion through %s: no bound" % name)
        stack.append(name)
        best, path = 0, []
        for callee in sorted(calls.get(name, ())):
            if callee in body:
                d, p = deepest(callee)
                if d > best:
                    best, path = d, p
        stack.pop()
        memo[name] = (frame(name)[0] + best, [name] + path)
        return memo[name]

    print("%d .su files, %d functions with a frame figure; image %s" % (files, len(frames), elf))
    worst = 0
    for root in args.root or ROOTS:
        if root not in body:
            sys.exit("%s is not in the image" % root)
        total, path = deepest(root)
        worst = max(worst, total)
        print("\n%s: %d bytes" % (root, total))
        for name in path:
            size, mark = frame(name)
            qual = frames.get(name, frames.get(base(name), (0, "", "")))[1]
            notes = []
            if qual and qual != "static":
                notes.append(qual)  # "dynamic": a frame GCC could not bound
            if name in indirect and base(name) not in extra:
                notes.append("calls through a pointer: no edge listed")
            if name in dup or base(name) in dup:
                notes.append("name defined twice: the larger frame")
            print("  %6s%s  %s%s" % (size, mark, name, "   [" + "; ".join(notes) + "]" if notes else ""))
    print("\ndeepest path: %d bytes" % worst)
    if args.top:
        print("\nlargest frames:")
        for name, (size, qual, f) in sorted(frames.items(), key=lambda kv: -kv[1][0])[:args.top]:
            print("  %6d  %s (%s, %s)" % (size, name, f, qual))


if __name__ == "__main__":
    main()
