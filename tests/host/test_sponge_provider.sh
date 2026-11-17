#!/bin/sh
# The aegis_pqc2 SHA-3 provider (gateway/pqc/aegis_sponge_drv.c) on the PC, against the C register model:
#   1. the model behaves as the RTL: it replays the RTL test script (hw/tb/vectors/sponge_ops.txt, from hw/tb/run_all.sh)
#   2. liboqs is built with the provider (tools/build_liboqs_sponge.sh x86); liboqs' own test_sha3 passes through it
#   3. ML-KEM-768 and ML-DSA-65 known-answer outputs are byte-identical to plain liboqs, with 8 slots, 1 slot (every
#      context switch spills) and without DMA
#   4. the NIST ACVP cases pass (8 slots and 1 slot); the corrupted cases give the same exit codes as plain liboqs
# Needs build/acvp/commands.jsonl (tools/acvp_commands.py) for step 4.
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
PY=${PYTHON:-$ROOT/.venv/bin/python}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT
pass=0; fail=0
ok() { echo "PASS $1"; pass=$((pass+1)); }
no() { echo "FAIL $1"; fail=$((fail+1)); }

[ -f "$ROOT/hw/tb/vectors/sponge_ops.txt" ] || "$PY" "$ROOT/hw/tb/gen_sponge_vectors.py" >/dev/null
cc -O2 -Wall -Wextra -Werror -I"$ROOT/gateway/pqc" "$ROOT/tools/accel/replay_model.c" "$ROOT/gateway/pqc/aegis_sponge_model.c" -o "$W/replay"
if "$W/replay" "$ROOT/hw/tb/vectors/sponge_ops.txt" >/dev/null; then ok "C model = RTL test script"; else no "C model = RTL test script"; fi

"$ROOT/tools/build_liboqs_sponge.sh" x86 >/dev/null
B=$T/liboqs-x86-sponge/tests
for slots in 8 1; do
	if AEGIS_PQC_SPONGE=model AEGIS_PQC_SLOTS=$slots "$B/test_sha3" >/dev/null 2>&1; then ok "test_sha3, $slots slot(s)"; else no "test_sha3, $slots slot(s)"; fi
done
AEGIS_PQC_SPONGE=model AEGIS_PQC_STATS=1 "$B/test_sha3" 2>"$W/st" >/dev/null || true
if grep -q "reads=[1-9]" "$W/st"; then ok "test_sha3 really went through the provider"; else no "test_sha3 really went through the provider"; fi

# every program the checks below use must really run through the provider (a silent fallback would pass them all)
used() { AEGIS_PQC_SPONGE=model AEGIS_PQC_STATS=1 "$@" 2>&1 >/dev/null | grep -q "permutations=[1-9]"; }
for prog in "kat_kem ML-KEM-768" "kat_sig ML-DSA-65"; do
	set -- $prog
	if used "$B/$1" "$2"; then ok "$1 really went through the provider"; else no "$1 really went through the provider"; fi
done
if [ -f "$ROOT/build/acvp/commands.jsonl" ]; then
	"$PY" - "$ROOT/build/acvp/commands.jsonl" "$B" > "$W/probe" <<'PY'
import json, os, subprocess, sys
seen = set()
for line in open(sys.argv[1]):
    r = json.loads(line)
    if r["bin"] in seen:
        continue
    seen.add(r["bin"])
    p = subprocess.run([os.path.join(sys.argv[2], r["bin"])] + r["args"], capture_output=True, text=True,
                       env=dict(os.environ, AEGIS_PQC_SPONGE="model", AEGIS_PQC_STATS="1"))
    print(r["bin"], "yes" if "permutations=" in p.stderr and "permutations=0 " not in p.stderr.split("aegis_sponge")[-1] else "no")
PY
	if ! grep -q " no$" "$W/probe" && [ -s "$W/probe" ]; then ok "ACVP programs really went through the provider ($(tr '\n' ' ' < "$W/probe"))"; else no "ACVP programs really went through the provider ($(tr '\n' ' ' < "$W/probe"))"; fi
fi

"$B/kat_kem" ML-KEM-768 > "$W/kem.ref"
"$B/kat_sig" ML-DSA-65 > "$W/sig.ref"
# AEGIS_PQC_MODEL_SLOT: the core is left in another slot by a previous process (found on the board: the driver
# assumed slot 0 at start)
for e in "AEGIS_PQC_SLOTS=8" "AEGIS_PQC_SLOTS=1" "AEGIS_PQC_NODMA=1" "AEGIS_PQC_MODEL_SLOT=5"; do
	env $e AEGIS_PQC_SPONGE=model "$B/kat_kem" ML-KEM-768 > "$W/kem" && cmp -s "$W/kem" "$W/kem.ref" && ok "ML-KEM-768 KAT identical ($e)" || no "ML-KEM-768 KAT identical ($e)"
	env $e AEGIS_PQC_SPONGE=model "$B/kat_sig" ML-DSA-65 > "$W/sig" && cmp -s "$W/sig" "$W/sig.ref" && ok "ML-DSA-65 KAT identical ($e)" || no "ML-DSA-65 KAT identical ($e)"
done

if [ -f "$ROOT/build/acvp/commands.jsonl" ]; then
	for slots in 8 1; do
		AEGIS_PQC_SPONGE=model AEGIS_PQC_SLOTS=$slots "$PY" "$ROOT/tools/run_acvp_commands.py" "$ROOT/build/acvp/commands.jsonl" "$B" > "$W/acvp" || true
		if "$PY" -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(not (d['cases'] == 265 and d['failed'] == 0))" "$W/acvp"; then
			ok "NIST ACVP 265 cases, $slots slot(s)"; else no "NIST ACVP 265 cases, $slots slot(s)"; fi
	done
	if [ -f "$ROOT/build/acvp/negative.jsonl" ]; then
		"$PY" - "$ROOT/build/acvp/negative.jsonl" "$B" <<'PY' && ok "corrupted ACVP cases: same exit codes as plain liboqs" || no "corrupted ACVP cases: same exit codes as plain liboqs"
import json, os, subprocess, sys
bad = 0
for line in open(sys.argv[1]):
    r = json.loads(line)
    codes = {subprocess.run([os.path.join(sys.argv[2], r["bin"])] + r["args"], capture_output=True,
                            env=dict(os.environ, **e)).returncode
             for e in ({}, {"AEGIS_PQC_SPONGE": "model"}, {"AEGIS_PQC_SPONGE": "model", "AEGIS_PQC_SLOTS": "1"})}
    bad += len(codes) != 1
sys.exit(bad)
PY
	fi
else
	echo "SKIP ACVP (no build/acvp/commands.jsonl)"
fi
echo "passed $pass, failed $fail"
[ "$fail" = 0 ]
