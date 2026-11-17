#!/bin/sh
# On the board with the accelerator v2 fabric (aegis_pqc2, ID 0xAE150002): the same checks as
# tests/host/test_sponge_provider.sh but with AEGIS_PQC_SPONGE=hw, plus raw timings and liboqs speed.
# Run from the PC; copies the RISC-V build (tools/build_liboqs_sponge.sh rv64) to the gateway.
#   GATEWAY=<address> tools/accel/board_sponge_test.sh  ->  logs/accel/<date>/
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
L=$T/liboqs-rv64-sponge
G=root@${GATEWAY:?set GATEWAY}
D=/root/aegis/oqs-sponge
OUT=$ROOT/logs/accel/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
ssh -o BatchMode=yes "$G" "rm -rf $D && mkdir -p $D"
scp -q "$L/lib/liboqs.so.0.16.0" "$L"/tests/test_sha3 "$L"/tests/kat_kem "$L"/tests/kat_sig "$L"/tests/vectors_kem \
    "$L"/tests/vectors_sig "$L"/tests/speed_kem "$L"/tests/speed_sig "$ROOT/build/accel/sponge_bench" \
    "$ROOT/tools/run_acvp_commands.py" "$ROOT/build/acvp/commands.jsonl" "$G:$D/"
ssh -o BatchMode=yes "$G" "cd $D && ln -sf liboqs.so.0.16.0 liboqs.so.9"
run() { ssh -o BatchMode=yes "$G" "cd $D && export LD_LIBRARY_PATH=$D && $1"; }
pass=0; fail=0
ok() { echo "PASS $1" | tee -a "$OUT/summary.txt"; pass=$((pass+1)); }
no() { echo "FAIL $1" | tee -a "$OUT/summary.txt"; fail=$((fail+1)); }

run "./sponge_bench 2000" > "$OUT/sponge_bench.txt" 2>&1 && ok "raw timings; DMA results equal APB squeezes" || no "raw timings; DMA results equal APB squeezes"
cat "$OUT/sponge_bench.txt"

for slots in 8 1; do
	run "AEGIS_PQC_SPONGE=hw AEGIS_PQC_SLOTS=$slots AEGIS_PQC_STATS=1 ./test_sha3" > "$OUT/test_sha3-$slots.txt" 2>&1 \
		&& grep -q "permutations=[1-9]" "$OUT/test_sha3-$slots.txt" && ok "test_sha3 on the core, $slots slot(s)" || no "test_sha3 on the core, $slots slot(s)"
done
run "./kat_kem ML-KEM-768 > kem.ref && ./kat_sig ML-DSA-65 > sig.ref"
for e in "AEGIS_PQC_SLOTS=8" "AEGIS_PQC_SLOTS=1" "AEGIS_PQC_NODMA=1"; do
	run "env $e AEGIS_PQC_SPONGE=hw AEGIS_PQC_STATS=1 ./kat_kem ML-KEM-768 2>kem.st | cmp -s - kem.ref && grep -q 'permutations=[1-9]' kem.st" \
		&& ok "ML-KEM-768 KAT identical on the core ($e)" || no "ML-KEM-768 KAT identical on the core ($e)"
	run "env $e AEGIS_PQC_SPONGE=hw AEGIS_PQC_STATS=1 ./kat_sig ML-DSA-65 2>sig.st | cmp -s - sig.ref && grep -q 'permutations=[1-9]' sig.st" \
		&& ok "ML-DSA-65 KAT identical on the core ($e)" || no "ML-DSA-65 KAT identical on the core ($e)"
done
run "grep aegis_sponge sig.st" >> "$OUT/kat_sig-stats.txt" 2>&1 || true
for slots in 8 1; do
	run "AEGIS_PQC_SPONGE=hw AEGIS_PQC_SLOTS=$slots python3 run_acvp_commands.py commands.jsonl ." > "$OUT/acvp-$slots.json" 2>&1 || true
	python3 -c "import json,sys; d=json.load(open(sys.argv[1])); sys.exit(not (d['cases']==265 and d['failed']==0))" "$OUT/acvp-$slots.json" \
		&& ok "NIST ACVP 265 cases on the core, $slots slot(s)" || no "NIST ACVP 265 cases on the core, $slots slot(s)"
done

for r in 1 2; do
	for mode in plain hw; do
		env=""; [ $mode = hw ] && env="AEGIS_PQC_SPONGE=hw"
		run "env $env ./speed_kem ML-KEM-768; env $env ./speed_sig ML-DSA-65" 2>&1 \
			| grep -E "^(keygen|encaps|decaps|keypair|sign|verify) " > "$OUT/speed-$mode-$r.txt" || true
	done
done
python3 - "$OUT" <<'PY' | tee "$OUT/speed.md"
import sys, glob, re
out = sys.argv[1]
def load(mode):
    acc = {}
    for f in sorted(glob.glob("%s/speed-%s-*.txt" % (out, mode))):
        for line in open(f):
            c = [x.strip() for x in line.split("|")]
            acc.setdefault(c[0], []).append(float(c[3]))
    return {k: sum(v) / len(v) for k, v in acc.items()}
p, h = load("plain"), load("hw")
print("| Operation | software (us) | with the core (us) | speed-up |")
print("|---|---|---|---|")
for k in ("keygen", "encaps", "decaps", "keypair", "sign", "verify"):
    if k in p and k in h:
        print("| %s | %.0f | %.0f | x%.2f |" % (k, p[k], h[k], p[k] / h[k]))
PY
echo "passed $pass, failed $fail -> $OUT"
[ "$fail" = 0 ]
