#!/bin/sh
# Aegis regression run. Host stages need no hardware; --board adds the checks on the real boards
# (gateway at $GATEWAY, STM32 line protocol at $STM32, the STM32 on its own Ethernet).
#   tools/regression.sh [--board]
# REDTEAM_STM32=host:port picks the STM32 the device red-team attacks (default $STM32), e.g. REDTEAM_STM32=$STM32_2
# while board 1 is not connected. The heartbeat stage checks every endpoint that holds a session on the gateway.
# Writes logs/regression/<time>/ and exits non-zero on the first failing stage.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"
[ -f "$REPO/bench.env" ] && { set -a; . "$REPO/bench.env"; set +a; }
PY=.venv/bin/python
GATEWAY=${GATEWAY:-}
STM32=${STM32:-}
OUT=logs/regression/$(date +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
pass=0; fail=0
stage() {
    name=$1; shift
    if "$@" > "$OUT/$name.log" 2>&1; then echo "PASS $name"; pass=$((pass+1)); else echo "FAIL $name (see $OUT/$name.log)"; fail=$((fail+1)); fi
}
stage host-unit-tests      $PY -m unittest discover -s tests/host
stage host-redteam         $PY tests/redteam/fuzz_host.py 2000
stage rtl-simulation       hw/tb/run_all.sh --fast
stage acvp-pc-software     $PY tools/run_acvp_commands.py build/acvp/commands.jsonl "$HOME/aegis-tools/liboqs-src/build/tests"
stage acvp-vectors-intact  sh -c 'cd vectors/acvp && sha256sum -c --quiet SHA256SUMS'
if [ "${1:-}" = --board ]; then
    : "${GATEWAY:?set GATEWAY in bench.env (see bench.env.example)}" "${STM32:?set STM32 in bench.env (see bench.env.example)}"
    B=root@$GATEWAY
    stage gateway-phase1       env BOARD=$GATEWAY $PY tests/board/phase1_board_checks.py
    stage fabric-selftest      ssh -o BatchMode=yes $B /root/aegis/pqc_selftest 200
    stage fabric-acvp          ssh -o BatchMode=yes $B 'cd /root/aegis/oqs-fabric && LD_LIBRARY_PATH=$PWD AEGIS_PQC_KECCAK=hw python3 run_acvp_commands.py commands.jsonl $PWD'
    # accelerator v2 (design 102): liboqs with the sponge provider, NIST ACVP cases with the core doing all SHA-3
    # (installed by tools/accel/board_sponge_test.sh)
    stage fabric-sponge-acvp   ssh -o BatchMode=yes $B 'cd /root/aegis/oqs-sponge && LD_LIBRARY_PATH=$PWD AEGIS_PQC_SPONGE=hw python3 run_acvp_commands.py commands.jsonl $PWD'
    stage fleet-once           ssh -o BatchMode=yes $B 'cd /root/aegis/gateway/aegisd && python3 fleet.py once ../policy/fleet.json --no-credentials | grep -q "\"admitted\": true"'
    stage fleet-session        ssh -o BatchMode=yes $B 'cd /root/aegis/gateway/aegisd && python3 fleet.py session ../policy/fleet.json | grep -q "\"same_session\": true"'
    stage fleet-heartbeat      ssh -o BatchMode=yes $B 'cd /root/aegis/gateway/aegisd && python3 -c "
import sys, json, os
sys.path.insert(0, \"../../common\")
import fleet
n = 0
for ep in json.load(open(\"../policy/fleet.json\"))[\"endpoints\"]:
    f = \"/var/lib/aegis/credentials/\" + ep[\"name\"] + \".session\"
    if os.path.exists(f):
        print(ep[\"name\"], fleet.heartbeat(ep, open(f, \"rb\").read()))
        n += 1
sys.exit(0 if n else \"no endpoint holds a session\")
"'
    stage device-redteam       $PY tests/redteam/fuzz_devices.py --stm32 "${REDTEAM_STM32:-$STM32}" --gateway "$GATEWAY" --n 40
fi
echo "passed $pass, failed $fail -> $OUT"
[ "$fail" -eq 0 ]
