#!/bin/sh
# Aegis regression run. Host stages need no hardware; --board adds the checks on the real boards
# (gateway at $GATEWAY, STM32 line protocol at $STM32, the STM32 on its own Ethernet).
#   tools/regression.sh [--board]
# Writes logs/regression/<time>/ and exits non-zero on the first failing stage.
set -u
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"
PY=.venv/bin/python
GATEWAY=${GATEWAY:-192.0.2.10}
STM32=${STM32:-192.0.2.20:7444}
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
    B=root@$GATEWAY
    stage gateway-phase1       env BOARD=$GATEWAY $PY tests/board/phase1_board_checks.py
    stage fabric-selftest      ssh -o BatchMode=yes $B /root/aegis/pqc_selftest 200
    stage fabric-acvp          ssh -o BatchMode=yes $B 'cd /root/aegis/oqs-fabric && LD_LIBRARY_PATH=$PWD AEGIS_PQC_KECCAK=hw python3 run_acvp_commands.py commands.jsonl $PWD'
    stage fleet-once           ssh -o BatchMode=yes $B 'cd /root/aegis/gateway/aegisd && python3 fleet.py once ../policy/fleet.json --no-credentials | grep -q "\"admitted\": true"'
    stage fleet-session        ssh -o BatchMode=yes $B 'cd /root/aegis/gateway/aegisd && python3 fleet.py session ../policy/fleet.json | grep -q "\"same_session\": true"'
    stage fleet-heartbeat      ssh -o BatchMode=yes $B 'cd /root/aegis/gateway/aegisd && python3 -c "import sys,json; sys.path.insert(0,\"../../common\"); import fleet; ep=json.load(open(\"../policy/fleet.json\"))[\"endpoints\"][0]; print(fleet.heartbeat(ep, open(\"/var/lib/aegis/credentials/\"+ep[\"name\"]+\".session\",\"rb\").read()))"'
    stage device-redteam       $PY tests/redteam/fuzz_devices.py --stm32 "$STM32" --gateway "$GATEWAY" --n 40
fi
echo "passed $pass, failed $fail -> $OUT"
[ "$fail" -eq 0 ]
