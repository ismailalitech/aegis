#!/bin/sh
# Aegis regression run. Host stages need no hardware; --board adds the checks on the real boards
# (gateway at $GATEWAY, STM32 line protocol at $STM32, the STM32 on its own Ethernet).
#   tools/regression.sh [--board [--with-expiry]] | --expiry-only
# REDTEAM_STM32=host:port picks the STM32 the device red-team attacks (default $STM32), e.g. REDTEAM_STM32=$STM32_2
# while board 1 is not connected. The heartbeat stage checks every endpoint that holds a session on the gateway.
# --with-expiry (or AEGIS_REGRESSION_EXPIRY=1 with --board) adds the stage endpoint-expiry, off by default: it stops
# the aegis-fleet service, runs tests/board/expiry_check.py on the gateway for each endpoint that holds a session
# (EXPIRY_ENDPOINTS="name ..." to choose), starts the service again however the stage ends (failure, Ctrl-C) and
# waits until those endpoints are ADMITTED again. About 3 minutes, during which the fleet is not re-attested.
# --expiry-only runs that one stage and nothing else (tools/soak.py's extra expiry rounds, docs/soak-and-watchdogs.md).
# Writes logs/regression/<time>/, runs every stage and exits non-zero if any failed.
# SPDX-License-Identifier: Apache-2.0
set -u
usage() { sed -n '2,12p' "$0" | cut -c3-; }
BOARD=; WITH_EXPIRY=; ONLY_EXPIRY=
for arg in "$@"; do
    case $arg in
        --board) BOARD=1 ;;
        --with-expiry) WITH_EXPIRY=1 ;;
        --expiry-only) ONLY_EXPIRY=1; BOARD=1; WITH_EXPIRY=1 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "unknown option: $arg" >&2; usage >&2; exit 2 ;;
    esac
done
[ -n "$WITH_EXPIRY" ] && [ -z "$BOARD" ] && { echo "--with-expiry needs --board" >&2; exit 2; }
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"
[ -f "$REPO/bench.env" ] && { set -a; . "$REPO/bench.env"; set +a; }
[ "${AEGIS_REGRESSION_EXPIRY:-0}" = 1 ] && WITH_EXPIRY=1
# AEGIS_STM32_OVERRIDE=host:port wins over bench.env for STM32 and REDTEAM_STM32 (tools/soak.py, board 1 not connected)
[ -n "${AEGIS_STM32_OVERRIDE:-}" ] && { STM32=$AEGIS_STM32_OVERRIDE; REDTEAM_STM32=$AEGIS_STM32_OVERRIDE; }
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

# The expiry stage's SSH calls give up on a dead link instead of hanging (and the soak's regression timeout with it).
SSHX="-o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=15 -o ServerAliveCountMax=3"
# endpoint-expiry: the fleet service would provision again in the middle of a check, so it is stopped for the stage.
# The EXIT trap (reached from Ctrl-C and kill through the INT/TERM/HUP traps) starts it again; a timer on the gateway
# starts it after 15 minutes should this PC or the link go away first. fleet_start prints the gateway's clock.
fleet_start() {
    ssh $SSHX "$B" \
        'date +%s; systemctl start aegis-fleet; systemctl stop aegis-expiry-guard.timer 2>/dev/null; true'
}
endpoint_expiry() {
    names=${EXPIRY_ENDPOINTS:-$(ssh $SSHX "$B" \
        'cd /var/lib/aegis/credentials && for f in *.session; do [ -f "$f" ] && echo "${f%.session}"; done')}
    [ -n "$names" ] || { echo "no endpoint holds a session"; return 1; }
    echo "endpoints:" $names
    trap fleet_start EXIT
    trap 'exit 130' INT TERM HUP
    ssh $SSHX "$B" 'systemctl stop aegis-expiry-guard.timer 2>/dev/null; systemctl reset-failed aegis-expiry-guard.service 2>/dev/null
        systemd-run --quiet --unit=aegis-expiry-guard --on-active=900 systemctl start aegis-fleet
        systemctl stop aegis-fleet && echo "aegis-fleet stopped"' || return 1
    rc=0
    for n in $names; do
        echo "== $n"
        ssh $SSHX "$B" "python3 - /root/aegis/gateway/policy/fleet.json $n" < tests/board/expiry_check.py \
            || { echo "FAIL $n"; rc=1; }
    done
    started=$(fleet_start)
    trap - EXIT INT TERM HUP
    since=$(echo "$started" | sed -n 1p)
    echo "aegis-fleet started at gateway time $since"
    case $since in ''|*[!0-9]*) echo "could not start aegis-fleet"; return 1 ;; esac
    deadline=$(( $(date +%s) + 240 ))
    for n in $names; do
        until ssh $SSHX "$B" \
                "journalctl -u aegis-fleet --since @$since -o cat --no-pager | grep -qF ' $n ADMITTED'"; do
            [ "$(date +%s)" -lt "$deadline" ] || { echo "FAIL $n not ADMITTED within 240 s of the restart"; rc=1; break; }
            sleep 5
        done
    done
    echo "== gateway journal since the restart"
    ssh $SSHX "$B" "journalctl -u aegis-fleet --since @$since -o cat --no-pager" | grep -F ' ADMITTED'
    return $rc
}

if [ -n "$ONLY_EXPIRY" ]; then
    : "${GATEWAY:?set GATEWAY in bench.env (see bench.env.example)}"
    B=root@$GATEWAY
    stage endpoint-expiry endpoint_expiry
    echo "passed $pass, failed $fail -> $OUT"
    [ "$fail" -eq 0 ]
    exit
fi
stage host-unit-tests      $PY -m unittest discover -s tests/host
stage host-redteam         $PY tests/redteam/fuzz_host.py 2000
stage rtl-simulation       hw/tb/run_all.sh --fast
stage acvp-pc-software     $PY tools/run_acvp_commands.py build/acvp/commands.jsonl "$HOME/aegis-tools/liboqs-src/build/tests"
stage acvp-vectors-intact  sh -c 'cd vectors/acvp && sha256sum -c --quiet SHA256SUMS'
if [ -n "$BOARD" ]; then
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
    [ -n "$WITH_EXPIRY" ] && stage endpoint-expiry endpoint_expiry
fi
echo "passed $pass, failed $fail -> $OUT"
[ "$fail" -eq 0 ]
