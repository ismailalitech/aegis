#!/bin/sh
# Aegis live demo on the bench, from the PC. About 4 minutes. Every verdict comes from the real
# boards: the PolarFire gateway (services aegisd + aegis-fleet) and the STM32H573 endpoint.
#
#   tools/demo.sh
#
# Steps
#   1. the PC checks the GATEWAY's own post-quantum quote (ML-DSA-65, fresh nonce)
#   2. the gateway attests the STM32 (TF-M token + ML-DSA-65 signature by a key derived from the
#      chip's hardware-unique key) -> ADMITTED, ML-KEM-768 credential and session, heartbeats
#   3. a TAMPERED Non-Secure image (signed with the trusted key, boots normally) is flashed
#      -> the gateway QUARANTINES it and revokes its credential
#   4. the good image is flashed back -> ADMITTED again with a NEW session
# Needs: the STM32 on the LAN (policy host = its Ethernet address),
# STM32CubeProgrammer, the artifacts in endpoints/stm32h573/artifacts/.
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
cd "$REPO"
PY=.venv/bin/python
GW=root@${GATEWAY:-192.0.2.10}
CLI=${CLI:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI}
A=endpoints/stm32h573/artifacts
GOOD=$A/prover-ns-0.4.0-hb.hex
BAD=${BAD:-$A/prover-ns-0.4.0-hb-tampered.hex}
LOG=logs/demo/$(date +%Y%m%d-%H%M%S); mkdir -p "$LOG"

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
journal_since() { ssh -o BatchMode=yes $GW "journalctl -u aegis-fleet --no-pager -o cat --since @$1" | sed 's/^[0-9:]* //'; }
wait_for() {  # wait_for <since> <regex> <seconds>
    end=$(( $(date +%s) + $3 ))
    while [ "$(date +%s)" -lt "$end" ]; do
        line=$(journal_since "$1" | grep -E "$2" | tail -1 || true)
        [ -n "$line" ] && { echo "   gateway: $line"; return 0; }
        sleep 5
    done
    echo "   (no '$2' within $3 s)"; return 1
}
flash() { "$CLI" -c port=SWD mode=UR -d "$1" -v 2>&1 | sed 's/\x1b\[[0-9;]*m//g' | grep -q 'verified successfully' \
          && "$CLI" -c port=SWD mode=HOTPLUG -hardRst > /dev/null 2>&1; }

[ -f "$BAD" ] || { echo "missing $BAD (build: SPE=... prover-ns/build.sh -DAEGIS_PROVER_VERSION=0.4.0-tampered)"; exit 1; }

say "1. The PC verifies the gateway's own quote (ML-DSA-65, fresh nonce)"
$PY host/aegis_verify.py quote ${GATEWAY:-192.0.2.10} | tee "$LOG/1-gateway-quote.json" | grep -E 'accepted|sig_bytes'

say "2. The gateway attests the STM32 and keeps its ML-KEM session alive"
ssh -o BatchMode=yes $GW 'cd /root/aegis/gateway/aegisd && python3 fleet.py once ../policy/fleet.json --no-credentials' \
    > "$LOG/2-attest.json"
grep -E '"admitted"|pq_signature' "$LOG/2-attest.json" | sed 's/^/   /'
T=$(ssh -o BatchMode=yes $GW date +%s)
wait_for "$T" 'ADMITTED.*credential: (issued|valid)' 75

say "2b. A legacy node that cannot attest (Arduino Uno, via the PC)"
T0=$(ssh -o BatchMode=yes $GW date +%s)
wait_for "$(( T0 - 40 ))" 'arduino-uno-legacy QUARANTINED' 45 || true

say "3. Flash a TAMPERED Non-Secure image (validly signed, boots normally)"
T=$(ssh -o BatchMode=yes $GW date +%s)
flash "$BAD" && echo "   tampered image running"
wait_for "$T" 'QUARANTINED.*credential: revoked' 90
ssh -o BatchMode=yes $GW 'ls /var/lib/aegis/credentials/ | wc -l' | sed 's/^/   credential files left on the gateway: /'

say "4. Flash the good image back"
T=$(ssh -o BatchMode=yes $GW date +%s)
flash "$GOOD" && echo "   good image running"
wait_for "$T" 'ADMITTED.*credential: issued' 120
wait_for "$T" 'ADMITTED.*credential: valid, heartbeat' 60
ssh -o BatchMode=yes $GW 'cd /root/aegis/gateway/aegisd && python3 fleet.py session ../policy/fleet.json' \
    | grep -E 'same_' | sed 's/^/   /'

say "Gateway journal for this run"
journal_since "$(( $(date +%s) - 300 ))" | tail -12 | tee "$LOG/journal.txt" | sed 's/^/   /'
echo; echo "log: $LOG"
