#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Replace an STM32H573I-DK's secure image (the TF-M slot only) and move the gateway's policy with it, as done for
# board 2 on 18 November 2026 (evidence/stm32-kemfix/board2-kemfix.txt):
#   1. checks: one ST-LINK with that serial; the new image is a signed MCUboot image with the same version and signer
#      as the running one (so MCUboot's security counter accepts it)
#   2. backup under reset: both 2 MiB flash views and the option bytes, plus the merged image that
#      restore_from_backup.sh cuts its slots from, all checksummed; its secure slot must measure as a value the
#      policy allows for this endpoint (the image running now)
#   3. the gateway policy allows the new SPE next to the old one (the policy file is copied aside first)
#   4. the image is written to the secure slot (0x0C038000), verified, the board reset
#   5. the gateway must admit the endpoint again; then the old SPE is removed, and it must be admitted once more
# It stops before writing anything if a check fails. If the endpoint is not admitted, it prints the rollback.
# Writes only the secure slot: not BL2, the option bytes, the NV counters or OTP.
#   upgrade_secure.sh <endpoint name in the policy> <ST-LINK serial> <tfm_s_signed.hex>
# Example (board 1, the image with the KEM_INIT fix):
#   upgrade_secure.sh stm32h573-dk "$STM32_SN" endpoints/stm32h573/artifacts/tfm-s-v2.3.0-aegis-pq-hb-hedged-kmac-kemfix.hex
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
[ -f "$REPO/bench.env" ] && { set -a; . "$REPO/bench.env"; set +a; }
EP=${1:?endpoint name}; SN=${2:?ST-LINK serial}; HEX=${3:?signed secure image (.hex)}
GW=root@${GATEWAY:?set GATEWAY in bench.env}
CLI=${CLI:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI}
PY=$REPO/.venv/bin/python
POLICY=/root/aegis/gateway/policy/fleet.json
STAMP=$(date +%Y%m%d-%H%M%S)
BK=$REPO/backups/stm32h573/$STAMP-$EP-before-upgrade
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
cli() { "$CLI" -c port=SWD sn=$SN "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
step() { echo "== $*"; }

step "1. checks"
"$CLI" -l st 2>/dev/null | sed 's/\x1b\[[0-9;]*m//g' | grep -q "ST-LINK SN *: *$SN" || { echo "no ST-LINK $SN connected"; exit 1; }
OBJCOPY=${OBJCOPY:-$(ls -d "$HOME"/st/stm32cubeide_*/plugins/*gnu-tools-for-stm32*/tools/bin/arm-none-eabi-objcopy 2>/dev/null | head -1)}
"$OBJCOPY" -I ihex -O binary "$HEX" "$TMP/new.bin"
head -c 4 "$TMP/new.bin" | od -An -tx1 | grep -q "3d b8 f3 96" || { echo "$HEX is not an MCUboot image"; exit 1; }
NEW=$("$PY" "$REPO/tools/image_measurement.py" "$TMP/new.bin")
NEW_SPE=$(echo "$NEW" | "$PY" -c 'import json,sys; print(list(json.load(sys.stdin).values())[0]["measurement_value"])')
echo "new image: SPE $NEW_SPE"

step "2. backup to $BK"
mkdir -p "$BK"
cli mode=UR -r 0x0C000000 0x200000 "$BK/flash_s_alias.bin" > "$BK/read_s.log"
cli mode=UR -r 0x08000000 0x200000 "$BK/flash_ns_alias.bin" > "$BK/read_ns.log"
cli mode=UR -ob displ > "$BK/option_bytes.txt"
cli mode=HOTPLUG -hardRst > /dev/null
! grep -q "Error" "$BK/read_s.log" "$BK/read_ns.log" "$BK/option_bytes.txt" || { echo "backup failed, see $BK"; exit 1; }
"$PY" - "$BK" <<'EOF'
import sys
d = sys.argv[1]
s = open(d + "/flash_s_alias.bin", "rb").read()
n = bytearray(open(d + "/flash_ns_alias.bin", "rb").read())
n[0x38000:0x88000] = s[0x38000:0x88000]   # the secure slot, where restore_from_backup.sh cuts it
open(d + "/flash_merged.bin", "wb").write(n)
open(d + "/s_slot.bin", "wb").write(s[0x38000:0x88000])
EOF
(cd "$BK" && sha256sum flash_s_alias.bin flash_ns_alias.bin flash_merged.bin > SHA256SUMS)
OLD=$("$PY" "$REPO/tools/image_measurement.py" "$BK/s_slot.bin")
OLD_SPE=$(echo "$OLD" | "$PY" -c 'import json,sys; print(list(json.load(sys.stdin).values())[0]["measurement_value"])')
same() { echo "$1" | "$PY" -c 'import json,sys; v=list(json.load(sys.stdin).values())[0]; print(v["version"], v["signer_id"])'; }
[ "$(same "$OLD")" = "$(same "$NEW")" ] || { echo "version or signer differ: running $(same "$OLD"), new $(same "$NEW")"; exit 1; }
rm "$BK/s_slot.bin"
echo "running image: SPE $OLD_SPE (same version and signer as the new one)"
[ "$OLD_SPE" != "$NEW_SPE" ] || { echo "the board already runs this image"; exit 0; }
ssh -o BatchMode=yes "$GW" "python3 -c \"
import json, sys
p = json.load(open('$POLICY'))
e = [x for x in p['endpoints'] if x['name'] == '$EP']
sys.exit(0 if e and any(a.get('measurement_value') == '$OLD_SPE' for a in e[0]['allowed']) else 'the policy for $EP does not allow the running SPE')
\""

policy() {   # policy add|remove <spe>
	ssh -o BatchMode=yes "$GW" "python3 -c \"
import json
p = json.load(open('$POLICY'))
e = [x for x in p['endpoints'] if x['name'] == '$EP'][0]
if '$1' == 'add':
    e['allowed'].append({'type': 'SPE', 'measurement_value': '$2'})
else:
    e['allowed'] = [a for a in e['allowed'] if a.get('measurement_value') != '$2']
json.dump(p, open('$POLICY', 'w'), indent=1)
print('allowed for $EP:', [(a['type'], a['measurement_value'][:12]) for a in e['allowed']])
\""
}
gw_now() { ssh -o BatchMode=yes "$GW" "date '+%Y-%m-%d %H:%M:%S'"; }
# wait_admitted <gateway time> any|second: wait (up to 3 minutes) for the gateway's verdicts on the endpoint after that
# time. any: succeed on the first ADMITTED. second: the second verdict decides (a cycle already running when the
# policy changed still used the old policy; the policy is reloaded at the start of each cycle).
wait_admitted() {
	i=0
	while [ $i -lt 18 ]; do
		v=$(ssh -o BatchMode=yes "$GW" "journalctl -u aegis-fleet --since '$1' -o cat" | grep "^[0-9:]* $EP " || true)
		n=$(printf '%s\n' "$v" | grep -c . || true)
		if [ "$2" = any ] && printf '%s\n' "$v" | grep -q " $EP ADMITTED"; then
			printf '%s\n' "$v" | sed 's/^/  /' | cut -c1-150; return 0
		fi
		if [ "$2" = second ] && [ "$n" -ge 2 ]; then
			printf '%s\n' "$v" | sed 's/^/  /' | cut -c1-150
			printf '%s\n' "$v" | sed -n 2p | grep -q " $EP ADMITTED"; return
		fi
		sleep 10; i=$((i + 1))
	done
	printf '%s\n' "$v" | sed 's/^/  /' | cut -c1-150
	return 1
}

step "3. policy: allow the new SPE ($GW:$POLICY.bak-$STAMP)"
ssh -o BatchMode=yes "$GW" "cp $POLICY $POLICY.bak-$STAMP"
policy add "$NEW_SPE"

step "4. write the secure slot"
cli mode=UR -d "$HEX" -v | grep -q "Download verified successfully" || { echo "write not verified; restore: STM32_SN=$SN $REPO/endpoints/stm32h573/restore_from_backup.sh $BK"; exit 1; }
cli mode=HOTPLUG -hardRst > /dev/null
T1=$(gw_now)
echo "written and verified, reset at $T1 (gateway time)"

step "5. the gateway must admit $EP again"
if ! wait_admitted "$T1" any; then
	echo "NOT admitted. Roll back with:"
	echo "  STM32_SN=$SN $REPO/endpoints/stm32h573/restore_from_backup.sh $BK"
	echo "  ssh $GW cp $POLICY.bak-$STAMP $POLICY"
	exit 1
fi
policy remove "$OLD_SPE"
T2=$(gw_now)
wait_admitted "$T2" second || { echo "admitted with both values allowed, not with the new one alone: see the journal"; exit 1; }
echo "done: $EP runs SPE $NEW_SPE; backup $BK"
