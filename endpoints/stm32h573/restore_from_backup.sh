#!/bin/sh
# Put the STM32H573I-DK's secure and non-secure image slots back exactly as they were in a
# backup taken by CubeProgrammer under reset (backups/stm32h573/<date>-cubeprog-UR/flash_merged.bin).
# Writes only the two primary slots: S 0x0C038000 (0x50000) and NS 0x08088000 (0x90000).
# BL2, option bytes, NV counters and protected storage are not touched.
#   restore_from_backup.sh [backup_dir]
set -eu
REPO=$(cd "$(dirname "$0")/../.." && pwd)
DIR=${1:-$(ls -d "$REPO"/backups/stm32h573/*-cubeprog-UR | head -1)}
CLI=${CLI:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI}
SN=${STM32_SN:?set STM32_SN: the ST-LINK serial of the board to restore (two may be connected)}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
(cd "$DIR" && sha256sum -c --quiet SHA256SUMS)
dd if="$DIR/flash_merged.bin" of="$TMP/s_slot.bin" bs=4096 skip=$((0x38000 / 4096)) count=$((0x50000 / 4096)) status=none
dd if="$DIR/flash_merged.bin" of="$TMP/ns_slot.bin" bs=4096 skip=$((0x88000 / 4096)) count=$((0x90000 / 4096)) status=none
"$CLI" -c port=SWD sn=$SN mode=UR -w "$TMP/s_slot.bin" 0x0C038000 -v | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'verified|Error'
"$CLI" -c port=SWD sn=$SN mode=UR -w "$TMP/ns_slot.bin" 0x08088000 -v | sed 's/\x1b\[[0-9;]*m//g' | grep -E 'verified|Error'
"$CLI" -c port=SWD sn=$SN mode=HOTPLUG -hardRst > /dev/null
echo "restored slots from $DIR"
