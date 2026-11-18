#!/bin/sh
# Flash the Aegis TF-M images on the FRDM-RW612 through its MCU-Link (J-Link firmware).
#   endpoints/rw612/tfm/flash.sh <secure .bin> <non-secure .bin>
# Halts the chip under reset first (a running TF-M blocks J-Link's flash loader), erases the whole secure and
# non-secure partitions (0x08000000-0x0839FFFF: the Aegis partition hashes both partitions whole, so the reference
# value is each image padded with 0xFF), then writes the secure image at 0x08000400 (its .bin starts with the flash
# config block) and the non-secure image at 0x080A0000, verifies both and resets. Nothing else is touched: TF-M's
# storage (0x083A0000-0x083E3FFF), the Wi-Fi firmware (0x08400000) and every fuse stay as they are.
set -eu
S=${1:?secure .bin}; NS=${2:?non-secure .bin}
J=${JLINK_DIR:-$HOME/aegis-tools/jlink}/JLinkExe
T=$(mktemp)
trap 'rm -f "$T"' EXIT
cat > "$T" <<EOS
r
h
erase 0x08000000 0x083A0000
loadbin $S 0x08000400
loadbin $NS 0x080A0000
verifybin $S 0x08000400
verifybin $NS 0x080A0000
r
g
exit
EOS
# J-Link's flash loader sometimes times out right after a running TF-M is reset ("RAMCode did not respond in
# time"); a second attempt has always worked.
for attempt in 1 2; do
	"$J" -NoGui 1 -device RW612 -if SWD -speed 4000 -autoconnect 1 -CommandFile "$T" > "$T.log" 2>&1 || true
	if [ "$(grep -c 'Verify successful' "$T.log")" -eq 2 ] && ! grep -qE "RAMCode|Unspecified error|Verification failed" "$T.log"; then
		break
	fi
	[ $attempt -eq 2 ] && { tail -20 "$T.log"; rm -f "$T.log"; exit 1; }
	echo "flash attempt $attempt failed, retrying"
done
grep -c "Verifying flash.*Done" "$T.log" | xargs -I{} echo "flashed and verified ({} write passes)"
rm -f "$T.log"
