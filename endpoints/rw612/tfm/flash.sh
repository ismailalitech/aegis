#!/bin/sh
# Flash the Aegis TF-M images on the FRDM-RW612 through its MCU-Link (J-Link firmware).
#   endpoints/rw612/tfm/flash.sh <secure .bin> <non-secure .bin>
# Halts the chip under reset first (a running TF-M blocks J-Link's flash loader), then writes each partition WHOLE:
# the secure image padded with 0xFF from 0x08000400 to 0x0809FFFF (its .bin starts with the flash config block) and
# the non-secure image padded with 0xFF from 0x080A0000 to 0x0839FFFF. The Aegis partition hashes both partitions
# whole, so the flash must be exactly image + 0xFF (tools/rw612_tfm_reference.py computes the same). J-Link's range
# erase was not enough: blocks from an earlier, larger image survived it. Then verifies both and resets. Nothing else is touched: TF-M's
# storage (0x083A0000-0x083E3FFF), the Wi-Fi firmware (0x08400000) and every fuse stay as they are.
set -eu
S=${1:?secure .bin}; NS=${2:?non-secure .bin}
J=${JLINK_DIR:-$HOME/aegis-tools/jlink}/JLinkExe
T=$(mktemp)
SP=$(mktemp --suffix=.bin); NP=$(mktemp --suffix=.bin)
trap 'rm -f "$T" "$SP" "$NP"' EXIT
python3 - "$S" "$NS" "$SP" "$NP" <<'PY'
import sys
s, ns = open(sys.argv[1], "rb").read(), open(sys.argv[2], "rb").read()
if len(s) > 0xA0000 - 0x400 or len(ns) > 0x300000:
    sys.exit("image larger than its partition")
open(sys.argv[3], "wb").write(s + b"\xff" * (0xA0000 - 0x400 - len(s)))
open(sys.argv[4], "wb").write(ns + b"\xff" * (0x300000 - len(ns)))
PY
cat > "$T" <<EOS
r
h
loadbin $SP 0x08000400
loadbin $NP 0x080A0000
verifybin $SP 0x08000400
verifybin $NP 0x080A0000
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
