#!/bin/sh
# Negative test of the Aegis peripheral rules on the FRDM-RW612: build the non-secure prover with a probe that reads
# one register of a peripheral from the non-secure side, flash it with the normal secure image, and record the console.
# A peripheral that endpoints/rw612/tfm/aegis_s/platform/target_cfg.c makes secure-only must fault (no "read ok").
#   endpoints/rw612/tfm/probe.sh <out dir> NAME=0xADDR [NAME=0xADDR ...]
# Leaves the last probe image on the board: flash the normal images afterwards.
set -eu
OUT=${1:?out dir}; shift
SDK=${MCUXSDK:-$HOME/aegis-tools/mcuxsdk/mcuxsdk}
HERE=$(cd "$(dirname "$0")" && pwd)
TTY=${RW612_TTY:-$(ls /dev/serial/by-id/usb-SEGGER_J-Link_*-if00 | head -1)}
export ARMGCC_DIR=${ARMGCC_DIR:-$HOME/aegis-tools/arm-gnu-toolchain-14.2.rel1-x86_64-arm-none-eabi}
export PATH=${WEST_VENV:-$HOME/aegis-tools/zephyr-venv}/bin:$PATH
mkdir -p "$OUT"
for t in "$@"; do
	name=${t%%=*}; addr=${t#*=}
	B=$OUT/build-$name
	(cd "$SDK" && AEGIS_NS_EXTRA_DEFINES="-DAEGIS_NS_PROBE_ADDR=$addr -DAEGIS_NS_PROBE_NAME=\\\"$name\\\"" \
		west build -p always --sysbuild "$HERE/prover_ns" --toolchain armgcc --config release -b frdmrw612 -d "$B" \
		> "$OUT/build-$name.log" 2>&1)
	python3 - "$TTY" "$OUT/console-$name.txt" 40 <<'PY' &
import re, sys, time, serial
s = serial.Serial(sys.argv[1], 115200, timeout=0.2); end = time.time() + float(sys.argv[3]); out = b""
while time.time() < end:
    out += s.read(4096)
t = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out.decode(errors="replace")).replace("\r", "")
t = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<lan address>", t)
open(sys.argv[2], "w").write(t)
PY
	sleep 1
	"$HERE/flash.sh" "$B/aegis_s/aegis_s.bin" "$B/prover_ns/prover_ns.bin" > /dev/null
	wait
	if grep -q "aegis-probe: read ok" "$OUT/console-$name.txt"; then r="READ ALLOWED"; else r="no read (fault)"; fi
	echo "$name $addr: $r"
done
