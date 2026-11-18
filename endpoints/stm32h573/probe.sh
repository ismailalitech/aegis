#!/bin/sh
# Negative test of the STM32H573's TrustZone configuration (TF-M v2.3.0 with the Aegis partition): build the
# non-secure prover with a probe that reads one word from the non-secure side right after start-up, write it to the
# non-secure slot, and record the console. Secure memory and secure-only peripherals must not give their contents:
# the read either faults (TF-M resets the chip, the read never returns) or returns zero (GTZC read-as-zero).
# The real secure values are read first over SWD (the debugger sees the secure view in product state Open), so a
# zero can be told apart from the real contents. After each probe it records the GTZC illegal-access flags.
#   STM32_SN=<ST-LINK serial> endpoints/stm32h573/probe.sh <out dir> NAME=0xADDR [NAME=0xADDR ...]
#   STM32_SN=<ST-LINK serial> endpoints/stm32h573/probe.sh <out dir> --saes
#     runs the secure partition's key derivation (AES-256-ECB under the DHUK in SAES) from the non-secure side
#     instead: it must fail. The console keeps only the status line, never an output.
# Afterwards it writes back the normal prover image (artifacts/prover-ns-0.5.0-mac.hex, NSPE 34637a4e...).
set -eu
OUT=${1:?out dir}; shift
SN=${STM32_SN:?ST-LINK serial}
HERE=$(cd "$(dirname "$0")" && pwd)
CLI=${CLI:-$HOME/STMicroelectronics/STM32Cube/STM32CubeProgrammer/bin/STM32_Programmer_CLI}
TTY=${STM32_TTY:-$(ls /dev/serial/by-id/usb-STMicroelectronics_STLINK-V3_${SN}-if0* 2>/dev/null | head -1)}
[ -n "$TTY" ] || { echo "no ST-LINK console for $SN" >&2; exit 1; }
SPE=${SPE:-$HOME/aegis-tools/tfm-aegis-build-kmac/api_ns}
NORMAL=$HERE/artifacts/prover-ns-0.5.0-mac.hex
PY=$HERE/../../.venv/bin/python
cli() { "$CLI" -c port=SWD sn=$SN "$@" 2>&1 | sed 's/\x1b\[[0-9;]*m//g'; }
mkdir -p "$OUT"
capture() {   # capture <file> <seconds>
	python3 - "$TTY" "$1" "$2" <<'PY'
import re, sys, time, serial
s = serial.Serial(sys.argv[1], 115200, timeout=0.2); end = time.time() + float(sys.argv[3]); out = b""
while time.time() < end:
    out += s.read(4096)
t = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", out.decode(errors="replace")).replace("\r", "")
t = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<lan address>", t)
t = re.sub(r"mac=([0-9a-f]{2}:){5}[0-9a-f]{2}", "mac=<mac>", t)
t = re.sub(r"(aegis-saes: output )[0-9a-f]+", r"\1<removed>", t)
open(sys.argv[2], "w").write(t)
PY
}
if [ "${1:-}" = --saes ]; then
	(cd "$HERE/prover-ns" && SPE=$SPE ./build.sh -DAEGIS_NS_SAES_TEST=ON > "$OUT/build-saes.log" 2>&1)
	cp "$HERE/prover-ns/build/bin/tfm_ns_signed.hex" "$OUT/saes-test.hex"
	capture "$OUT/console-saes.txt" 30 &
	sleep 1
	cli mode=UR -d "$OUT/saes-test.hex" -v | grep -q "Download verified successfully" || { echo "saes: write failed"; exit 1; }
	cli mode=HOTPLUG -hardRst > /dev/null
	wait
	tzic=$(cli mode=HOTPLUG -r32 0x50032810 16 | grep -oiE "^0x50032810 *: *.*" | cut -d: -f2 | xargs)
	line=$(grep "aegis-saes: init=" "$OUT/console-saes.txt" || echo "no status line")
	if grep -q "aegis-saes: output" "$OUT/console-saes.txt"; then r="SAES ENCRYPTED UNDER THE DHUK FROM THE NON-SECURE SIDE"
	elif grep -q "encrypt=0" "$OUT/console-saes.txt"; then r="SAES ENCRYPTED UNDER THE DHUK FROM THE NON-SECURE SIDE"
	else r="refused"; fi
	echo "SAES-DHUK: $r ($line); TZIC SR1-4: $tzic" | tee -a "$OUT/summary.txt"
	set --
fi
for t in "$@"; do
	name=${t%%=*}; addr=${t#*=}
	real=$(cli mode=HOTPLUG -r32 "$addr" 4 | grep -oiE "^0x[0-9a-f]+ *: *[0-9a-f]+" | awk '{print $NF}' | head -1)
	(cd "$HERE/prover-ns" && SPE=$SPE ./build.sh -DAEGIS_NS_PROBE_ADDR="$addr" -DAEGIS_NS_PROBE_NAME="$name" \
		> "$OUT/build-$name.log" 2>&1) || { echo "$name: build failed, see $OUT/build-$name.log"; exit 1; }
	cp "$HERE/prover-ns/build/bin/tfm_ns_signed.hex" "$OUT/probe-$name.hex"
	capture "$OUT/console-$name.txt" 40 &
	sleep 1
	cli mode=UR -d "$OUT/probe-$name.hex" -v | grep -q "Download verified successfully" || { echo "$name: write failed"; exit 1; }
	cli mode=HOTPLUG -hardRst > /dev/null
	wait
	# GTZC illegal-access flags (TZIC1 SR1-SR4, secure view): which secure resource the non-secure read hit
	tzic=$(cli mode=HOTPLUG -r32 0x50032810 16 | grep -oiE "^0x50032810 *: *.*" | cut -d: -f2 | xargs)
	tries=$(grep -c "aegis-probe: non-secure read" "$OUT/console-$name.txt" || true)
	boots=$(grep -c "AEGIS-PROVER" "$OUT/console-$name.txt" || true)
	got=$(grep -o "aegis-probe: read ok, value 0x[0-9a-f]*" "$OUT/console-$name.txt" | head -1 | awk '{print $NF}')
	if [ -n "$got" ]; then
		if [ "$((got))" = "$((0x${real:-0}))" ] && [ "$((got))" != 0 ]; then r="READ ALLOWED: returned the real value $got"
		elif [ "$((got))" = 0 ]; then r="no read (read as zero; secure value 0x$real)"
		else r="read returned $got (secure view 0x$real)"; fi
	elif [ "$tries" -ge 2 ] && [ "$boots" -ge "$tries" ]; then r="no read (fault: $tries attempts, $boots boots)"
	else r="INCONCLUSIVE ($tries attempts, $boots boots)"; fi
	echo "$name $addr: $r; TZIC SR1-4: $tzic" | tee -a "$OUT/summary.txt"
done
# written back, then reset twice: once seen not to come back on the network after a single reset
cli mode=UR -d "$NORMAL" -v | grep -q "Download verified successfully" && cli mode=HOTPLUG -hardRst > /dev/null \
	&& sleep 3 && cli mode=HOTPLUG -hardRst > /dev/null \
	&& echo "normal prover written back ($NORMAL)" | tee -a "$OUT/summary.txt"
