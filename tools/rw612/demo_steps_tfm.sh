#!/bin/sh
# The operator's steps in the recorded TrustZone demo (tools/rw612/record_demo.sh with STEPS=tfm): the good images
# run, a non-secure image changed by one byte is flashed, then the good one again. Fleet cycle: about 34 s.
#   demo_steps_tfm.sh <build dir with aegis_s/ and prover_ns/>
set -eu
B=$1
HERE=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$HERE/../.." && pwd)
S=$B/aegis_s/aegis_s.bin; NS=$B/prover_ns/prover_ns.bin
MOD=$(mktemp --suffix=.bin); trap 'rm -f "$MOD"' EXIT
python3 - "$NS" "$MOD" <<'PY'
import sys
d = bytearray(open(sys.argv[1], "rb").read()); i = d.find(b"AEGIS-RW612-TFM-PROVER"); d[i + 19] ^= 0x01
open(sys.argv[2], "wb").write(d)
PY
Bo=$(printf '\033[1m') R=$(printf '\033[0m') Y=$(printf '\033[33m')
say() { printf '%s\n' "$*"; }
nspe() { python3 "$ROOT/tools/rw612_tfm_reference.py" "$S" "$1" | awk '/NSPE/{print substr($2,1,16)}'; }
say "${Bo}Aegis on the RW612 with TrustZone${R}"
say "The key and the measurements are in the"
say "TF-M secure partition. The gateway allows"
say "  NSPE $(nspe "$NS")..."
say ""
say "${Y}1. The good images run${R}"
sleep 70
say ""
say "${Y}2. Flash a non-secure image changed by${R}"
say "${Y}   one byte (the banner text)${R}"
say "  NSPE $(nspe "$MOD")..."
"$ROOT/endpoints/rw612/tfm/flash.sh" "$S" "$MOD" > /dev/null && say "  flashed (both partitions written whole)"
sleep 75
say ""
say "${Y}3. Flash the good non-secure image again${R}"
"$ROOT/endpoints/rw612/tfm/flash.sh" "$S" "$NS" > /dev/null && say "  flashed"
sleep 80
say ""
say "${Bo}Same key all along; only the image changed.${R}"
sleep 4
