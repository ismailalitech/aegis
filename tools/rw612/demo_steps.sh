#!/bin/sh
# The operator's steps in the recorded demo (tools/rw612/record_demo.sh): the good image runs, a modified image is
# flashed (one configuration value changed), then the good image again. Fleet cycle: about 34 s.
#   demo_steps.sh <good build dir> <modified build dir>
set -eu
GOOD=$1 BAD=$2
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
export ZEPHYR_BASE=$T/zephyrproject/zephyr PATH=$T/zephyr-venv/bin:$T/jlink:$PATH
B=$(printf '\033[1m') R=$(printf '\033[0m') Y=$(printf '\033[33m')
say() { printf '%s\n' "$*"; }
flash() { (cd "$T/zephyrproject" && west flash -d "$1" -r jlink --tool-opt="-NoGui 1" > /dev/null 2>&1) && say "  flashed through the board's MCU-Link"; }
short() { sha256sum "$1/zephyr/zephyr.bin" | cut -c1-16; }

say "${B}Aegis: NXP FRDM-RW612, a modified image${R}"
say "The ML-DSA-65 key comes from the chip (ELS)."
say "The gateway pins it, and allows one image:"
say "  APP sha256 $(short "$GOOD")..."
say ""
say "${Y}1. The good image runs${R}"
sleep 70
say ""
say "${Y}2. Flash a modified image${R}"
say "  the same prover, one setting changed"
say "  (CONFIG_NET_HOSTNAME)"
say "  APP sha256 $(short "$BAD")..."
flash "$BAD"
sleep 75
say ""
say "${Y}3. Flash the good image again${R}"
flash "$GOOD"
sleep 80
say ""
say "${B}Same key all along; only the image changed.${R}"
sleep 4
