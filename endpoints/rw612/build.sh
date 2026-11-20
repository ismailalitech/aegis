#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Build (and optionally flash) the Aegis prover for the NXP FRDM-RW612.
#   endpoints/rw612/build.sh [flash]
# Needs: a Zephyr v4.5.0 workspace ($ZEPHYR_WS, default ~/aegis-tools/zephyrproject, modules hal_nxp and cmsis_6),
# Zephyr SDK 1.0.1, west in $WEST_VENV, mldsa-native / mlkem-native v2.0.0 in ~/aegis-tools, and for flashing the
# SEGGER J-Link software (the board's MCU-Link runs J-Link firmware). Output: $OUT/zephyr/zephyr.{bin,hex,elf}.
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
T=${AEGIS_TOOLS:-$HOME/aegis-tools}
WS=${ZEPHYR_WS:-$T/zephyrproject}
OUT=${OUT:-$T/nxp-build/prover}
export ZEPHYR_BASE=$WS/zephyr ZEPHYR_SDK_INSTALL_DIR=${ZEPHYR_SDK_INSTALL_DIR:-$T/zephyr-sdk-1.0.1}
export PATH=${WEST_VENV:-$T/zephyr-venv}/bin:${JLINK_DIR:-$T/jlink}:$PATH
cd "$WS"
west build -p always -b frdm_rw612 -d "$OUT" "$HERE/prover"
sha256sum "$OUT/zephyr/zephyr.bin"
if [ "${1:-}" = flash ]; then
	west flash -d "$OUT" -r jlink --tool-opt="-NoGui 1"
fi
