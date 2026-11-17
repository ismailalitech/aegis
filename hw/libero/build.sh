#!/bin/bash
# Build the Aegis fabric = pfdaq v0.5.x fabric (unchanged, from the pfdaq repository) + aegis_pqc in
# FIC3 APB slot 14 (0x40000E00).
#   hw/libero/build.sh <design_version> [rtl_dir]   (rtl_dir default: hw/rtl; hw/libero/stub for the stub)
# Output: build/libero/AEGIS_dv<ver>.job (FABRIC + SNVM only; never eNVM, keys or security settings).
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
PF=${PFDAQ_ROOT:?set PFDAQ_ROOT to the pfdaq repository checkout}
VER=${1:?design version required}
RTL=${2:-$ROOT/hw/rtl}
JOB=AEGIS_dv$VER
LIBERO=${LIBERO:-/usr/local/microchip/Libero_SoC_2026.1/Libero_SoC/Designer/bin/libero}
export LM_LICENSE_FILE=${LM_LICENSE_FILE:-1702@localhost}
export SNPSLMD_LICENSE_FILE=${SNPSLMD_LICENSE_FILE:-$LM_LICENSE_FILE}
REF=${PFDAQ_REFDESIGN:-$PF/build/disco-ref}
OUT=$ROOT/build/libero
WORK=$OUT/work
mkdir -p "$OUT"
[ -d "$REF" ] || { echo "reference design checkout missing: $REF"; exit 1; }
[ -d "$WORK" ] && mv "$WORK" "$OUT/work.old.$(date +%s)"
mkdir -p "$WORK"
( cd "$REF" && tar cf - --exclude=.git . ) | ( cd "$WORK" && tar xf - )

OV=$PF/hw/libero/overlay
( cd "$WORK" && patch -p1 --no-backup-if-mismatch < "$OV/reference-design-v2026.04.patch" )
# source the Aegis overlay right after PFDAQ.tcl
sed -i 's|^\(\s*\)safe_source script_support/additional_configurations/PFDAQ/PFDAQ.tcl|&\n\1safe_source script_support/additional_configurations/AEGIS/AEGIS_PQC.tcl|' \
    "$WORK/MPFS_DISCOVERY_KIT_REFERENCE_DESIGN.tcl"
grep -q 'AEGIS/AEGIS_PQC.tcl' "$WORK/MPFS_DISCOVERY_KIT_REFERENCE_DESIGN.tcl" || { echo "overlay hook failed"; exit 1; }
mkdir -p "$WORK/script_support/additional_configurations/PFDAQ" "$WORK/script_support/hdl/pfdaq" \
         "$WORK/script_support/additional_configurations/AEGIS" "$WORK/script_support/hdl/aegis"
cp "$OV/PFDAQ.tcl" "$WORK/script_support/additional_configurations/PFDAQ/"
cp "$OV/pfdaq_cdc.sdc" "$WORK/script_support/constraints/"
cp "$PF"/hw/rtl/*.v "$WORK/script_support/hdl/pfdaq/"
OVL=${AEGIS_OVERLAY:-AEGIS_PQC.tcl}            # file name in hw/libero, or an absolute path
case "$OVL" in /*) ;; *) OVL=$ROOT/hw/libero/$OVL ;; esac
cp "$OVL" "$WORK/script_support/additional_configurations/AEGIS/AEGIS_PQC.tcl"
cp "$RTL"/*.v "$WORK/script_support/hdl/aegis/"
cp "$PF/hw/libero/export_job.tcl" "$PF/hw/libero/sta_without_cdc.tcl" "$WORK/"

LOG=$OUT/build-dv$VER.log
cd "$WORK"
# DESIGN_ONLY=1: build the SmartDesign only (no synthesis, layout or timing), to check the wiring quickly
STEPS=AXI4_STREAM_DEMO+VERIFY_TIMING+DESIGN_VERSION:$VER
[ "${DESIGN_ONLY:-0}" = 1 ] && STEPS=AXI4_STREAM_DEMO+DESIGN_VERSION:$VER
"$LIBERO" script:MPFS_DISCOVERY_KIT_REFERENCE_DESIGN.tcl \
    SCRIPT_ARGS:$STEPS logfile:"$OUT/libero-dv$VER.log" > "$LOG" 2>&1 &
PID=$!
while kill -0 $PID 2>/dev/null; do
    if grep -q 'Error: SDC00' "$LOG"; then echo "ABORT: constraint error"; kill $PID || true; exit 1; fi
    io=$(grep -a -m1 'I/O Bank and Globals Assigner identified [0-9]* fixed' "$LOG" || true)
    if [ -n "$io" ] && ! echo "$io" | grep -q ' 0 unfixed'; then echo "ABORT: unplaced I/Os: $io"; kill $PID || true; exit 1; fi
    sleep 15
done
wait $PID || { echo "Libero failed, see $LOG"; exit 1; }
if [ "${DESIGN_ONLY:-0}" = 1 ]; then grep -a -iE "^Error|error:" "$LOG" | head -20; echo "design only: $WORK"; exit 0; fi
V="$WORK/PFDAQ/designer/MPFS_DISCOVERY_KIT/MPFS_DISCOVERY_KIT_has_violations"
grep -a -m1 'I/O Bank and Globals Assigner identified' "$LOG"
grep multi_corner "$V"
if grep multi_corner "$V" | grep -q violated; then echo "ABORT: timing violated"; exit 1; fi
grep -a -E '^\| (4LUT|DFF|Logic Element|uSRAM|LSRAM|Math)' "$WORK/PFDAQ/designer/MPFS_DISCOVERY_KIT/MPFS_DISCOVERY_KIT_layout_log.log" | sort -u
PFDAQ_JOB_NAME=$JOB PFDAQ_JOB_DIR=$OUT "$LIBERO" script:export_job.tcl > "$OUT/export-dv$VER.log" 2>&1
grep -a 'Fabric component bitstream digest' "$OUT/export-dv$VER.log"
ls -la "$OUT/$JOB.job"
