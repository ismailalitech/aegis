#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Run every check for hw/: Python model self-tests, ROM freshness, vector
# generation, RTL unit test and the APB system test (Icarus Verilog).
# Exits non-zero on the first failure.
#
#   hw/tb/run_all.sh            full run
#   hw/tb/run_all.sh --fast     skip the ~6 s exhaustive ML-DSA Barrett sweep
#
# Environment: PYTHON (default: ../../.venv/bin/python if present, else python3)

set -euo pipefail

TB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HW_DIR="$(cd "$TB_DIR/.." && pwd)"
if [[ -z "${PYTHON:-}" ]]; then
    if [[ -x "$HW_DIR/../.venv/bin/python" ]]; then
        PYTHON="$HW_DIR/../.venv/bin/python"
    else
        PYTHON=python3
    fi
fi
FAST=""
[[ "${1:-}" == "--fast" ]] && FAST="--fast"

IVFLAGS=(-g2012 -Wall)
BUILD="$TB_DIR/build"
mkdir -p "$BUILD"

step() { printf '\n=== %s\n' "$*"; }

# Compile and fail on any compiler warning as well as on errors.
compile() {
    local out="$1"; shift
    local log="$BUILD/$(basename "$out" .vvp).iverilog.log"
    if ! iverilog "${IVFLAGS[@]}" -I "$TB_DIR/vectors" -o "$out" "$@" >"$log" 2>&1; then
        cat "$log"; echo "iverilog failed"; exit 1
    fi
    if [[ -s "$log" ]]; then
        cat "$log"; echo "iverilog produced warnings"; exit 1
    fi
}

RTL=(
    "$HW_DIR/rtl/aegis_pqc.v"
    "$HW_DIR/rtl/aegis_keccak.v"
    "$HW_DIR/rtl/aegis_keccak_round.v"
    "$HW_DIR/rtl/aegis_ntt.v"
    "$HW_DIR/rtl/aegis_modmul.v"
    "$HW_DIR/rtl/aegis_ram_sdp.v"
    "$HW_DIR/rtl/aegis_ntt_rom.v"
)

step "Python models"
(cd "$HW_DIR/model" && "$PYTHON" keccak.py)
(cd "$HW_DIR/model" && "$PYTHON" ntt.py)
(cd "$HW_DIR/model" && "$PYTHON" ntt_hw.py $FAST)

step "Twiddle ROM is up to date"
(cd "$HW_DIR/model" && "$PYTHON" gen_rom.py --check)

step "Generate vectors"
"$PYTHON" "$TB_DIR/gen_vectors.py"
"$PYTHON" "$TB_DIR/gen_sponge_vectors.py"

# Run a simulation; it must exit 0 AND print "<name>: PASS".
simulate() {
    local name="$1" vvp="$2"
    local log="$BUILD/$name.log"
    (cd "$TB_DIR" && vvp -n "$vvp") 2>&1 | tee "$log"
    if ! grep -q "^$name: PASS\$" "$log"; then
        echo "$name: no PASS line"; exit 1
    fi
}

step "RTL unit test: aegis_modmul"
compile "$BUILD/tb_modmul.vvp" -s tb_modmul "$TB_DIR/tb_modmul.sv" "$HW_DIR/rtl/aegis_modmul.v"
simulate tb_modmul "$BUILD/tb_modmul.vvp"

step "RTL system test: aegis_pqc over APB"
compile "$BUILD/tb_aegis_pqc.vvp" -s tb_aegis_pqc "$TB_DIR/tb_aegis_pqc.sv" "${RTL[@]}"
simulate tb_aegis_pqc "$BUILD/tb_aegis_pqc.vvp"

step "RTL system test: aegis_pqc2 (sponge, slots, DMA squeeze) over APB with an AXI memory model"
RTL2=("$HW_DIR/rtl/aegis_pqc2.v" "$HW_DIR/rtl/aegis_sponge.v" "${RTL[@]:2}")
compile "$BUILD/tb_aegis_pqc2.vvp" -s tb_aegis_pqc2 "$TB_DIR/tb_aegis_pqc2.sv" "${RTL2[@]}"
simulate tb_aegis_pqc2 "$BUILD/tb_aegis_pqc2.vvp"

step "ALL PASS"
