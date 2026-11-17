#!/usr/bin/env bash
# Rebuild docs/diagrams/wave-sponge-dma.yaml from a real simulation run of tb_aegis_pqc2 (needs Icarus Verilog).
set -euo pipefail
TB=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$TB/../.." && pwd)
PY=${PYTHON:-python3}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
[ -f "$TB/vectors/sponge_ops.txt" ] || "$PY" "$TB/gen_sponge_vectors.py" > /dev/null
cat > "$T/dump.sv" <<EOT
module dump_tb;
  initial begin
    \$dumpfile("$T/trace.vcd");
    \$dumpvars(1, tb_aegis_pqc2);
    \$dumpvars(1, tb_aegis_pqc2.dut);
  end
endmodule
EOT
R=$ROOT/hw/rtl
iverilog -g2012 -o "$T/t.vvp" -s tb_aegis_pqc2 -s dump_tb "$TB/tb_aegis_pqc2.sv" "$T/dump.sv" \
    "$R/aegis_pqc2.v" "$R/aegis_sponge.v" "$R/aegis_keccak_round.v" "$R/aegis_ntt.v" "$R/aegis_modmul.v" \
    "$R/aegis_ram_sdp.v" "$R/aegis_ntt_rom.v"
(cd "$TB" && vvp -n "$T/t.vvp" | grep "tb_aegis_pqc2: PASS")
"$PY" "$TB/extract_wave_dma.py" "$T/trace.vcd" "$ROOT/docs/diagrams/wave-sponge-dma.yaml"
