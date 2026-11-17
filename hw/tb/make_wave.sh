#!/usr/bin/env bash
# Rebuild docs/diagrams/wave-keccak.yaml from a real simulation run (needs Icarus Verilog).
set -euo pipefail
TB=$(cd "$(dirname "$0")" && pwd); ROOT=$(cd "$TB/../.." && pwd)
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
cat > "$T/dump.sv" <<EOT
module dump_tb;
  initial begin
    \$dumpfile("$T/trace.vcd");
    \$dumpvars(0, tb_aegis_pqc.PCLK, tb_aegis_pqc.PSEL, tb_aegis_pqc.PENABLE, tb_aegis_pqc.PWRITE, tb_aegis_pqc.PADDR);
    \$dumpvars(1, tb_aegis_pqc.dut);
  end
endmodule
EOT
iverilog -g2012 -I "$TB/vectors" -o "$T/t.vvp" -s tb_aegis_pqc -s dump_tb "$TB/tb_aegis_pqc.sv" "$T/dump.sv" "$ROOT"/hw/rtl/*.v
(cd "$TB" && vvp -n "$T/t.vvp" | tail -2)
python3 "$TB/extract_wave.py" "$T/trace.vcd" "$ROOT/docs/diagrams/wave-keccak.yaml"
