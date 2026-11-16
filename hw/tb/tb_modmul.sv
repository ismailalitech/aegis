// SPDX-License-Identifier: Apache-2.0
//
// Unit test for rtl/aegis_modmul.v: streams one (a, b) pair per clock and
// compares p, LAT = 4 clocks later, against a*b mod q from the Python model
// (vectors/modmul.hex: {mode, a, b, expected}, 24 bits each). Vectors are
// grouped by mode; the pipeline is drained before the mode changes.
//
// Timing: inputs change at the falling edge; a pair presented at falling
// edge n is sampled by the rising edge after it, and p holds its result from
// the LAT-th rising edge on, i.e. at falling edge n + LAT.

`timescale 1ns / 1ps

module tb_modmul;

    `include "params.svh"

    localparam integer LAT = 4;

    reg         clk = 1'b0;
    reg         mode = 1'b0;
    reg  [22:0] a = 23'd0, b = 23'd0;
    wire [22:0] p;

    aegis_modmul dut (.clk(clk), .mode(mode), .a(a), .b(b), .p(p));

    always #10 clk = ~clk;

    reg [95:0] vec [0:NM-1];
    reg [22:0] exp_q [0:LAT-1];    // [n] = pair presented n falling edges ago
    reg        exp_v [0:LAT-1];
    integer    i, k, n, errors, checked, cycles;

    initial begin
        $readmemh("vectors/modmul.hex", vec);
        errors  = 0;
        checked = 0;
        cycles  = 0;
        for (k = 0; k < LAT; k = k + 1) begin
            exp_v[k] = 1'b0;
            exp_q[k] = 23'd0;
        end
        i = 0;
        @(negedge clk);
        while (i < NM || exp_v[0] || exp_v[1] || exp_v[2] || exp_v[3]) begin
            // result of the pair presented LAT falling edges ago
            if (exp_v[LAT-1]) begin
                checked = checked + 1;
                if (p !== exp_q[LAT-1]) begin
                    errors = errors + 1;
                    if (errors <= 10)
                        $display("tb_modmul: MISMATCH mode=%0d got %0d expected %0d",
                                 mode, p, exp_q[LAT-1]);
                end
            end
            for (k = LAT - 1; k > 0; k = k - 1) begin
                exp_v[k] = exp_v[k-1];
                exp_q[k] = exp_q[k-1];
            end
            exp_v[0] = 1'b0;
            n = 0;
            for (k = 1; k < LAT; k = k + 1)
                n = n + exp_v[k];
            // present the next pair, unless a mode change must wait for a drain
            if (i < NM && (vec[i][72] == mode || n == 0)) begin
                mode     = vec[i][72];
                a        = vec[i][70:48];
                b        = vec[i][46:24];
                exp_q[0] = vec[i][22:0];
                exp_v[0] = 1'b1;
                i = i + 1;
            end
            cycles = cycles + 1;
            @(negedge clk);
        end
        if (checked != NM) begin
            $display("tb_modmul: checked %0d of %0d", checked, NM);
            errors = errors + 1;
        end
        $display("tb_modmul: %0d products checked in %0d clocks, %0d errors", checked, cycles, errors);
        if (errors != 0)
            $fatal(1, "tb_modmul: FAIL");
        $display("tb_modmul: PASS");
        $finish;
    end

endmodule
