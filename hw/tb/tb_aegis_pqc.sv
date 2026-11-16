// SPDX-License-Identifier: Apache-2.0
//
// System testbench for rtl/aegis_pqc.v. Everything goes through real APB3
// transfers (setup phase, access phase, PREADY/PSLVERR checked on every
// access, back-to-back transfers and random idle cycles). Expected values
// come from the Python models via tb/vectors (see gen_vectors.py).
//
// Coverage:
//   - ID, reset values, unmapped offsets, writes to read-only registers
//   - NTT_INDEX write/read, masking, auto-increment on NTT_DATA reads and
//     writes, wrap at 256
//   - Keccak: all-zero known answer, NK states vs model, STATUS bits, cycle
//     register, writes/reads/starts while busy
//   - NTT: NV vectors per mode per direction vs model, NV forward-then-
//     inverse round trips per mode entirely in hardware, cycle register,
//     STATUS mode bit, writes/reads/starts while busy, Keccak and NTT
//     running at the same time, both start bits set at once

`timescale 1ns / 1ps

module tb_aegis_pqc;

    `include "params.svh"

    localparam [31:0] BASE     = 32'h40000E00;
    localparam [7:0]  A_ID     = 8'h00;
    localparam [7:0]  A_CTRL   = 8'h04;
    localparam [7:0]  A_STATUS = 8'h08;
    localparam [7:0]  A_KCYC   = 8'h0C;
    localparam [7:0]  A_NCYC   = 8'h10;
    localparam [7:0]  A_NIDX   = 8'h14;
    localparam [7:0]  A_NDATA  = 8'h18;
    localparam [31:0] C_KECCAK = 32'h001;
    localparam [31:0] C_FWD    = 32'h002;
    localparam [31:0] C_INV    = 32'h004;
    localparam [31:0] C_DSA    = 32'h100;
    localparam [31:0] ID_VALUE = 32'hAE150001;

    localparam integer V_FWD_IN = 0, V_FWD_OUT = 1, V_INV_IN = 2, V_INV_OUT = 3;

    reg         PCLK = 1'b0;
    reg         PRESETN = 1'b0;
    reg         PSEL = 1'b0;
    reg         PENABLE = 1'b0;
    reg  [31:0] PADDR = 32'd0;
    reg         PWRITE = 1'b0;
    reg  [31:0] PWDATA = 32'd0;
    wire [31:0] PRDATA;
    wire        PREADY;
    wire        PSLVERR;

    aegis_pqc dut (
        .PCLK(PCLK), .PRESETN(PRESETN), .PSEL(PSEL), .PENABLE(PENABLE),
        .PADDR(PADDR), .PWRITE(PWRITE), .PWDATA(PWDATA), .PRDATA(PRDATA),
        .PREADY(PREADY), .PSLVERR(PSLVERR)
    );

    always #10 PCLK = ~PCLK;      // 50 MHz

    // ------------------------------------------------------------ vectors
    reg [63:0] k_in  [0:NK*25-1];
    reg [63:0] k_out [0:NK*25-1];
    // all NTT vectors in one array: section (mode * 4 + V_*) holds NV x 256
    localparam integer SEC = NV * 256;
    reg [23:0] nv [0:8*SEC-1];

    function automatic [23:0] nvec(input integer m, input integer kind, input integer idx);
        nvec = nv[(4 * m + kind) * SEC + idx];
    endfunction

    // ------------------------------------------------------------ bookkeeping
    integer errors = 0;
    integer checks = 0;
    integer n_apb = 0;
    integer idle_pct = 0;
    integer n_keccak = 0;
    integer n_fwd [0:1];
    integer n_inv [0:1];
    integer n_rt  [0:1];
    integer kcyc_seen = -1;
    integer ncyc_seen [0:1];

    task automatic check(input [8*48-1:0] what, input [31:0] got, input [31:0] expv);
        begin
            checks = checks + 1;
            if (got !== expv) begin
                errors = errors + 1;
                if (errors <= 25)
                    $display("FAIL t=%0t %0s: got 0x%08X expected 0x%08X", $time, what, got, expv);
            end
        end
    endtask

    // ------------------------------------------------------------ APB master
    // Both tasks start right after a rising edge and return right after the
    // rising edge that ends the access phase, so calls chain back to back.
    task automatic check_bus;
        begin
            if (PREADY !== 1'b1 || PSLVERR !== 1'b0) begin
                errors = errors + 1;
                $display("FAIL t=%0t PREADY=%b PSLVERR=%b", $time, PREADY, PSLVERR);
            end
        end
    endtask

    task automatic maybe_idle;
        begin
            if (idle_pct != 0 && ($urandom % 100) < idle_pct)
                @(posedge PCLK);
        end
    endtask

    task automatic apb_write(input [7:0] off, input [31:0] data);
        begin
            PSEL <= 1'b1; PENABLE <= 1'b0; PWRITE <= 1'b1;
            PADDR <= BASE | {24'd0, off}; PWDATA <= data;
            @(posedge PCLK);                 // end of setup phase
            PENABLE <= 1'b1;
            @(negedge PCLK);
            check_bus;
            @(posedge PCLK);                 // end of access phase
            PSEL <= 1'b0; PENABLE <= 1'b0; PWRITE <= 1'b0;
            n_apb = n_apb + 1;
            maybe_idle;
        end
    endtask

    task automatic apb_read(input [7:0] off, output [31:0] data);
        begin
            PSEL <= 1'b1; PENABLE <= 1'b0; PWRITE <= 1'b0;
            PADDR <= BASE | {24'd0, off}; PWDATA <= $urandom;
            @(posedge PCLK);
            PENABLE <= 1'b1;
            @(negedge PCLK);                 // PRDATA sampled in the access phase
            check_bus;
            data = PRDATA;
            @(posedge PCLK);
            PSEL <= 1'b0; PENABLE <= 1'b0;
            n_apb = n_apb + 1;
            maybe_idle;
        end
    endtask

    task automatic read_check(input [8*48-1:0] what, input [7:0] off, input [31:0] expv);
        reg [31:0] d;
        begin
            apb_read(off, d);
            check(what, d, expv);
        end
    endtask

    // ------------------------------------------------------------ helpers
    task automatic wait_idle(input integer bit_busy);
        reg [31:0] s;
        integer n;
        begin
            n = 0;
            s = 32'hFFFFFFFF;
            while (s[bit_busy] && n < 5000) begin
                apb_read(A_STATUS, s);
                n = n + 1;
            end
            if (s[bit_busy]) begin
                $display("FAIL: timeout waiting for STATUS[%0d] to clear", bit_busy);
                $fatal(1, "tb_aegis_pqc: FAIL (timeout)");
            end
            check("done bit set when busy clears", {31'd0, s[bit_busy + 4]}, 32'd1);
        end
    endtask

    function automatic [7:0] lane_lo(input integer i);
        lane_lo = LANE_BASE + 8 * i;
    endfunction

    task automatic keccak_load(input integer v);
        integer i;
        begin
            for (i = 0; i < 25; i = i + 1) begin
                apb_write(lane_lo(i),     k_in[25*v + i][31:0]);
                apb_write(lane_lo(i) + 4, k_in[25*v + i][63:32]);
            end
        end
    endtask

    task automatic keccak_check(input integer v);
        integer i;
        reg [31:0] lo, hi;
        begin
            for (i = 0; i < 25; i = i + 1) begin
                apb_read(lane_lo(i),     lo);
                apb_read(lane_lo(i) + 4, hi);
                check("keccak lane lo", lo, k_out[25*v + i][31:0]);
                check("keccak lane hi", hi, k_out[25*v + i][63:32]);
            end
        end
    endtask

    task automatic keccak_cycles_check;
        reg [31:0] c;
        begin
            apb_read(A_KCYC, c);
            check("KECCAK_CYCLES", c, KECCAK_CYC);
            kcyc_seen = c;
        end
    endtask

    task automatic ntt_load(input integer m, input integer kind, input integer v);
        integer i;
        begin
            apb_write(A_NIDX, 32'd0);
            for (i = 0; i < 256; i = i + 1)
                apb_write(A_NDATA, {8'd0, nvec(m, kind, 256*v + i)});
        end
    endtask

    task automatic ntt_check(input integer m, input integer kind, input integer v);
        integer i;
        reg [31:0] d;
        begin
            apb_write(A_NIDX, 32'd0);
            for (i = 0; i < 256; i = i + 1) begin
                apb_read(A_NDATA, d);
                check("NTT coefficient", d, {8'd0, nvec(m, kind, 256*v + i)});
            end
            read_check("NTT_INDEX wrapped after 256 reads", A_NIDX, 32'd0);
        end
    endtask

    task automatic ntt_run(input integer m, input [31:0] ctrl);
        reg [31:0] s, c;
        begin
            apb_write(A_CTRL, ctrl | (m ? C_DSA : 32'd0));
            wait_idle(1);
            apb_read(A_STATUS, s);
            check("STATUS mode bit", {31'd0, s[8]}, m);
            apb_read(A_NCYC, c);
            check("NTT_CYCLES", c, m ? NTT_CYC_DSA : NTT_CYC_KEM);
            ncyc_seen[m] = c;
        end
    endtask

    // ------------------------------------------------------------ test
    integer m, v, i;
    reg [31:0] d, s;

    initial begin
        $readmemh("vectors/keccak_in.hex",  k_in);
        $readmemh("vectors/keccak_out.hex", k_out);
        $readmemh("vectors/ntt_kem_fwd_in.hex",  nv, 0 * SEC, 1 * SEC - 1);
        $readmemh("vectors/ntt_kem_fwd_out.hex", nv, 1 * SEC, 2 * SEC - 1);
        $readmemh("vectors/ntt_kem_inv_in.hex",  nv, 2 * SEC, 3 * SEC - 1);
        $readmemh("vectors/ntt_kem_inv_out.hex", nv, 3 * SEC, 4 * SEC - 1);
        $readmemh("vectors/ntt_dsa_fwd_in.hex",  nv, 4 * SEC, 5 * SEC - 1);
        $readmemh("vectors/ntt_dsa_fwd_out.hex", nv, 5 * SEC, 6 * SEC - 1);
        $readmemh("vectors/ntt_dsa_inv_in.hex",  nv, 6 * SEC, 7 * SEC - 1);
        $readmemh("vectors/ntt_dsa_inv_out.hex", nv, 7 * SEC, 8 * SEC - 1);
        for (m = 0; m < 2; m = m + 1) begin
            n_fwd[m] = 0; n_inv[m] = 0; n_rt[m] = 0; ncyc_seen[m] = -1;
        end

        repeat (4) @(posedge PCLK);
        PRESETN <= 1'b1;
        @(posedge PCLK);

        // ---- 1. ID, reset values, unmapped offsets, read-only registers
        read_check("ID", A_ID, ID_VALUE);
        read_check("STATUS after reset", A_STATUS, 32'd0);
        read_check("KECCAK_CYCLES after reset", A_KCYC, 32'd0);
        read_check("NTT_CYCLES after reset", A_NCYC, 32'd0);
        read_check("NTT_INDEX after reset", A_NIDX, 32'd0);
        read_check("CTRL reads 0", A_CTRL, 32'd0);
        for (i = 8'h1C; i < LANE_BASE; i = i + 4)
            read_check("unmapped offset", i[7:0], 32'd0);
        read_check("lane 0 lo after reset", lane_lo(0), 32'd0);
        read_check("lane 24 hi after reset", lane_lo(24) + 4, 32'd0);
        apb_write(A_ID, 32'hFFFFFFFF);
        apb_write(A_STATUS, 32'hFFFFFFFF);
        apb_write(A_KCYC, 32'hFFFFFFFF);
        apb_write(A_NCYC, 32'hFFFFFFFF);
        apb_write(8'h20, 32'hFFFFFFFF);
        read_check("ID after write", A_ID, ID_VALUE);
        read_check("STATUS after write", A_STATUS, 32'd0);
        read_check("KECCAK_CYCLES after write", A_KCYC, 32'd0);
        read_check("NTT_CYCLES after write", A_NCYC, 32'd0);
        read_check("unmapped after write", 8'h20, 32'd0);

        // ---- 2. NTT_INDEX and auto-increment
        apb_write(A_NIDX, 32'h000001FF);
        read_check("NTT_INDEX masked to 8 bits", A_NIDX, 32'h000000FF);
        apb_write(A_NIDX, 32'd250);
        for (i = 0; i < 10; i = i + 1)
            apb_write(A_NDATA, 32'h00100000 + i);
        read_check("NTT_INDEX after 10 writes from 250", A_NIDX, 32'd4);
        apb_write(A_NIDX, 32'd250);
        for (i = 0; i < 10; i = i + 1)
            read_check("NTT_DATA readback across wrap", A_NDATA, 32'h00100000 + i);
        read_check("NTT_INDEX after 10 reads from 250", A_NIDX, 32'd4);
        apb_write(A_NIDX, 32'd7);
        apb_write(A_NDATA, 32'hFFFFFFFF);
        apb_write(A_NIDX, 32'd7);
        read_check("NTT_DATA keeps 23 bits", A_NDATA, 32'h007FFFFF);

        // ---- 3. Keccak known answer: all-zero state
        keccak_load(0);
        apb_write(A_CTRL, C_KECCAK);
        apb_read(A_STATUS, s);
        check("STATUS keccak busy, not done", s & 32'h11, 32'h01);
        wait_idle(0);
        apb_read(A_STATUS, s);
        check("STATUS keccak done, not busy", s & 32'h11, 32'h10);
        read_check("zero-state lane0 lo", lane_lo(0),     32'h40E1DDE7);
        read_check("zero-state lane0 hi", lane_lo(0) + 4, 32'hF1258F79);
        keccak_check(0);
        keccak_cycles_check;
        n_keccak = n_keccak + 1;

        // ---- 4. Keccak: accesses while busy
        keccak_load(1);
        apb_write(A_CTRL, C_KECCAK);
        apb_write(lane_lo(0), 32'hDEADBEEF);             // dropped
        read_check("lane read while busy", lane_lo(5), 32'd0);
        apb_read(A_STATUS, s);
        check("STATUS busy, done cleared by start", s & 32'h11, 32'h01);
        apb_write(A_CTRL, C_KECCAK);                      // ignored
        apb_read(A_STATUS, s);
        check("still busy after ignored start", s & 32'h11, 32'h01);
        wait_idle(0);
        keccak_check(1);                                  // no restart, no write
        keccak_cycles_check;
        n_keccak = n_keccak + 1;

        // ---- 5. Keccak random states
        idle_pct = 20;
        for (v = 2; v < NK; v = v + 1) begin
            keccak_load(v);
            apb_write(A_CTRL, C_KECCAK);
            wait_idle(0);
            keccak_check(v);
            keccak_cycles_check;
            n_keccak = n_keccak + 1;
        end

        // ---- 6. NTT vectors, both modes
        idle_pct = 5;
        for (m = 0; m < 2; m = m + 1) begin
            for (v = 0; v < NV; v = v + 1) begin
                // forward vs model, then inverse in hardware -> original input
                ntt_load(m, V_FWD_IN, v);
                ntt_run(m, C_FWD);
                ntt_check(m, V_FWD_OUT, v);
                n_fwd[m] = n_fwd[m] + 1;
                ntt_run(m, C_INV);
                ntt_check(m, V_FWD_IN, v);
                n_rt[m] = n_rt[m] + 1;
            end
            for (v = 0; v < NV; v = v + 1) begin
                ntt_load(m, V_INV_IN, v);
                ntt_run(m, C_INV);
                ntt_check(m, V_INV_OUT, v);
                n_inv[m] = n_inv[m] + 1;
            end
        end

        // ---- 7. NTT: accesses while busy, both modes
        idle_pct = 0;
        for (m = 0; m < 2; m = m + 1) begin
            ntt_load(m, V_FWD_IN, 8);
            apb_write(A_NIDX, 32'd5);
            apb_write(A_CTRL, C_FWD | (m ? C_DSA : 32'd0));
            apb_read(A_STATUS, s);
            check("STATUS ntt busy, done cleared", s & 32'h122, {23'd0, m[0], 8'h02});
            apb_write(A_NDATA, 32'h00000123);                         // dropped, index 6
            read_check("NTT_DATA read while busy", A_NDATA, 32'd0);  // index 7
            read_check("NTT_INDEX increments while busy", A_NIDX, 32'd7);
            apb_write(A_CTRL, C_INV | (m ? 32'd0 : C_DSA));           // ignored
            apb_write(A_CTRL, C_FWD | (m ? C_DSA : 32'd0));           // ignored
            apb_read(A_STATUS, s);
            check("still busy, mode unchanged", s & 32'h122, {23'd0, m[0], 8'h02});
            wait_idle(1);
            apb_read(A_NCYC, d);
            check("NTT_CYCLES after ignored starts", d, m ? NTT_CYC_DSA : NTT_CYC_KEM);
            ntt_check(m, V_FWD_OUT, 8);
            n_fwd[m] = n_fwd[m] + 1;
        end

        // ---- 8. Keccak and NTT at the same time; done bits independent
        keccak_load(2);
        ntt_load(0, V_FWD_IN, 9);
        apb_write(A_CTRL, C_KECCAK | C_FWD);
        apb_read(A_STATUS, s);
        check("both busy", s & 32'h133, 32'h003);
        wait_idle(0);
        apb_read(A_STATUS, s);
        check("keccak done, ntt still busy", s & 32'h133, 32'h012);
        wait_idle(1);
        apb_read(A_STATUS, s);
        check("both done", s & 32'h133, 32'h030);
        keccak_check(2);
        ntt_check(0, V_FWD_OUT, 9);
        n_keccak = n_keccak + 1;
        n_fwd[0] = n_fwd[0] + 1;
        apb_write(A_CTRL, C_KECCAK);
        apb_read(A_STATUS, s);
        check("keccak start keeps ntt_done", s & 32'h133, 32'h021);
        wait_idle(0);

        // ---- 9. both start bits: forward runs; mode bit alone does nothing
        ntt_load(1, V_FWD_IN, 10);
        ntt_run(1, C_FWD | C_INV);
        ntt_check(1, V_FWD_OUT, 10);
        n_fwd[1] = n_fwd[1] + 1;
        apb_write(A_CTRL, 32'd0);                 // mode bit 0 without a start
        apb_read(A_STATUS, s);
        check("mode kept without a start", s & 32'h133, 32'h130);

        // ---- summary
        $display("tb_aegis_pqc: Keccak: %0d permutations vs model (incl. all-zero KAT)", n_keccak);
        $display("tb_aegis_pqc: ML-KEM: %0d NTT, %0d NTT^-1 vs model, %0d HW round trips",
                 n_fwd[0], n_inv[0], n_rt[0]);
        $display("tb_aegis_pqc: ML-DSA: %0d NTT, %0d NTT^-1 vs model, %0d HW round trips",
                 n_fwd[1], n_inv[1], n_rt[1]);
        $display("tb_aegis_pqc: KECCAK_CYCLES = %0d, NTT_CYCLES ML-KEM = %0d, ML-DSA = %0d",
                 kcyc_seen, ncyc_seen[0], ncyc_seen[1]);
        $display("tb_aegis_pqc: %0d APB transfers, %0d checks, %0d errors", n_apb, checks, errors);
        if (errors != 0)
            $fatal(1, "tb_aegis_pqc: FAIL");
        $display("tb_aegis_pqc: PASS");
        $finish;
    end

endmodule
