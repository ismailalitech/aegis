// SPDX-License-Identifier: Apache-2.0
//
// tb_aegis_pqc2: replays vectors/sponge_ops.txt (tb/gen_sponge_vectors.py) against aegis_pqc2 over APB, with an AXI4
// write slave model behind the DMA port: a sparse 64-bit memory, random AWREADY / WREADY / BVALID delays, SLVERR in
// [ERR_BASE, ERR_BASE + 4 KiB), and protocol checks (no 4 KiB crossing, WLAST on the last beat, stable signals while
// waiting). Prints "tb_aegis_pqc2: PASS" when every check holds.

`timescale 1ns / 1ps

module tb_aegis_pqc2;

    localparam integer AW = 38;
    localparam [AW-1:0] ERR_BASE = 38'h80F000;

    reg         clk = 1'b0;
    reg         rstn = 1'b0;
    reg         psel = 1'b0, penable = 1'b0, pwrite = 1'b0;
    reg  [31:0] paddr = 32'd0, pwdata = 32'd0;
    wire [31:0] prdata;
    wire        pready, pslverr;

    wire [AW-1:0] awaddr;
    wire [7:0]    awlen;
    wire [2:0]    awsize, awprot;
    wire [1:0]    awburst;
    wire [3:0]    awcache, awid, awqos;
    wire          awlock, awvalid, wlast, wvalid, bready;
    wire [63:0]   wdata;
    wire [7:0]    wstrb;
    reg           awready = 1'b0, wready = 1'b0, bvalid = 1'b0;
    reg  [1:0]    bresp = 2'b00;

    always #10 clk = ~clk;   // 50 MHz

    aegis_pqc2 #(.AXI_AW(AW)) dut (
        .PCLK(clk), .PRESETN(rstn), .PSEL(psel), .PENABLE(penable), .PADDR(paddr), .PWRITE(pwrite),
        .PWDATA(pwdata), .PRDATA(prdata), .PREADY(pready), .PSLVERR(pslverr),
        .m_axi_awaddr(awaddr), .m_axi_awlen(awlen), .m_axi_awsize(awsize), .m_axi_awburst(awburst),
        .m_axi_awcache(awcache), .m_axi_awprot(awprot), .m_axi_awid(awid), .m_axi_awlock(awlock),
        .m_axi_awqos(awqos), .m_axi_awvalid(awvalid), .m_axi_awready(awready), .m_axi_wdata(wdata),
        .m_axi_wstrb(wstrb), .m_axi_wlast(wlast), .m_axi_wvalid(wvalid), .m_axi_wready(wready),
        .m_axi_bid(4'd0), .m_axi_bresp(bresp), .m_axi_bvalid(bvalid), .m_axi_bready(bready)
    );

    integer errors = 0, checks = 0, stalls = 0, max_stall = 0, beats = 0;

    task automatic fail(input [8*64-1:0] what);
        begin
            errors = errors + 1;
            if (errors <= 20) $display("FAIL %0s", what);
        end
    endtask

    // ---------------------------------------------------------------- AXI4 write slave
    // two 64 KiB windows: 0x0000800000 and 0x1400800000 (the high one checks address bits 37:32)
    reg [63:0]   mem   [0:16383];
    reg          valid [0:16383];
    integer      vi;
    initial for (vi = 0; vi < 16384; vi = vi + 1) valid[vi] = 1'b0;
    function automatic integer midx(input [AW-1:0] a);
        if (a[AW-1:16] == 22'h000080)      midx = {1'b0, a[15:3]};
        else if (a[AW-1:16] == 22'h140080) midx = {1'b1, a[15:3]};
        else                               midx = -1;
    endfunction
    reg [AW-1:0] cur_addr;
    reg [7:0]    left;
    reg          cur_err, in_burst = 1'b0, resp_pending = 1'b0;
    integer      seed = 32'h5EED;

    always @(posedge clk) begin
        // address: accept with a random delay, only when no burst is open (the master never overlaps)
        awready <= 1'b0;
        if (awvalid && !awready && !in_burst && !resp_pending && ($random(seed) & 3) == 0) begin
            awready  <= 1'b1;
            in_burst <= 1'b1;
            cur_addr <= awaddr;
            left     <= awlen;
            cur_err  <= (awaddr >= ERR_BASE) && (awaddr < ERR_BASE + 38'h1000);
            checks = checks + 1;
            if (awsize != 3'b011 || awburst != 2'b01 || awid != 0 || awlock || awcache != 4'b0011)
                fail("AW attributes");
            if (awaddr[2:0] != 0) fail("AW not 8-byte aligned");
            if ((awaddr & 38'hFFF) + (({30'd0, awlen} + 1) << 3) > 38'h1000) fail("burst crosses 4 KiB");
        end
        // data
        wready <= in_burst && (($random(seed) & 1) == 0);
        if (wvalid && wready) begin
            beats = beats + 1;
            if (wstrb != 8'hFF) fail("WSTRB");
            if (wlast != (left == 0)) fail("WLAST position");
            if (!cur_err) begin
                if (midx(cur_addr) < 0) fail("write outside the memory model");
                else begin
                    mem[midx(cur_addr)] = wdata;
                    valid[midx(cur_addr)] = 1'b1;
                end
            end
            cur_addr <= cur_addr + 8;
            left     <= left - 1;
            if (wlast) begin
                in_burst     <= 1'b0;
                wready       <= 1'b0;
                resp_pending <= 1'b1;
            end
        end
        // response after a random delay
        if (resp_pending && !bvalid && ($random(seed) & 3) == 0) begin
            bvalid <= 1'b1;
            bresp  <= cur_err ? 2'b10 : 2'b00;
        end
        if (bvalid && bready) begin
            bvalid       <= 1'b0;
            resp_pending <= 1'b0;
        end
    end

    // master must hold AW and W stable while waiting
    reg [AW-1:0] aw_hold;
    reg [63:0]   w_hold;
    reg          aw_wait = 1'b0, w_wait = 1'b0;
    always @(posedge clk) begin
        if (aw_wait && (awaddr != aw_hold || !awvalid)) fail("AW changed while waiting");
        if (w_wait && (wdata != w_hold || !wvalid)) fail("W changed while waiting");
        aw_wait <= awvalid && !awready;
        aw_hold <= awaddr;
        w_wait  <= wvalid && !wready;
        w_hold  <= wdata;
    end

    // ---------------------------------------------------------------- APB master
    task automatic apb(input w, input [7:0] off, input [31:0] data, output [31:0] rd);
        integer n;
        begin
            @(posedge clk);
            psel <= 1'b1; pwrite <= w; paddr <= {24'd0, off}; pwdata <= data; penable <= 1'b0;
            @(posedge clk);
            penable <= 1'b1;
            n = 0;
            @(posedge clk);
            while (!pready) begin
                n = n + 1;
                if (n > 4000) begin
                    fail("PREADY stuck low");
                    disable apb;
                end
                @(posedge clk);
            end
            if (n > 0) begin
                stalls = stalls + 1;
                if (n > max_stall) max_stall = n;
            end
            if (pslverr) fail("PSLVERR");
            rd = prdata;
            psel <= 1'b0; penable <= 1'b0;
        end
    endtask

    // ---------------------------------------------------------------- script
    integer fd, rc, ops = 0, polls;
    reg done = 1'b0;
    reg [8*4-1:0] op;
    reg [63:0]    a1, a2, a3;
    reg [31:0]    rd;
    reg [8*96-1:0] msg;

    initial begin
        fd = $fopen("vectors/sponge_ops.txt", "r");
        if (fd == 0) begin
            $display("cannot open vectors/sponge_ops.txt");
            $finish;
        end
        repeat (5) @(posedge clk);
        rstn = 1'b1;
        while (!done) begin
            rc = $fscanf(fd, "%s", op);
            if (rc != 1) begin
                fail("script ended without E");
                op = "E";
            end
            ops = ops + 1;
            case (op[7:0])
            "W": begin
                rc = $fscanf(fd, "%h %h", a1, a2);
                apb(1'b1, a1[7:0], a2[31:0], rd);
            end
            "R": begin
                rc = $fscanf(fd, "%h %h %h", a1, a2, a3);
                apb(1'b0, a1[7:0], 32'd0, rd);
                checks = checks + 1;
                if ((rd & a3[31:0]) !== a2[31:0]) begin
                    $sformat(msg, "op %0d read 0x%02h = %08h, expected %08h", ops, a1[7:0], rd, a2[31:0]);
                    fail(msg);
                end
            end
            "D": begin
                rc = $fscanf(fd, "%h %h", a1, a2);
                polls = 0;
                apb(1'b0, 8'h08, 32'd0, rd);
                while (rd[16]) begin
                    polls = polls + 1;
                    apb(1'b0, 8'h08, 32'd0, rd);
                end
                checks = checks + 1;
                if ((rd & a2[31:0]) !== a1[31:0]) begin
                    $sformat(msg, "op %0d STATUS %08h, expected %08h (mask %08h)", ops, rd, a1[31:0], a2[31:0]);
                    fail(msg);
                end
            end
            "M": begin
                rc = $fscanf(fd, "%h %h", a1, a2);
                checks = checks + 1;
                if (midx(a1[AW-1:0]) < 0 || !valid[midx(a1[AW-1:0])] || mem[midx(a1[AW-1:0])] !== a2) begin
                    $sformat(msg, "memory %010h: expected %016h", a1, a2);
                    fail(msg);
                end
            end
            "N": begin
                rc = $fscanf(fd, "%h", a1);
                checks = checks + 1;
                if (beats != a1) begin
                    $sformat(msg, "%0d write beats, expected %0d", beats, a1);
                    fail(msg);
                end
            end
            "E": done = 1'b1;
            default: begin
                fail("unknown script line");
                done = 1'b1;
            end
            endcase
        end
        $fclose(fd);
        $display("tb_aegis_pqc2: %0d operations, %0d checks, %0d write beats, %0d stalled accesses (longest %0d clocks)",
                 ops, checks, beats, stalls, max_stall);
        if (errors == 0) $display("tb_aegis_pqc2: PASS");
        else $display("tb_aegis_pqc2: FAIL (%0d errors)", errors);
        $finish;
    end

endmodule
