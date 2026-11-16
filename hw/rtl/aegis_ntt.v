// SPDX-License-Identifier: Apache-2.0
//
// aegis_ntt: 256-point NTT / NTT^-1 engine for ML-KEM (FIPS 203 Algorithms 9
// and 10, q = 3329) and ML-DSA (FIPS 204 Algorithms 41 and 42, q = 8380417).
//
// Storage: 256 coefficients in two 128 x 23 simple dual-port RAMs. Coefficient
// i lives in bank ^i (parity of the 8-bit index) at address i[6:0]. The two
// operands of a butterfly, j and j + 2^l, differ in exactly one bit, so they
// are always in different banks: each bank sees one read and one write per
// clock, and one butterfly is issued every clock.
//
// Butterflies are issued in the order of the standards' loops (layer, then
// group, then j). No stalls are needed between layers: the earliest
// coefficient a layer reads was written by the previous layer at least 57
// clocks earlier (pipeline is 8 clocks), see hw/model/ntt_hw.py.
//
// Butterfly datapath (two aegis_modmul instances, A and B):
//   forward (Cooley-Tukey):   pA = b * zeta,         pB = a * 1
//                             a' = pB + pA,          b' = pB - pA
//   inverse (Gentleman-Sande): pA = (b - a) * zeta,  pB = (a + b) * zB
//                             a' = pB,               b' = pA
// For the last inverse layer (len = 128) zeta is replaced by zetas[1] * f
// (ROM entry k = 0) and zB = f, which merges the final multiply by f
// (3303 or 8347681) into that layer. (b - a) * zeta equals FIPS 204's
// (-zeta) * (a - b), so one formula serves both standards.
//
// Pipeline (stage = clocks after the issue clock):
//   0 G  address generation          -> s1 regs
//   1 R  RAM / ROM read              -> RAM output regs, s2 regs
//   2 P  bank swap, (b-a), (a+b)     -> multiplier input regs, s3
//   3..6 modmul (4 clocks)           -> pA, pB at stage 7, s7
//   7 Q  final add/sub, bank swap    -> s8 regs
//   8 W  RAM write
// busy covers 128 * layers + 8 clocks: 904 (ML-KEM), 1032 (ML-DSA).
//
// Host port (used only while !busy): host_idx selects a coefficient;
// host_we writes host_wdata; host_rdata returns the coefficient at the
// host_idx of the previous clock. host_rvalid says the previous clock's read
// was a host read (engine idle), so the caller can return 0 otherwise.
//
// Inputs must be canonical (< q). Non-canonical inputs give unspecified
// results (no error is flagged).

`timescale 1ns / 1ps

module aegis_ntt (
    input             clk,
    input             rstn,
    input             start_fwd,
    input             start_inv,
    input             mode_in,
    output reg        busy,
    output reg        done,
    output reg        mode,
    output reg [31:0] cycles,
    input      [7:0]  host_idx,
    input             host_we,
    input      [22:0] host_wdata,
    output     [22:0] host_rdata,
    output reg        host_rvalid
);

    localparam [22:0] Q_K = 23'd3329;
    localparam [22:0] Q_D = 23'd8380417;
    localparam [22:0] F_K = 23'd3303;        // 128^-1 mod 3329
    localparam [22:0] F_D = 23'd8347681;     // 256^-1 mod 8380417

    wire [22:0] q    = mode ? Q_D : Q_K;
    wire [22:0] finv = mode ? F_D : F_K;

    // (x + y) mod q and (x - y) mod q for x, y in [0, q)
    function [22:0] addq;
        input [22:0] x;
        input [22:0] y;
        input [22:0] m;
        reg   [23:0] s;
        reg   [24:0] t;
        begin
            s    = {1'b0, x} + {1'b0, y};
            t    = {1'b0, s} - {2'b00, m};
            addq = t[24] ? s[22:0] : t[22:0];
        end
    endfunction

    function [22:0] subq;
        input [22:0] x;
        input [22:0] y;
        input [22:0] m;
        reg   [23:0] d;
        begin
            d    = {1'b0, x} - {1'b0, y};
            subq = d[23] ? (d[22:0] + m) : d[22:0];
        end
    endfunction

    // ------------------------------------------------------------ control
    reg       inv;          // 0: forward NTT, 1: inverse
    reg       issuing;
    reg [2:0] lc;           // layer counter, execution order
    reg [6:0] bf;           // butterfly within the layer

    wire [2:0] lc_last = mode ? 3'd7 : 3'd6;
    // log2(len): forward 7 down to 1 (KEM) / 0 (DSA); inverse back up to 7
    wire [2:0] l = inv ? (lc + {2'b00, ~mode}) : (3'd7 - lc);

    // ------------------------------------------------------------ stage G
    wire [7:0] lmask = (8'd1 << l) - 8'd1;
    wire [7:0] bf8   = {1'b0, bf};
    wire [7:0] j     = (bf8 & lmask) | ((bf8 & ~lmask) << 1);
    wire [7:0] jb    = j | (8'd1 << l);
    wire [7:0] kfull = {1'b1, (inv ? ~bf : bf)} >> l;  // fwd: G+group, inv: 2G-1-group
    wire       last  = inv & (l == 3'd7);
    wire [7:0] k     = last ? 8'd0 : kfull;
    wire       par   = ^j;                             // bank of j; jb is in the other

    // pipeline valid bits, s<n> = registers feeding stage n
    reg s1_v, s2_v, s3_v, s4_v, s5_v, s6_v, s7_v, s8_v;
    wire inflight = s1_v | s2_v | s3_v | s4_v | s5_v | s6_v | s7_v;

    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            busy    <= 1'b0;
            done    <= 1'b0;
            mode    <= 1'b0;
            inv     <= 1'b0;
            issuing <= 1'b0;
            lc      <= 3'd0;
            bf      <= 7'd0;
            cycles  <= 32'd0;
        end else if (!busy) begin
            if (start_fwd | start_inv) begin
                busy    <= 1'b1;
                done    <= 1'b0;
                mode    <= mode_in;
                inv     <= ~start_fwd;
                issuing <= 1'b1;
                lc      <= 3'd0;
                bf      <= 7'd0;
                cycles  <= 32'd0;
            end
        end else begin
            cycles <= cycles + 32'd1;
            if (issuing) begin
                bf <= bf + 7'd1;
                if (bf == 7'd127) begin
                    lc <= lc + 3'd1;
                    if (lc == lc_last)
                        issuing <= 1'b0;
                end
            end else if (!inflight) begin
                // the last write (s8) commits at this same edge
                busy <= 1'b0;
                done <= 1'b1;
            end
        end
    end

    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            {s1_v, s2_v, s3_v, s4_v, s5_v, s6_v, s7_v, s8_v} <= 8'd0;
            host_rvalid <= 1'b0;
        end else begin
            s1_v <= busy & issuing;
            s2_v <= s1_v;
            s3_v <= s2_v;
            s4_v <= s3_v;
            s5_v <= s4_v;
            s6_v <= s5_v;
            s7_v <= s6_v;
            s8_v <= s7_v;
            host_rvalid <= ~busy;
        end
    end

    // ------------------------------------------------------------ data path
    reg  [6:0]  s1_a0, s1_a1;        // bank 0 / bank 1 address
    reg  [7:0]  s1_k;
    reg         s1_par, s1_last;
    reg  [6:0]  s2_a0, s2_a1;
    reg         s2_par, s2_last;
    reg  [22:0] m_a, m_za, m_b, m_zb; // multiplier inputs (A: m_a*m_za, B: m_b*m_zb)
    reg  [6:0]  s3_a0, s3_a1, s4_a0, s4_a1, s5_a0, s5_a1, s6_a0, s6_a1, s7_a0, s7_a1;
    reg         s3_par, s4_par, s5_par, s6_par, s7_par;
    reg  [6:0]  s8_a0, s8_a1;
    reg  [22:0] s8_d0, s8_d1;
    reg         hpar;                // bank of the host read issued last clock

    wire [22:0] rd0, rd1, zeta, pA, pB;

    // stage P: operands in butterfly order
    wire [22:0] op_a = s2_par ? rd1 : rd0;
    wire [22:0] op_b = s2_par ? rd0 : rd1;

    // stage Q: butterfly outputs
    wire [22:0] out_a = inv ? pB : addq(pB, pA, q);
    wire [22:0] out_b = inv ? pA : subq(pB, pA, q);

    always @(posedge clk) begin
        // G -> s1
        s1_a0   <= par ? jb[6:0] : j[6:0];
        s1_a1   <= par ? j[6:0]  : jb[6:0];
        s1_par  <= par;
        s1_k    <= k;
        s1_last <= last;
        // R -> s2 (RAM and ROM register their own outputs)
        s2_a0   <= s1_a0;
        s2_a1   <= s1_a1;
        s2_par  <= s1_par;
        s2_last <= s1_last;
        // P -> s3, multiplier inputs
        m_a     <= inv ? subq(op_b, op_a, q) : op_b;
        m_za    <= zeta;
        m_b     <= inv ? addq(op_a, op_b, q) : op_a;
        m_zb    <= s2_last ? finv : 23'd1;
        s3_a0   <= s2_a0;   s3_a1 <= s2_a1;   s3_par <= s2_par;
        // multiplier latency
        s4_a0   <= s3_a0;   s4_a1 <= s3_a1;   s4_par <= s3_par;
        s5_a0   <= s4_a0;   s5_a1 <= s4_a1;   s5_par <= s4_par;
        s6_a0   <= s5_a0;   s6_a1 <= s5_a1;   s6_par <= s5_par;
        s7_a0   <= s6_a0;   s7_a1 <= s6_a1;   s7_par <= s6_par;
        // Q -> s8, already sorted by bank
        s8_a0   <= s7_a0;
        s8_a1   <= s7_a1;
        s8_d0   <= s7_par ? out_b : out_a;
        s8_d1   <= s7_par ? out_a : out_b;
        // host read bank
        hpar    <= ^host_idx;
    end

    aegis_modmul u_mul_a (.clk(clk), .mode(mode), .a(m_a), .b(m_za), .p(pA));
    aegis_modmul u_mul_b (.clk(clk), .mode(mode), .a(m_b), .b(m_zb), .p(pB));

    aegis_ntt_rom u_rom (.clk(clk), .addr({mode, s1_k}), .data(zeta));

    // ------------------------------------------------------------ RAM banks
    wire        hbank = ^host_idx;
    wire        we0   = busy ? s8_v  : (host_we & ~hbank);
    wire        we1   = busy ? s8_v  : (host_we &  hbank);
    wire [6:0]  wa0   = busy ? s8_a0 : host_idx[6:0];
    wire [6:0]  wa1   = busy ? s8_a1 : host_idx[6:0];
    wire [22:0] wd0   = busy ? s8_d0 : host_wdata;
    wire [22:0] wd1   = busy ? s8_d1 : host_wdata;
    wire [6:0]  ra0   = busy ? s1_a0 : host_idx[6:0];
    wire [6:0]  ra1   = busy ? s1_a1 : host_idx[6:0];

    aegis_ram_sdp #(.AW(7), .DW(23)) u_bank0 (
        .clk(clk), .we(we0), .waddr(wa0), .wdata(wd0), .raddr(ra0), .rdata(rd0));
    aegis_ram_sdp #(.AW(7), .DW(23)) u_bank1 (
        .clk(clk), .we(we1), .waddr(wa1), .wdata(wd1), .raddr(ra1), .rdata(rd1));

    assign host_rdata = hpar ? rd1 : rd0;

endmodule
