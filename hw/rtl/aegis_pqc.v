// SPDX-License-Identifier: Apache-2.0
//
// aegis_pqc: APB3 slave with a Keccak-f[1600] permutation unit and a
// 256-point NTT / NTT^-1 unit for ML-KEM (q = 3329) and ML-DSA (q = 8380417).
// Everything runs on PCLK. PREADY is tied 1 (zero wait states), PSLVERR 0.
//
// Register map (byte offsets in the 256-byte slot, 32-bit registers; only
// PADDR[7:2] is decoded, PADDR[1:0] are ignored):
//   0x00 ID            R   0xAE150001
//   0x04 CTRL          W   bit0 KECCAK_START, bit1 NTT_FWD_START,
//                          bit2 NTT_INV_START, bit8 NTT_MODE (latched on an
//                          NTT start: 0 ML-KEM, 1 ML-DSA). Starts are ignored
//                          while the unit is busy. If bit1 and bit2 are both
//                          set, the forward transform runs.
//   0x08 STATUS        R   bit0 keccak_busy, bit1 ntt_busy, bit4 keccak_done,
//                          bit5 ntt_done, bit8 NTT mode of the last start
//   0x0C KECCAK_CYCLES R   busy clocks of the last permutation
//   0x10 NTT_CYCLES    R   busy clocks of the last NTT / NTT^-1
//   0x14 NTT_INDEX     RW  coefficient index 0..255
//   0x18 NTT_DATA      RW  coefficient[NTT_INDEX], bits 22:0. Every read or
//                          write increments NTT_INDEX (mod 256), also while
//                          busy; while ntt_busy writes are dropped and reads
//                          return 0.
//   0x38 + 8*i         RW  Keccak lane i (i = x + 5*y = 0..24) bits 31:0
//   0x3C + 8*i         RW  Keccak lane i bits 63:32
//                          (lanes occupy 0x38..0xFF; writes are dropped and
//                          reads return 0 while keccak_busy)
//   all other offsets read 0, writes are ignored.
//
// Lane base: 25 lanes x 8 bytes = 200 bytes do not fit between 0x40 and the
// end of the 256-byte slot, so the lanes start at 0x38 (LANE_BASE).

`timescale 1ns / 1ps

module aegis_pqc (
    input             PCLK,
    input             PRESETN,
    input             PSEL,
    input             PENABLE,
    input      [31:0] PADDR,    // only PADDR[7:0] is meaningful
    input             PWRITE,
    input      [31:0] PWDATA,
    output     [31:0] PRDATA,
    output            PREADY,   // tied 1
    output            PSLVERR   // tied 0
);

    localparam [31:0] ID_VALUE  = 32'hAE150001;
    localparam [5:0]  W_ID      = 6'h00;
    localparam [5:0]  W_CTRL    = 6'h01;
    localparam [5:0]  W_STATUS  = 6'h02;
    localparam [5:0]  W_KCYC    = 6'h03;
    localparam [5:0]  W_NCYC    = 6'h04;
    localparam [5:0]  W_NIDX    = 6'h05;
    localparam [5:0]  W_NDATA   = 6'h06;
    localparam [5:0]  W_LANE0   = 6'h0E;    // byte offset 0x38 = LANE_BASE

    assign PREADY  = 1'b1;
    assign PSLVERR = 1'b0;

    wire [5:0] word   = PADDR[7:2];
    wire       acc_wr = PSEL & PENABLE &  PWRITE;
    wire       acc_rd = PSEL & PENABLE & ~PWRITE;

    wire       sel_ctrl  = (word == W_CTRL);
    wire       sel_nidx  = (word == W_NIDX);
    wire       sel_ndata = (word == W_NDATA);
    wire       sel_lane  = (word >= W_LANE0);
    wire [5:0] lane_word = word - W_LANE0;      // 0..49 when sel_lane

    // ------------------------------------------------------------ Keccak
    wire        k_busy, k_done;
    wire [31:0] k_cycles, k_rdata;

    aegis_keccak u_keccak (
        .clk     (PCLK),
        .rstn    (PRESETN),
        .start   (acc_wr & sel_ctrl & PWDATA[0]),
        .wr_en   (acc_wr & sel_lane),
        .wr_word (lane_word),
        .wr_data (PWDATA),
        .rd_word (lane_word),
        .rd_data (k_rdata),
        .busy    (k_busy),
        .done    (k_done),
        .cycles  (k_cycles)
    );

    // ------------------------------------------------------------ NTT
    reg  [7:0]  ntt_idx;
    wire        n_busy, n_done, n_mode, n_rvalid;
    wire [31:0] n_cycles;
    wire [22:0] n_rdata;

    always @(posedge PCLK or negedge PRESETN) begin
        if (!PRESETN)
            ntt_idx <= 8'd0;
        else if (acc_wr & sel_nidx)
            ntt_idx <= PWDATA[7:0];
        else if ((acc_wr | acc_rd) & sel_ndata)
            ntt_idx <= ntt_idx + 8'd1;
    end

    aegis_ntt u_ntt (
        .clk         (PCLK),
        .rstn        (PRESETN),
        .start_fwd   (acc_wr & sel_ctrl & PWDATA[1]),
        .start_inv   (acc_wr & sel_ctrl & PWDATA[2]),
        .mode_in     (PWDATA[8]),
        .busy        (n_busy),
        .done        (n_done),
        .mode        (n_mode),
        .cycles      (n_cycles),
        .host_idx    (ntt_idx),
        .host_we     (acc_wr & sel_ndata & ~n_busy),
        .host_wdata  (PWDATA[22:0]),
        .host_rdata  (n_rdata),
        .host_rvalid (n_rvalid)
    );

    // ------------------------------------------------------------ read mux
    reg [31:0] rdata;
    always @(*) begin
        rdata = 32'd0;
        case (word)
            W_ID:     rdata = ID_VALUE;
            W_STATUS: rdata = {23'd0, n_mode, 2'b00, n_done, k_done, 2'b00, n_busy, k_busy};
            W_KCYC:   rdata = k_cycles;
            W_NCYC:   rdata = n_cycles;
            W_NIDX:   rdata = {24'd0, ntt_idx};
            W_NDATA:  rdata = (n_rvalid & ~n_busy) ? {9'd0, n_rdata} : 32'd0;
            default:  rdata = (sel_lane & ~k_busy) ? k_rdata : 32'd0;
        endcase
    end
    assign PRDATA = rdata;

endmodule
