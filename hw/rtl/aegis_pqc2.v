// SPDX-License-Identifier: Apache-2.0
//
// aegis_pqc2: APB3 slave (256 bytes) with the Keccak sponge (aegis_sponge) and the NTT unit (aegis_ntt), plus an AXI4
// write master through which the sponge squeezes into DDR. Same register map as aegis_pqc where they overlap, so the
// first driver keeps working (CLEAR is not needed there: it writes all 50 words before each permutation).
//
//   0x00 ID       0xAE150002
//   0x04 CTRL     W: bit 0 permute (the sponge's PERMUTE), bit 1 NTT forward, bit 2 NTT inverse, bit 8 NTT mode
//   0x08 STATUS   R: bit 0 sponge busy, bit 1 NTT busy, bit 4 sponge idle, bit 5 NTT done, bit 8 NTT mode,
//                    bit 16 DMA busy, bit 17 DMA error, bits 20:18 current slot, bits 31:24 DMA blocks written
//   0x0C KCOUNT   R: permutations done since reset
//   0x10 NCYC, 0x14 NIDX, 0x18 NDATA   NTT, as aegis_pqc
//   0x1C SCMD     W: bits 2:0 command (1 PERMUTE, 2 CLEAR, 3 SELECT, 4 SQUEEZE_DMA), bits 6:4 slot for SELECT
//   0x20 SCFG     R/W: bit 0 XOR mode for state writes, bits 12:8 DMA rate in lanes, bits 23:16 DMA block count
//   0x24 DMA_LO   R/W: DMA destination, physical address bits 31:0 (8-byte aligned)
//   0x28 DMA_HI   R/W: bits AXI_AW-1:32 (reads 0 above the address width; with AXI_AW = 32 there are none)
//   0x38..0xFF    state words (lane i: low half 0x38 + 8i, high half 0x3C + 8i)
//
// While the sponge is busy, an access to the state words, SCMD or a CTRL write with bit 0 is held with PREADY low until
// the sponge is idle; software therefore never polls between a command and the next state access. STATUS, ID and the
// NTT registers always answer at once. A DMA command can last long (tens of microseconds): poll STATUS bit 16.

`timescale 1ns / 1ps

module aegis_pqc2 #(
    parameter AXI_AW = 38
) (
    input               PCLK,
    input               PRESETN,
    input               PSEL,
    input               PENABLE,
    input      [31:0]   PADDR,
    input               PWRITE,
    input      [31:0]   PWDATA,
    output     [31:0]   PRDATA,
    output              PREADY,
    output              PSLVERR,

    output [AXI_AW-1:0] m_axi_awaddr,
    output [7:0]        m_axi_awlen,
    output [2:0]        m_axi_awsize,
    output [1:0]        m_axi_awburst,
    output [3:0]        m_axi_awcache,
    output [2:0]        m_axi_awprot,
    output [3:0]        m_axi_awid,
    output              m_axi_awlock,
    output [3:0]        m_axi_awqos,
    output              m_axi_awvalid,
    input               m_axi_awready,
    output [63:0]       m_axi_wdata,
    output [7:0]        m_axi_wstrb,
    output              m_axi_wlast,
    output              m_axi_wvalid,
    input               m_axi_wready,
    input  [3:0]        m_axi_bid,
    input  [1:0]        m_axi_bresp,
    input               m_axi_bvalid,
    output              m_axi_bready
);

    localparam [31:0] ID_VALUE = 32'hAE150002;
    localparam [63:0] ADDR_MASK = (AXI_AW >= 64) ? ~64'd0 : ((64'd1 << AXI_AW) - 64'd1);
    localparam [31:0] HI_MASK   = ADDR_MASK[63:32];   // DMA_HI reads back only the bits that exist
    localparam [5:0]  W_ID = 6'h00, W_CTRL = 6'h01, W_STATUS = 6'h02, W_KCOUNT = 6'h03, W_NCYC = 6'h04,
                      W_NIDX = 6'h05, W_NDATA = 6'h06, W_SCMD = 6'h07, W_SCFG = 6'h08, W_DMALO = 6'h09,
                      W_DMAHI = 6'h0A, W_LANE0 = 6'h0E;

    wire [5:0] word      = PADDR[7:2];
    wire       sel_ctrl  = (word == W_CTRL);
    wire       sel_scmd  = (word == W_SCMD);
    wire       sel_nidx  = (word == W_NIDX);
    wire       sel_ndata = (word == W_NDATA);
    wire       sel_lane  = (word >= W_LANE0);
    wire [5:0] lane_word = word - W_LANE0;

    wire s_busy;
    wire needs_idle = sel_lane | sel_scmd | (sel_ctrl & PWRITE & PWDATA[0]);
    assign PREADY  = ~(PSEL & PENABLE & needs_idle & s_busy);
    assign PSLVERR = 1'b0;

    wire acc_wr = PSEL & PENABLE &  PWRITE & PREADY;
    wire acc_rd = PSEL & PENABLE & ~PWRITE & PREADY;

    // ------------------------------------------------------------ configuration registers
    reg              xor_mode;
    reg [4:0]        dma_rate;
    reg [7:0]        dma_nblk;
    reg [63:0]       dma_addr;      // only bits AXI_AW-1:0 reach the engine
    always @(posedge PCLK or negedge PRESETN) begin
        if (!PRESETN) begin
            xor_mode <= 1'b0;
            dma_rate <= 5'd0;
            dma_nblk <= 8'd0;
            dma_addr <= 64'd0;
        end else if (acc_wr) begin
            case (word)
            W_SCFG:  begin xor_mode <= PWDATA[0]; dma_rate <= PWDATA[12:8]; dma_nblk <= PWDATA[23:16]; end
            W_DMALO: dma_addr[31:0] <= PWDATA;
            W_DMAHI: dma_addr[63:32] <= PWDATA;
            default: ;
            endcase
        end
    end

    // ------------------------------------------------------------ sponge
    wire        cmd_from_ctrl = acc_wr & sel_ctrl & PWDATA[0];
    wire        cmd_from_scmd = acc_wr & sel_scmd;
    wire [2:0]  s_cmd = cmd_from_scmd ? PWDATA[2:0] : 3'd1;
    wire        s_dma_busy, s_dma_err;
    wire [7:0]  s_done_blk;
    wire [2:0]  s_slot;
    wire [31:0] s_count, s_rdata;

    assign m_axi_awid   = 4'd0;
    assign m_axi_awlock = 1'b0;
    assign m_axi_awqos  = 4'd0;

    aegis_sponge #(.AXI_AW(AXI_AW)) u_sponge (
        .clk(PCLK), .rstn(PRESETN),
        .wr_en(acc_wr & sel_lane), .wr_word(lane_word), .wr_data(PWDATA), .xor_mode(xor_mode),
        .rd_word(lane_word), .rd_data(s_rdata),
        .cmd_valid(cmd_from_ctrl | cmd_from_scmd), .cmd(s_cmd), .cmd_slot(PWDATA[6:4]),
        .dma_rate_lanes(dma_rate), .dma_nblk(dma_nblk), .dma_addr(dma_addr[AXI_AW-1:0]),
        .busy(s_busy), .dma_busy(s_dma_busy), .dma_err(s_dma_err), .dma_done_blk(s_done_blk),
        .cur_slot(s_slot), .perm_count(s_count),
        .m_awaddr(m_axi_awaddr), .m_awlen(m_axi_awlen), .m_awsize(m_axi_awsize), .m_awburst(m_axi_awburst),
        .m_awcache(m_axi_awcache), .m_awprot(m_axi_awprot), .m_awvalid(m_axi_awvalid), .m_awready(m_axi_awready),
        .m_wdata(m_axi_wdata), .m_wstrb(m_axi_wstrb), .m_wlast(m_axi_wlast), .m_wvalid(m_axi_wvalid),
        .m_wready(m_axi_wready), .m_bresp(m_axi_bresp), .m_bvalid(m_axi_bvalid), .m_bready(m_axi_bready)
    );

    // ------------------------------------------------------------ NTT (as aegis_pqc)
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
        .clk(PCLK), .rstn(PRESETN),
        .start_fwd(acc_wr & sel_ctrl & PWDATA[1]), .start_inv(acc_wr & sel_ctrl & PWDATA[2]), .mode_in(PWDATA[8]),
        .busy(n_busy), .done(n_done), .mode(n_mode), .cycles(n_cycles),
        .host_idx(ntt_idx), .host_we(acc_wr & sel_ndata & ~n_busy), .host_wdata(PWDATA[22:0]),
        .host_rdata(n_rdata), .host_rvalid(n_rvalid)
    );

    // ------------------------------------------------------------ read mux
    reg [31:0] rdata;
    always @(*) begin
        rdata = 32'd0;
        case (word)
            W_ID:     rdata = ID_VALUE;
            W_STATUS: rdata = {s_done_blk, 3'd0, s_slot, s_dma_err, s_dma_busy, 7'd0, n_mode, 2'b00, n_done, ~s_busy,
                               2'b00, n_busy, s_busy};
            W_KCOUNT: rdata = s_count;
            W_NCYC:   rdata = n_cycles;
            W_NIDX:   rdata = {24'd0, ntt_idx};
            W_NDATA:  rdata = (n_rvalid & ~n_busy) ? {9'd0, n_rdata} : 32'd0;
            W_SCFG:   rdata = {8'd0, dma_nblk, 3'd0, dma_rate, 7'd0, xor_mode};
            W_DMALO:  rdata = dma_addr[31:0];
            W_DMAHI:  rdata = dma_addr[63:32] & HI_MASK;
            default:  rdata = sel_lane ? s_rdata : 32'd0;
        endcase
    end
    assign PRDATA = rdata;

endmodule
