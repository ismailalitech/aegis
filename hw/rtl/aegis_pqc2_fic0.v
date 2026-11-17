// SPDX-License-Identifier: Apache-2.0
//
// aegis_pqc2_fic0: aegis_pqc2 with the port set of the board design's FIC0 interconnect (DMA_INITIATOR master port):
// 32-bit addresses, 8-bit IDs, 2-bit lock, 1-bit user signals, and a read channel that is never used (tied off).
// Everything that matters is in aegis_pqc2, which is the simulated module; this file only adapts the ports.

`timescale 1ns / 1ps

module aegis_pqc2_fic0 (
    input         PCLK,
    input         PRESETN,
    input         PSEL,
    input         PENABLE,
    input  [31:0] PADDR,
    input         PWRITE,
    input  [31:0] PWDATA,
    output [31:0] PRDATA,
    output        PREADY,
    output        PSLVERR,

    output [7:0]  AWID,
    output [31:0] AWADDR,
    output [7:0]  AWLEN,
    output [2:0]  AWSIZE,
    output [1:0]  AWBURST,
    output [1:0]  AWLOCK,
    output [3:0]  AWCACHE,
    output [2:0]  AWPROT,
    output [3:0]  AWQOS,
    output [3:0]  AWREGION,
    output [0:0]  AWUSER,
    output        AWVALID,
    input         AWREADY,
    output [63:0] WDATA,
    output [7:0]  WSTRB,
    output        WLAST,
    output [0:0]  WUSER,
    output        WVALID,
    input         WREADY,
    input  [7:0]  BID,
    input  [1:0]  BRESP,
    input  [0:0]  BUSER,
    input         BVALID,
    output        BREADY,

    output [7:0]  ARID,
    output [31:0] ARADDR,
    output [7:0]  ARLEN,
    output [2:0]  ARSIZE,
    output [1:0]  ARBURST,
    output [1:0]  ARLOCK,
    output [3:0]  ARCACHE,
    output [2:0]  ARPROT,
    output [3:0]  ARQOS,
    output [3:0]  ARREGION,
    output [0:0]  ARUSER,
    output        ARVALID,
    input         ARREADY,
    input  [7:0]  RID,
    input  [63:0] RDATA,
    input  [1:0]  RRESP,
    input         RLAST,
    input  [0:0]  RUSER,
    input         RVALID,
    output        RREADY
);

    wire [3:0] awid4, awqos4;
    wire       awlock1;

    aegis_pqc2 #(.AXI_AW(32)) u_core (
        .PCLK(PCLK), .PRESETN(PRESETN), .PSEL(PSEL), .PENABLE(PENABLE), .PADDR(PADDR), .PWRITE(PWRITE),
        .PWDATA(PWDATA), .PRDATA(PRDATA), .PREADY(PREADY), .PSLVERR(PSLVERR),
        .m_axi_awaddr(AWADDR), .m_axi_awlen(AWLEN), .m_axi_awsize(AWSIZE), .m_axi_awburst(AWBURST),
        .m_axi_awcache(AWCACHE), .m_axi_awprot(AWPROT), .m_axi_awid(awid4), .m_axi_awlock(awlock1),
        .m_axi_awqos(awqos4), .m_axi_awvalid(AWVALID), .m_axi_awready(AWREADY),
        .m_axi_wdata(WDATA), .m_axi_wstrb(WSTRB), .m_axi_wlast(WLAST), .m_axi_wvalid(WVALID), .m_axi_wready(WREADY),
        .m_axi_bid(BID[3:0]), .m_axi_bresp(BRESP), .m_axi_bvalid(BVALID), .m_axi_bready(BREADY)
    );

    assign AWID     = {4'd0, awid4};
    assign AWLOCK   = {1'b0, awlock1};
    assign AWQOS    = awqos4;
    assign AWREGION = 4'd0;
    assign AWUSER   = 1'b0;
    assign WUSER    = 1'b0;

    assign ARID     = 8'd0;
    assign ARADDR   = 32'd0;
    assign ARLEN    = 8'd0;
    assign ARSIZE   = 3'd3;
    assign ARBURST  = 2'b01;
    assign ARLOCK   = 2'd0;
    assign ARCACHE  = 4'd0;
    assign ARPROT   = 3'd0;
    assign ARQOS    = 4'd0;
    assign ARREGION = 4'd0;
    assign ARUSER   = 1'b0;
    assign ARVALID  = 1'b0;
    assign RREADY   = 1'b1;

endmodule
