// SPDX-License-Identifier: Apache-2.0
//
// aegis_ram_sdp: simple dual-port RAM (one write port, one read port, one
// clock), written in the plain style synthesis tools infer as block or micro
// RAM. Synchronous read: rdata = mem[raddr] registered at the clock edge.
// A read and a write to the same address in the same cycle return the old
// data; aegis_ntt never relies on that case.

module aegis_ram_sdp #(
    parameter AW = 7,
    parameter DW = 23
) (
    input               clk,
    input               we,
    input      [AW-1:0] waddr,
    input      [DW-1:0] wdata,
    input      [AW-1:0] raddr,
    output reg [DW-1:0] rdata
);

    reg [DW-1:0] mem [0:(1 << AW) - 1];

    always @(posedge clk) begin
        if (we)
            mem[waddr] <= wdata;
        rdata <= mem[raddr];
    end

endmodule
