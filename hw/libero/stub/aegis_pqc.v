// SPDX-License-Identifier: Apache-2.0
// Integration stub of aegis_pqc: same ports, only the ID register (0x00 = 0xAE15_0000).
// Used to prove the Libero plumbing (APB slot 14 at 0x40000E00) before the real core.
module aegis_pqc (
    input             PCLK,
    input             PRESETN,
    input             PSEL,
    input             PENABLE,
    input      [31:0] PADDR,
    input             PWRITE,
    input      [31:0] PWDATA,
    output     [31:0] PRDATA,
    output            PREADY,
    output            PSLVERR
);
    reg [31:0] scratch;
    always @(posedge PCLK or negedge PRESETN)
        if (!PRESETN) scratch <= 32'h0;
        else if (PSEL && PENABLE && PWRITE && PADDR[7:0] == 8'h04) scratch <= PWDATA;
    assign PRDATA = (PADDR[7:0] == 8'h00) ? 32'hAE150000 : (PADDR[7:0] == 8'h04) ? scratch : 32'h0;
    assign PREADY = 1'b1;
    assign PSLVERR = 1'b0;
endmodule
