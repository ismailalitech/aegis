// SPDX-License-Identifier: Apache-2.0
//
// aegis_keccak: Keccak-f[1600] permutation, one round per clock, in place on
// a 1600-bit state register. The state is accessed as 50 32-bit words:
// word w = 2*lane + half, i.e. lane i low half = word 2i, high half = 2i+1.
//
// start (pulse) is ignored while busy. A permutation keeps busy high for 24
// clocks; done is sticky and cleared by the next accepted start. cycles holds
// the busy clock count of the last permutation (24). Word writes are ignored
// while busy (the caller also returns 0 for reads while busy).

`timescale 1ns / 1ps

module aegis_keccak (
    input             clk,
    input             rstn,
    input             start,
    input             wr_en,
    input      [5:0]  wr_word,
    input      [31:0] wr_data,
    input      [5:0]  rd_word,
    output     [31:0] rd_data,
    output reg        busy,
    output reg        done,
    output reg [31:0] cycles
);

    reg  [1599:0] st;
    reg  [4:0]    rnd;
    wire [1599:0] st_next;

    aegis_keccak_round u_round (.s_in(st), .rnd(rnd), .s_out(st_next));

    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            busy   <= 1'b0;
            done   <= 1'b0;
            rnd    <= 5'd0;
            cycles <= 32'd0;
        end else if (busy) begin
            rnd    <= rnd + 5'd1;
            cycles <= cycles + 32'd1;
            if (rnd == 5'd23) begin
                busy <= 1'b0;
                done <= 1'b1;
            end
        end else if (start) begin
            busy   <= 1'b1;
            done   <= 1'b0;
            rnd    <= 5'd0;
            cycles <= 32'd0;
        end
    end

    // State: round update while busy, otherwise per-word host writes.
    integer w;
    always @(posedge clk or negedge rstn) begin
        if (!rstn)
            st <= 1600'd0;
        else if (busy)
            st <= st_next;
        else if (wr_en)
            for (w = 0; w < 50; w = w + 1)
                if (wr_word == w)
                    st[32*w +: 32] <= wr_data;
    end

    // Read word mux; rd_word >= 50 reads 0.
    reg [31:0] rd_mux;
    integer i;
    always @(*) begin
        rd_mux = 32'd0;
        for (i = 0; i < 50; i = i + 1)
            if (rd_word == i)
                rd_mux = st[32*i +: 32];
    end
    assign rd_data = rd_mux;

endmodule
