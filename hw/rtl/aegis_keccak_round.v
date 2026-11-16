// SPDX-License-Identifier: Apache-2.0
//
// aegis_keccak_round: one Keccak-f[1600] round (theta, rho, pi, chi, iota),
// purely combinational. State packing: lane i = x + 5*y occupies
// s[64*i +: 64], lane bit z at s[64*i + z] (FIPS 202 state bytes 8i..8i+7,
// little-endian).

`timescale 1ns / 1ps

module aegis_keccak_round (
    input  [1599:0] s_in,
    input  [4:0]    rnd,
    output [1599:0] s_out
);

    // rho rotation offsets r[i], i = x + 5*y, packed 6 bits each (i = 0 at LSB)
    localparam [149:0] RHO = {
        6'd14, 6'd56, 6'd61, 6'd2,  6'd18,   // i = 24..20 (y = 4)
        6'd8,  6'd21, 6'd15, 6'd45, 6'd41,   // i = 19..15 (y = 3)
        6'd39, 6'd25, 6'd43, 6'd10, 6'd3,    // i = 14..10 (y = 2)
        6'd20, 6'd55, 6'd6,  6'd44, 6'd36,   // i =  9..5  (y = 1)
        6'd27, 6'd28, 6'd62, 6'd1,  6'd0     // i =  4..0  (y = 0)
    };

    reg [63:0] rc;
    always @(*) begin
        case (rnd)
            5'd0:  rc = 64'h0000000000000001;
            5'd1:  rc = 64'h0000000000008082;
            5'd2:  rc = 64'h800000000000808A;
            5'd3:  rc = 64'h8000000080008000;
            5'd4:  rc = 64'h000000000000808B;
            5'd5:  rc = 64'h0000000080000001;
            5'd6:  rc = 64'h8000000080008081;
            5'd7:  rc = 64'h8000000000008009;
            5'd8:  rc = 64'h000000000000008A;
            5'd9:  rc = 64'h0000000000000088;
            5'd10: rc = 64'h0000000080008009;
            5'd11: rc = 64'h000000008000000A;
            5'd12: rc = 64'h000000008000808B;
            5'd13: rc = 64'h800000000000008B;
            5'd14: rc = 64'h8000000000008089;
            5'd15: rc = 64'h8000000000008003;
            5'd16: rc = 64'h8000000000008002;
            5'd17: rc = 64'h8000000000000080;
            5'd18: rc = 64'h000000000000800A;
            5'd19: rc = 64'h800000008000000A;
            5'd20: rc = 64'h8000000080008081;
            5'd21: rc = 64'h8000000000008080;
            5'd22: rc = 64'h0000000080000001;
            5'd23: rc = 64'h8000000080008008;
            default: rc = 64'h0000000000000000;
        endcase
    end

    wire [319:0]  c;      // theta column parities, 5 x 64
    wire [319:0]  d;      // theta column effect
    wire [1599:0] e;      // after theta
    wire [1599:0] b;      // after rho and pi
    wire [1599:0] x;      // after chi

    genvar gx, gy;
    generate
        for (gx = 0; gx < 5; gx = gx + 1) begin : g_theta_c
            assign c[64*gx +: 64] = s_in[64*gx +: 64] ^ s_in[64*(gx+5) +: 64] ^
                                    s_in[64*(gx+10) +: 64] ^ s_in[64*(gx+15) +: 64] ^
                                    s_in[64*(gx+20) +: 64];
        end
        for (gx = 0; gx < 5; gx = gx + 1) begin : g_theta_d
            localparam integer XM = (gx + 4) % 5;
            localparam integer XP = (gx + 1) % 5;
            assign d[64*gx +: 64] = c[64*XM +: 64] ^ {c[64*XP +: 63], c[64*XP + 63]};
        end
        for (gy = 0; gy < 5; gy = gy + 1) begin : g_y
            for (gx = 0; gx < 5; gx = gx + 1) begin : g_x
                localparam integer I  = gx + 5 * gy;
                localparam integer R  = RHO[6*I +: 6];
                localparam integer PI = gy + 5 * ((2 * gx + 3 * gy) % 5);  // pi target
                localparam integer X1 = ((gx + 1) % 5) + 5 * gy;
                localparam integer X2 = ((gx + 2) % 5) + 5 * gy;
                assign e[64*I +: 64] = s_in[64*I +: 64] ^ d[64*gx +: 64];
                if (R == 0) begin : g_r0
                    assign b[64*PI +: 64] = e[64*I +: 64];
                end else begin : g_rn
                    assign b[64*PI +: 64] = {e[64*I +: 64-R], e[64*I+64-R +: R]};
                end
                // chi
                if (I == 0) begin : g_iota
                    assign x[64*I +: 64] = b[64*I +: 64] ^ (~b[64*X1 +: 64] & b[64*X2 +: 64]) ^ rc;
                end else begin : g_chi
                    assign x[64*I +: 64] = b[64*I +: 64] ^ (~b[64*X1 +: 64] & b[64*X2 +: 64]);
                end
            end
        end
    endgenerate

    assign s_out = x;

endmodule
