// SPDX-License-Identifier: Apache-2.0
//
// aegis_modmul: pipelined modular multiplier, p = a * b mod q, for the two
// moduli used by aegis_ntt:
//   mode 0: q = 3329    (ML-KEM), n = 12
//   mode 1: q = 8380417 (ML-DSA), n = 23
//
// Reduction is Barrett (HAC Algorithm 14.42, base 2) with
//   q1 = x >> (n-1),  q3 = (q1 * mu) >> (n+1),  mu = floor(2^(2n) / q),
//   r  = (x - q3*q) mod 2^(n+2),  then two conditional subtractions.
// For every x <= (q-1)^2, 0 <= x - q3*q < 3q; this is checked exhaustively
// (block by block) in hw/model/ntt_hw.py, so the output is canonical.
//
// Inputs must be in [0, q). a and b are sampled in the cycle they are
// presented (they should come straight from registers); the result appears
// on p LAT = 4 clocks later. mode must be stable while data is in flight.
// No reset: the pipeline carries data only, validity is tracked by the user.

module aegis_modmul (
    input             clk,
    input             mode,
    input      [22:0] a,
    input      [22:0] b,
    output reg [22:0] p
);

    localparam [22:0] Q_D  = 23'd8380417;
    localparam [23:0] MU_D = 24'd8396807;    // floor(2^46 / 8380417)
    localparam [11:0] Q_K  = 12'd3329;
    localparam [12:0] MU_K = 13'd5039;       // floor(2^24 / 3329)

    // ---- stage 1: product ------------------------------------------------
    reg [45:0] x1;
    always @(posedge clk)
        x1 <= a * b;

    // ---- stage 2: q2 = q1 * mu --------------------------------------------
    wire [23:0] d_q1 = x1[45:22];
    wire [12:0] k_q1 = x1[23:11];
    reg  [47:0] d_q2;
    reg  [25:0] k_q2;
    reg  [24:0] x2;                          // low bits of x are enough for r
    always @(posedge clk) begin
        d_q2 <= d_q1 * MU_D;
        k_q2 <= k_q1 * MU_K;
        x2   <= x1[24:0];
    end

    // ---- stage 3: r = x - q3*q (mod 2^(n+2)) -----------------------------
    wire [23:0] d_q3 = d_q2[47:24];
    wire [12:0] k_q3 = k_q2[25:13];
    wire [46:0] d_t  = d_q3 * Q_D;
    wire [24:0] k_t  = k_q3 * Q_K;
    reg  [24:0] d_r;
    reg  [13:0] k_r;
    always @(posedge clk) begin
        d_r <= x2 - d_t[24:0];
        k_r <= x2[13:0] - k_t[13:0];
    end

    // ---- stage 4: r in [0, 3q) -> [0, q) and mode select --------------------
    wire [25:0] d_m1 = {1'b0, d_r} - {3'b000, Q_D};          // r - q
    wire [25:0] d_m2 = {1'b0, d_r} - {2'b00, Q_D, 1'b0};     // r - 2q
    wire [14:0] k_m1 = {1'b0, k_r} - {3'b000, Q_K};
    wire [14:0] k_m2 = {1'b0, k_r} - {2'b00, Q_K, 1'b0};
    wire [22:0] d_res = !d_m2[25] ? d_m2[22:0] : (!d_m1[25] ? d_m1[22:0] : d_r[22:0]);
    wire [11:0] k_res = !k_m2[14] ? k_m2[11:0] : (!k_m1[14] ? k_m1[11:0] : k_r[11:0]);
    always @(posedge clk)
        p <= mode ? d_res : {11'd0, k_res};

endmodule
