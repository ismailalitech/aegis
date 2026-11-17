// SPDX-License-Identifier: Apache-2.0
//
// aegis_sponge: a Keccak sponge whose state stays in the fabric between calls, so software moves only the bytes that
// enter or leave the sponge instead of the whole 200-byte state for every permutation (aegis_keccak).
//
//   - state: 1600 bits, one Keccak round per clock (aegis_keccak_round), 24 clocks per permutation
//   - host words: 50 x 32 bits, word w = lane w/2, half w%2 (as aegis_keccak); a write replaces the word, or XORs into
//     it when xor_mode is set (absorbing a block = XOR-writing rate/4 words)
//   - slots: 8 saved states in block RAM. SELECT n saves the working state to the current slot and loads slot n
//     (51 clocks); SELECT of the current slot does nothing. A slot never saved holds whatever the RAM held: CLEAR it.
//   - squeeze by DMA: nblk times { permute; write the first rate_lanes lanes, little-endian, as one AXI4 INCR burst of
//     64-bit beats to dma_addr + k * rate_lanes * 8 }. Refused (dma_err) if the address is not 8-byte aligned, rate_lanes
//     is 0 or above 21, nblk is 0, or the transfer would cross a 4 KiB boundary (AXI forbids bursts that do).
//     A write response other than OKAY sets dma_err and stops the command. One burst is in flight at a time.
//   - commands are ignored while busy; the APB wrapper (aegis_pqc2) stalls the bus instead of letting that happen.
//
// Commands (cmd, with cmd_valid for one clock): 1 PERMUTE, 2 CLEAR, 3 SELECT cmd_slot, 4 SQUEEZE_DMA.

`timescale 1ns / 1ps

module aegis_sponge #(
    parameter AXI_AW = 38
) (
    input                   clk,
    input                   rstn,

    input                   wr_en,
    input      [5:0]        wr_word,
    input      [31:0]       wr_data,
    input                   xor_mode,
    input      [5:0]        rd_word,
    output     [31:0]       rd_data,

    input                   cmd_valid,
    input      [2:0]        cmd,
    input      [2:0]        cmd_slot,
    input      [4:0]        dma_rate_lanes,
    input      [7:0]        dma_nblk,
    input      [AXI_AW-1:0] dma_addr,

    output                  busy,
    output                  dma_busy,
    output reg              dma_err,
    output reg [7:0]        dma_done_blk,
    output reg [2:0]        cur_slot,
    output reg [31:0]       perm_count,

    output reg [AXI_AW-1:0] m_awaddr,
    output     [7:0]        m_awlen,
    output     [2:0]        m_awsize,
    output     [1:0]        m_awburst,
    output     [3:0]        m_awcache,
    output     [2:0]        m_awprot,
    output reg              m_awvalid,
    input                   m_awready,
    output     [63:0]       m_wdata,
    output     [7:0]        m_wstrb,
    output                  m_wlast,
    output reg              m_wvalid,
    input                   m_wready,
    input      [1:0]        m_bresp,
    input                   m_bvalid,
    output                  m_bready
);

    localparam [2:0] C_PERMUTE = 3'd1, C_CLEAR = 3'd2, C_SELECT = 3'd3, C_SQUEEZE = 3'd4;
    localparam [3:0] S_IDLE = 4'd0, S_PERM = 4'd1, S_SAVE = 4'd2, S_LOAD = 4'd3,
                     S_DPERM = 4'd4, S_DAW = 4'd5, S_DW = 4'd6, S_DB = 4'd7;

    reg  [3:0]        state;
    reg  [1599:0]     st;
    reg  [4:0]        rnd;
    wire [1599:0]     st_next;
    reg  [4:0]        idx;          // lane counter for SAVE / LOAD (LOAD runs to 25: one clock of RAM latency)
    reg  [2:0]        next_slot;
    reg  [4:0]        rate;
    reg  [7:0]        nblk;
    reg  [4:0]        beat;

    aegis_keccak_round u_round (.s_in(st), .rnd(rnd), .s_out(st_next));

    // ---------------------------------------------------------------- slot RAM: {slot, lane} x 64 bits
    wire        ram_we    = (state == S_SAVE);
    wire [7:0]  ram_waddr = {cur_slot, idx};
    wire [7:0]  ram_raddr = {next_slot, idx};
    wire [63:0] ram_rdata;
    reg  [63:0] lane_at_idx;
    integer li;
    always @(*) begin
        lane_at_idx = 64'd0;
        for (li = 0; li < 25; li = li + 1)
            if (idx == li[4:0])
                lane_at_idx = st[64*li +: 64];
    end
    aegis_ram_sdp #(.AW(8), .DW(64)) u_slots (
        .clk(clk), .we(ram_we), .waddr(ram_waddr), .wdata(lane_at_idx), .raddr(ram_raddr), .rdata(ram_rdata));

    // ---------------------------------------------------------------- DMA command check
    wire [16:0] dma_bytes = {9'd0, dma_nblk} * {9'd0, dma_rate_lanes, 3'b000};
    wire [16:0] dma_end   = {5'd0, dma_addr[11:0]} + dma_bytes;
    wire        dma_ok    = (dma_addr[2:0] == 3'd0) && (dma_rate_lanes != 5'd0) && (dma_rate_lanes <= 5'd21) &&
                            (dma_nblk != 8'd0) && (dma_end <= 17'd4096);

    assign busy      = (state != S_IDLE);
    assign dma_busy  = (state == S_DPERM) || (state == S_DAW) || (state == S_DW) || (state == S_DB);
    assign m_awlen   = {3'd0, rate} - 8'd1;
    assign m_awsize  = 3'b011;          // 8 bytes per beat
    assign m_awburst = 2'b01;           // INCR
    assign m_awcache = 4'b0011;         // normal, non-cacheable, bufferable
    assign m_awprot  = 3'b000;
    assign m_wstrb   = 8'hFF;
    assign m_wlast   = (beat == rate - 5'd1);
    assign m_bready  = (state == S_DB);

    reg [63:0] lane_at_beat;
    integer bi;
    always @(*) begin
        lane_at_beat = 64'd0;
        for (bi = 0; bi < 25; bi = bi + 1)
            if (beat == bi[4:0])
                lane_at_beat = st[64*bi +: 64];
    end
    assign m_wdata = lane_at_beat;

    // ---------------------------------------------------------------- control
    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            state        <= S_IDLE;
            rnd          <= 5'd0;
            idx          <= 5'd0;
            cur_slot     <= 3'd0;
            next_slot    <= 3'd0;
            rate         <= 5'd0;
            nblk         <= 8'd0;
            beat         <= 5'd0;
            dma_err      <= 1'b0;
            dma_done_blk <= 8'd0;
            perm_count   <= 32'd0;
            m_awaddr     <= {AXI_AW{1'b0}};
            m_awvalid    <= 1'b0;
            m_wvalid     <= 1'b0;
        end else begin
            case (state)
            S_IDLE:
                if (cmd_valid) begin
                    case (cmd)
                    C_PERMUTE: begin
                        state <= S_PERM;
                        rnd   <= 5'd0;
                    end
                    C_SELECT:
                        if (cmd_slot != cur_slot) begin
                            next_slot <= cmd_slot;
                            idx       <= 5'd0;
                            state     <= S_SAVE;
                        end
                    C_SQUEEZE: begin
                        dma_done_blk <= 8'd0;
                        if (dma_ok) begin
                            dma_err  <= 1'b0;
                            rate     <= dma_rate_lanes;
                            nblk     <= dma_nblk;
                            m_awaddr <= dma_addr;
                            rnd      <= 5'd0;
                            state    <= S_DPERM;
                        end else begin
                            dma_err  <= 1'b1;
                        end
                    end
                    default: ;
                    endcase
                end
            S_PERM: begin
                rnd <= rnd + 5'd1;
                if (rnd == 5'd23) begin
                    perm_count <= perm_count + 32'd1;
                    state      <= S_IDLE;
                end
            end
            S_SAVE: begin
                idx <= idx + 5'd1;
                if (idx == 5'd24) begin
                    idx   <= 5'd0;
                    state <= S_LOAD;
                end
            end
            S_LOAD: begin
                idx <= idx + 5'd1;
                if (idx == 5'd25) begin
                    cur_slot <= next_slot;
                    state    <= S_IDLE;
                end
            end
            S_DPERM: begin
                rnd <= rnd + 5'd1;
                if (rnd == 5'd23) begin
                    perm_count <= perm_count + 32'd1;
                    m_awvalid  <= 1'b1;
                    state      <= S_DAW;
                end
            end
            S_DAW:
                if (m_awready) begin
                    m_awvalid <= 1'b0;
                    m_wvalid  <= 1'b1;
                    beat      <= 5'd0;
                    state     <= S_DW;
                end
            S_DW:
                if (m_wready) begin
                    if (m_wlast) begin
                        m_wvalid <= 1'b0;
                        state    <= S_DB;
                    end else begin
                        beat <= beat + 5'd1;
                    end
                end
            S_DB:
                if (m_bvalid) begin
                    if (m_bresp != 2'b00) begin
                        dma_err <= 1'b1;
                        state   <= S_IDLE;
                    end else begin
                        dma_done_blk <= dma_done_blk + 8'd1;
                        if (nblk == 8'd1) begin
                            state <= S_IDLE;
                        end else begin
                            nblk     <= nblk - 8'd1;
                            m_awaddr <= m_awaddr + {{(AXI_AW-8){1'b0}}, rate, 3'b000};
                            rnd      <= 5'd0;
                            state    <= S_DPERM;
                        end
                    end
                end
            default: state <= S_IDLE;
            endcase
        end
    end

    // ---------------------------------------------------------------- state register
    integer w;
    always @(posedge clk or negedge rstn) begin
        if (!rstn) begin
            st <= 1600'd0;
        end else if (state == S_PERM || state == S_DPERM) begin
            st <= st_next;
        end else if (state == S_LOAD) begin
            if (idx != 5'd0)
                for (w = 0; w < 25; w = w + 1)
                    if (idx == w[4:0] + 5'd1)
                        st[64*w +: 64] <= ram_rdata;
        end else if (state == S_IDLE) begin
            if (cmd_valid && cmd == C_CLEAR)
                st <= 1600'd0;
            else if (wr_en)
                for (w = 0; w < 50; w = w + 1)
                    if (wr_word == w[5:0])
                        st[32*w +: 32] <= xor_mode ? (st[32*w +: 32] ^ wr_data) : wr_data;
        end
    end

    reg [31:0] rd_mux;
    integer i;
    always @(*) begin
        rd_mux = 32'd0;
        for (i = 0; i < 50; i = i + 1)
            if (rd_word == i[5:0])
                rd_mux = st[32*i +: 32];
    end
    assign rd_data = rd_mux;

endmodule
