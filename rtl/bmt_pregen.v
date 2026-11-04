`timescale 1ns / 1ps
// ============================================================================
// bmt_pregen.v — Background BMT share pre-generator with AES-GCM encryption
//
// Continuously generates Beaver Multiplication Triples, splits them into
// XOR shares, encrypts each server's shares with that server's AES-GCM key,
// and stores the results in per-server FIFOs. The packet FSM pops entries
// from these FIFOs when building envelopes.
//
// Each FIFO entry contains:
//   - iv       [95:0]   (12 bytes)
//   - ct0      [127:0]  (16 bytes — encrypted a,b)
//   - ct1      [127:0]  (16 bytes — upper 64 bits = encrypted c, lower 64 = 0)
//   - tag      [127:0]  (16 bytes)
//   Total: 52 bytes per encrypted triple
//
// The plaintext layout for each triple:
//   blk0 = {a_share[63:0], b_share[63:0]}  (16 bytes)
//   blk1 = {c_share[63:0], 64'h0}          (8 bytes + pad)
// ============================================================================

module bmt_pregen #(
    parameter FIFO_DEPTH = 128   // entries per server
) (
    input  wire         clk,
    input  wire         rst_n,

    // AES keys (hardcoded at top level, directly wired in)
    input  wire [127:0] key_s0,    // encryption key for server 0's shares
    input  wire [127:0] key_s1,    // encryption key for server 1's shares

    // PRNG seed -- REQUIRED once per reset before any triple is generated.
    //   The first seed_valid with nonzero seed_data after reset loads the
    //   PRNG and raises `seeded`; every later seed_valid is ignored until the
    //   next reset. An all-zero seed is ignored (all-zero is a fixed point of
    //   xoshiro256++: every draw would be 0).
    input  wire         seed_valid,
    input  wire [255:0] seed_data,
    output wire         seeded,

    // FIFO status
    output wire [$clog2(FIFO_DEPTH):0] fifo_count_s0,
    output wire [$clog2(FIFO_DEPTH):0] fifo_count_s1,

    // Pop interface for server 0's FIFO
    input  wire         pop_s0,
    output wire [95:0]  pop_iv_s0,
    output wire [127:0] pop_ct0_s0,
    output wire [127:0] pop_ct1_s0,
    output wire [127:0] pop_tag_s0,
    output wire         pop_valid_s0,

    // Pop interface for server 1's FIFO
    input  wire         pop_s1,
    output wire [95:0]  pop_iv_s1,
    output wire [127:0] pop_ct0_s1,
    output wire [127:0] pop_ct1_s1,
    output wire [127:0] pop_tag_s1,
    output wire         pop_valid_s1
);

    localparam CNTW = $clog2(FIFO_DEPTH) + 1;
    localparam PTRW = $clog2(FIFO_DEPTH);

    // =========================================================================
    // PRNG (xoshiro256++ — 64 bits per advance)
    // =========================================================================
    reg         prng_advance;
    wire [63:0] prng_out;

    // SEED GATE.
    //
    // The PRNG resets to fixed constants and the AES keys are fixed, so
    // without a fresh seed every reset would regenerate the same triples and
    // the same GCM IVs under the same keys: nonce reuse across boots, and
    // triple reuse across sessions. Generation is therefore held in G_IDLE
    // until a seed has been loaded.
    //
    // Exactly one load per reset. A seed_valid held high, or pulsed again
    // mid-triple, would otherwise reload the PRNG while draws are being
    // taken and hand out the same value more than once.
    reg  seeded_r;
    wire prng_seed_load = seed_valid && (seed_data != 256'b0) && !seeded_r;
    assign seeded = seeded_r;

    always @(posedge clk or negedge rst_n)
        if (!rst_n)              seeded_r <= 1'b0;
        else if (prng_seed_load) seeded_r <= 1'b1;

    prng_xoshiro256pp u_prng (
        .clk       (clk),
        .rst_n     (rst_n),
        .seed_valid(prng_seed_load),
        .seed_data (seed_data),
        .advance   (prng_advance),
        .rnd_out   (prng_out)
    );

    // =========================================================================
    // AES-GCM encrypt instance (shared, time-multiplexed between servers)
    // =========================================================================
    reg          gcm_start;
    reg  [127:0] gcm_key;
    reg  [95:0]  gcm_iv;
    reg  [127:0] gcm_blk0, gcm_blk1;
    wire [127:0] gcm_ct0, gcm_ct1;
    wire [127:0] gcm_tag;
    wire         gcm_done;

    aes_gcm_encrypt_24b u_gcm (
        .clk    (clk),
        .rst_n  (rst_n),
        .start  (gcm_start),
        .key    (gcm_key),
        .iv     (gcm_iv),
        .blk0   (gcm_blk0),
        .blk1   (gcm_blk1),
        .ct0    (gcm_ct0),
        .ct1    (gcm_ct1),
        .tag_out(gcm_tag),
        .done   (gcm_done)
    );

    // =========================================================================
    // Per-server FIFOs (register-based)
    // =========================================================================
    // Server 0
    reg [95:0]  fifo_iv_s0  [0:FIFO_DEPTH-1];
    reg [127:0] fifo_ct0_s0 [0:FIFO_DEPTH-1];
    reg [127:0] fifo_ct1_s0 [0:FIFO_DEPTH-1];
    reg [127:0] fifo_tag_s0 [0:FIFO_DEPTH-1];
    reg [PTRW-1:0] wr_ptr_s0, rd_ptr_s0;
    reg [CNTW-1:0] count_s0;

    // Server 1
    reg [95:0]  fifo_iv_s1  [0:FIFO_DEPTH-1];
    reg [127:0] fifo_ct0_s1 [0:FIFO_DEPTH-1];
    reg [127:0] fifo_ct1_s1 [0:FIFO_DEPTH-1];
    reg [127:0] fifo_tag_s1 [0:FIFO_DEPTH-1];
    reg [PTRW-1:0] wr_ptr_s1, rd_ptr_s1;
    reg [CNTW-1:0] count_s1;

    assign fifo_count_s0 = count_s0;
    assign fifo_count_s1 = count_s1;

    // Pop outputs (head of FIFO)
    assign pop_iv_s0  = fifo_iv_s0[rd_ptr_s0];
    assign pop_ct0_s0 = fifo_ct0_s0[rd_ptr_s0];
    assign pop_ct1_s0 = fifo_ct1_s0[rd_ptr_s0];
    assign pop_tag_s0 = fifo_tag_s0[rd_ptr_s0];
    assign pop_valid_s0 = (count_s0 != 0);

    assign pop_iv_s1  = fifo_iv_s1[rd_ptr_s1];
    assign pop_ct0_s1 = fifo_ct0_s1[rd_ptr_s1];
    assign pop_ct1_s1 = fifo_ct1_s1[rd_ptr_s1];
    assign pop_tag_s1 = fifo_tag_s1[rd_ptr_s1];
    assign pop_valid_s1 = (count_s1 != 0);

    // =========================================================================
    // Generation FSM
    // =========================================================================
    localparam [3:0]
        G_IDLE     = 4'd0,
        G_DRAW_A   = 4'd1,
        G_DRAW_B   = 4'd2,
        G_DRAW_S0A = 4'd3,
        G_DRAW_S0B = 4'd4,
        G_DRAW_S0C = 4'd5,
        G_DRAW_IV0 = 4'd6,  // IV for server 0 (96 bits = 1.5 draws, use 2)
        G_DRAW_IV1 = 4'd7,
        G_ENC_S0   = 4'd8,  // encrypt server 0's share
        G_WAIT_S0  = 4'd9,
        G_DRAW_IV2 = 4'd10, // IV for server 1
        G_DRAW_IV3 = 4'd11,
        G_ENC_S1   = 4'd12,
        G_WAIT_S1  = 4'd13,
        G_PUSH     = 4'd14;

    reg [3:0] gen_state;

    // Generated values
    reg [63:0] gen_a, gen_b, gen_c;
    reg [63:0] s0_a, s0_b, s0_c;
    reg [63:0] s1_a, s1_b, s1_c;
    reg [95:0] iv_for_s0, iv_for_s1;

    // Encrypted results (captured from GCM output)
    reg [95:0]  enc_iv_s0;
    reg [127:0] enc_ct0_s0, enc_ct1_s0, enc_tag_s0;
    reg [95:0]  enc_iv_s1;
    reg [127:0] enc_ct0_s1, enc_ct1_s1, enc_tag_s1;

    // Both FIFOs full? Retained: exported/observed elsewhere and used by the
    // formal properties. NOT used to gate generation any more -- see any_full.
    wire both_full = (count_s0 == FIFO_DEPTH) && (count_s1 == FIFO_DEPTH);

    // EITHER FIFO full. Generation must stall on this, not on both_full.
    //
    // both_full was an AND, so whenever the two servers drained at different
    // rates the generator kept running with one FIFO already at FIFO_DEPTH.
    // At G_PUSH that side's write guard was false, so its half of the triple
    // was silently discarded while the other half was enqueued -- the two
    // queues then differ by one entry for ever after, and s0_a ^ s1_a != a
    // for every subsequent AND gate, with no error indication anywhere.
    //
    // Stalling on any_full is sound: no push occurs between G_IDLE and
    // G_PUSH, so both counts can only decrease over those cycles. If neither
    // is full at the G_IDLE check, neither can be full at G_PUSH, and both
    // write guards are guaranteed true.
    wire any_full  = (count_s0 == FIFO_DEPTH) || (count_s1 == FIFO_DEPTH);

    // =========================================================================
    // Main generation loop
    // =========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            gen_state    <= G_IDLE;
            prng_advance <= 1'b0;
            gcm_start    <= 1'b0;
            gcm_key      <= 128'b0;
            gcm_iv       <= 96'b0;
            gcm_blk0     <= 128'b0;
            gcm_blk1     <= 128'b0;
            gen_a <= 64'b0; gen_b <= 64'b0; gen_c <= 64'b0;
            s0_a <= 64'b0; s0_b <= 64'b0; s0_c <= 64'b0;
            s1_a <= 64'b0; s1_b <= 64'b0; s1_c <= 64'b0;
            iv_for_s0 <= 96'b0; iv_for_s1 <= 96'b0;
            enc_iv_s0  <= 96'b0;  enc_ct0_s0 <= 128'b0;
            enc_ct1_s0 <= 128'b0; enc_tag_s0 <= 128'b0;
            enc_iv_s1  <= 96'b0;  enc_ct0_s1 <= 128'b0;
            enc_ct1_s1 <= 128'b0; enc_tag_s1 <= 128'b0;

            wr_ptr_s0 <= 0; rd_ptr_s0 <= 0; count_s0 <= 0;
            wr_ptr_s1 <= 0; rd_ptr_s1 <= 0; count_s1 <= 0;
        end else begin
            prng_advance <= 1'b0;
            gcm_start    <= 1'b0;

            // FIFO pop logic (independent of generation FSM)
            if (pop_s0 && count_s0 != 0) begin
                rd_ptr_s0 <= (rd_ptr_s0 == FIFO_DEPTH-1) ? 0 : rd_ptr_s0 + 1;
                count_s0  <= count_s0 - 1;
            end
            if (pop_s1 && count_s1 != 0) begin
                rd_ptr_s1 <= (rd_ptr_s1 == FIFO_DEPTH-1) ? 0 : rd_ptr_s1 + 1;
                count_s1  <= count_s1 - 1;
            end

            case (gen_state)

            // =================================================================
            G_IDLE: begin
                if (seeded_r && !any_full)
                    gen_state <= G_DRAW_A;
            end

            // =================================================================
            // Draw 5 random values for the triple + shares
            // =================================================================
            G_DRAW_A: begin
                prng_advance <= 1'b1;
                gen_state    <= G_DRAW_B;
            end

            G_DRAW_B: begin
                gen_a        <= prng_out;
                prng_advance <= 1'b1;
                gen_state    <= G_DRAW_S0A;
            end

            G_DRAW_S0A: begin
                gen_b        <= prng_out;
                gen_c        <= gen_a & prng_out;  // c = a & b
                prng_advance <= 1'b1;
                gen_state    <= G_DRAW_S0B;
            end

            G_DRAW_S0B: begin
                s0_a         <= prng_out;
                prng_advance <= 1'b1;
                gen_state    <= G_DRAW_S0C;
            end

            G_DRAW_S0C: begin
                s0_b         <= prng_out;
                prng_advance <= 1'b1;
                gen_state    <= G_DRAW_IV0;
            end

            // =================================================================
            // Draw IV for server 0's encryption (96 bits = 2 draws, use [95:0])
            // =================================================================
            G_DRAW_IV0: begin
                s0_c         <= prng_out;
                // Compute s1 shares
                s1_a         <= s0_a ^ gen_a;
                s1_b         <= s0_b ^ gen_b;
                s1_c         <= prng_out ^ gen_c;  // s0_c = prng_out this cycle
                prng_advance <= 1'b1;
                gen_state    <= G_DRAW_IV1;
            end

            G_DRAW_IV1: begin
                iv_for_s0[95:32] <= prng_out;
                prng_advance     <= 1'b1;
                gen_state        <= G_ENC_S0;
            end

            // =================================================================
            // Encrypt server 0's shares
            // =================================================================
            G_ENC_S0: begin
                iv_for_s0[31:0] <= prng_out[31:0];
                gcm_key  <= key_s0;
                gcm_iv   <= {iv_for_s0[95:32], prng_out[31:0]};
                gcm_blk0 <= {s0_a, s0_b};
                gcm_blk1 <= {s0_c, 64'h0};
                gcm_start <= 1'b1;
                gen_state <= G_WAIT_S0;
            end

            G_WAIT_S0: begin
                if (gcm_done) begin
                    enc_iv_s0  <= iv_for_s0;
                    enc_ct0_s0 <= gcm_ct0;
                    enc_ct1_s0 <= gcm_ct1;
                    enc_tag_s0 <= gcm_tag;
                    // Now draw IV for server 1
                    prng_advance <= 1'b1;
                    gen_state    <= G_DRAW_IV2;
                end
            end

            // =================================================================
            // Draw IV for server 1's encryption
            // =================================================================
            G_DRAW_IV2: begin
                iv_for_s1[95:32] <= prng_out;
                prng_advance     <= 1'b1;
                gen_state        <= G_DRAW_IV3;
            end

            G_DRAW_IV3: begin
                iv_for_s1[31:0] <= prng_out[31:0];
                gen_state       <= G_ENC_S1;
            end

            // =================================================================
            // Encrypt server 1's shares
            // =================================================================
            G_ENC_S1: begin
                gcm_key  <= key_s1;
                gcm_iv   <= iv_for_s1;
                gcm_blk0 <= {s1_a, s1_b};
                gcm_blk1 <= {s1_c, 64'h0};
                gcm_start <= 1'b1;
                gen_state <= G_WAIT_S1;
            end

            G_WAIT_S1: begin
                if (gcm_done) begin
                    enc_iv_s1  <= iv_for_s1;
                    enc_ct0_s1 <= gcm_ct0;
                    enc_ct1_s1 <= gcm_ct1;
                    enc_tag_s1 <= gcm_tag;
                    gen_state  <= G_PUSH;
                end
            end

            // =================================================================
            // Push encrypted entries into both FIFOs
            // =================================================================
            G_PUSH: begin
                // Push to server 0 FIFO if not full.
                //
                // This guard formerly read
                //     count_s0 < FIFO_DEPTH || (pop_s0 && count_s0 != 0)
                // to admit a write when a pop freed a slot on the same cycle.
                // Removed: the any_full stall in G_IDLE means G_PUSH is only
                // ever reached with room in both queues, so the second
                // disjunct could never be the reason a write happened. Proven
                // twice over -- a_push_has_room_s0/s1 assert it directly, and
                // a mutation forcing the guard true was shown equivalent to
                // the original by the MCY miter.
                //
                // Removing it also removes a subtle coupling: the widened
                // guard required the cancel clause below to drop its
                // `count < FIFO_DEPTH` term, or count would reach
                // FIFO_DEPTH+1. Two coupled edits, neither reachable, neither
                // executable by any test. If any_full is ever relaxed, both
                // must be reinstated together and verified.
                if (count_s0 < FIFO_DEPTH) begin
                    fifo_iv_s0[wr_ptr_s0]  <= enc_iv_s0;
                    fifo_ct0_s0[wr_ptr_s0] <= enc_ct0_s0;
                    fifo_ct1_s0[wr_ptr_s0] <= enc_ct1_s0;
                    fifo_tag_s0[wr_ptr_s0] <= enc_tag_s0;
                    wr_ptr_s0 <= (wr_ptr_s0 == FIFO_DEPTH-1) ? 0 : wr_ptr_s0 + 1;
                    count_s0  <= count_s0 + 1;
                end

                // Push to server 1 FIFO if not full. See the note above.
                if (count_s1 < FIFO_DEPTH) begin
                    fifo_iv_s1[wr_ptr_s1]  <= enc_iv_s1;
                    fifo_ct0_s1[wr_ptr_s1] <= enc_ct0_s1;
                    fifo_ct1_s1[wr_ptr_s1] <= enc_ct1_s1;
                    fifo_tag_s1[wr_ptr_s1] <= enc_tag_s1;
                    wr_ptr_s1 <= (wr_ptr_s1 == FIFO_DEPTH-1) ? 0 : wr_ptr_s1 + 1;
                    count_s1  <= count_s1 + 1;
                end

                // Handle simultaneous pop + push count adjustments.
                //
                // The `count < FIFO_DEPTH` term is restored: it must match the
                // write guard above. A write only happens when
                // count < FIFO_DEPTH, so the cancel must apply on exactly that
                // set. Widen one without the other and count either reaches
                // FIFO_DEPTH+1 or fails to decrement on a pop.
                if (pop_s0 && count_s0 != 0 && count_s0 < FIFO_DEPTH)
                    count_s0 <= count_s0;  // push and pop cancel out
                if (pop_s1 && count_s1 != 0 && count_s1 < FIFO_DEPTH)
                    count_s1 <= count_s1;

                gen_state <= G_IDLE;
            end

            default: gen_state <= G_IDLE;

            endcase
        end
    end

// ---------------------------------------------------------------------------
// Formal property attachment. Inert unless FORMAL is defined, which only
// `read -define FORMAL` / `read -formal` in the SymbiYosys flow does. Vivado
// never defines it, so the synthesized netlist is unaffected.
// ---------------------------------------------------------------------------
`ifdef FORMAL
`include "bmt_pregen_props_inst.vh"
`endif

endmodule
