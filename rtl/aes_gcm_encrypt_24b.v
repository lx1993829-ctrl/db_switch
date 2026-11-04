`timescale 1ns / 1ps
// ============================================================================
// aes_gcm_encrypt_24b.v — Minimal AES-128-GCM encrypt for 24-byte payloads
//
// Encrypts exactly 24 bytes (two 128-bit blocks: one full, one 8-byte partial)
// and produces a 128-bit authentication tag. No AAD support (aad_len = 0).
//
// Interface:
//   - Pulse 'start' with key, iv, blk0, blk1 all valid.
//   - blk0 = plaintext[191:64] (bytes 0-15, full block)
//   - blk1 = {plaintext[63:0], 64'h0} (bytes 16-23, padded to 128 bits)
//   - After some cycles, 'done' pulses with ct0, ct1 (ciphertext) and tag_out.
//   - ct1 is already masked: only upper 64 bits are valid.
//
// Latency: ~30 cycles from start to done (11-cycle AES pipeline × 3 encryptions
//          + GHASH processing).
// ============================================================================

module aes_gcm_encrypt_24b (
    input  wire         clk,
    input  wire         rst_n,

    // Control
    input  wire         start,
    input  wire [127:0] key,
    input  wire [95:0]  iv,
    input  wire [127:0] blk0,     // plaintext bytes 0-15
    input  wire [127:0] blk1,     // {plaintext bytes 16-23, 64'h0}

    // Output
    output reg  [127:0] ct0,      // ciphertext block 0
    output reg  [127:0] ct1,      // ciphertext block 1 (upper 64 bits valid)
    output reg  [127:0] tag_out,
    output reg          done
);

    // =========================================================================
    // States
    // =========================================================================
    localparam [3:0]
        ST_IDLE      = 4'd0,
        ST_INIT_WAIT = 4'd1,  // wait for key settle (3 cycles)
        ST_SEND_H    = 4'd2,  // AES(K, 0) for H
        ST_SEND_EY0  = 4'd3,  // AES(K, IV||1) for E(Y0)
        ST_SEND_CTR2 = 4'd4,  // AES(K, IV||2) for block 0
        ST_SEND_CTR3 = 4'd5,  // AES(K, IV||3) for block 1
        ST_WAIT_PIPE = 4'd6,  // wait for pipeline outputs
        ST_GHASH_1   = 4'd7,  // feed ct0 to GHASH
        ST_GHASH_2   = 4'd8,  // feed ct1 to GHASH
        ST_GHASH_LEN = 4'd9,  // feed len block to GHASH
        ST_GHASH_W1  = 4'd10, // wait for GHASH stage 1
        ST_GHASH_W2  = 4'd11, // wait for GHASH stage 2
        ST_TAG       = 4'd12, // compute tag = GHASH ^ E(Y0)
        ST_DONE      = 4'd13;

    reg [3:0] state;

    // =========================================================================
    // Stored inputs
    // =========================================================================
    reg [127:0] key_r;
    reg [95:0]  iv_r;
    reg [127:0] blk0_r, blk1_r;

    // =========================================================================
    // AES pipeline interface
    // =========================================================================
    reg  [127:0] aes_plaintext;
    reg          aes_valid_in;
    wire [127:0] aes_ciphertext;
    wire         aes_valid_out;

    aes128_encrypt_pipeline_fpga u_aes (
        .clk       (clk),
        .rst_n     (rst_n),
        .enable    (1'b1),
        .plaintext (aes_plaintext),
        .key       (key_r),
        .valid_in  (aes_valid_in),
        .ciphertext(aes_ciphertext),
        .valid_out (aes_valid_out)
    );

    // =========================================================================
    // GHASH interface
    // =========================================================================
    reg  [127:0] ghash_data;
    reg          ghash_data_valid;
    reg          ghash_start;
    wire [127:0] ghash_result;
    wire         ghash_result_valid;
    wire         ghash_ready;
    reg  [127:0] h_key;

    ghash_single_cycle_fpga u_ghash (
        .clk        (clk),
        .rst_n      (rst_n),
        .enable     (1'b1),
        .start      (ghash_start),
        .h_key      (h_key),
        .data_in    (ghash_data),
        .data_valid (ghash_data_valid),
        .ghash_out  (ghash_result),
        .ghash_valid(ghash_result_valid),
        .ready      (ghash_ready)
    );

    // =========================================================================
    // Pipeline output capture
    // We send 4 items into the AES pipeline in order:
    //   1. AES(K, 0)       -> H
    //   2. AES(K, IV||1)   -> E(Y0) for tag
    //   3. AES(K, IV||2)   -> keystream for block 0
    //   4. AES(K, IV||3)   -> keystream for block 1
    // They come out 11 cycles later in the same order.
    // =========================================================================
    reg [2:0]   pipe_out_cnt;  // counts outputs: 0=H, 1=E(Y0), 2=ks0, 3=ks1
    reg [127:0] e_y0;
    reg [127:0] ct0_r, ct1_r;

    // Partial block mask: upper 64 bits valid
    localparam [127:0] MASK_8B = 128'hFFFFFFFF_FFFFFFFF_00000000_00000000;

    // Length block: {aad_len_bits, data_len_bits} = {0, 192}
    // 24 bytes = 192 bits
    localparam [127:0] LEN_BLOCK = {64'h0, 64'd192};

    // =========================================================================
    // Init wait counter
    // =========================================================================
    reg [1:0] init_wait;

    // =========================================================================
    // Main FSM
    // =========================================================================
    always @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state           <= ST_IDLE;
            key_r           <= 128'b0;
            iv_r            <= 96'b0;
            blk0_r          <= 128'b0;
            blk1_r          <= 128'b0;
            aes_plaintext   <= 128'b0;
            aes_valid_in    <= 1'b0;
            ghash_data      <= 128'b0;
            ghash_data_valid<= 1'b0;
            ghash_start     <= 1'b0;
            h_key           <= 128'b0;
            e_y0            <= 128'b0;
            ct0             <= 128'b0;
            ct1             <= 128'b0;
            ct0_r           <= 128'b0;
            ct1_r           <= 128'b0;
            tag_out         <= 128'b0;
            done            <= 1'b0;
            pipe_out_cnt    <= 3'd0;
            init_wait       <= 2'd0;
        end else begin
            // Defaults
            aes_valid_in    <= 1'b0;
            ghash_data_valid<= 1'b0;
            ghash_start     <= 1'b0;
            done            <= 1'b0;

            case (state)

            // =================================================================
            ST_IDLE: begin
                if (start) begin
                    key_r   <= key;
                    iv_r    <= iv;
                    blk0_r  <= blk0;
                    blk1_r  <= blk1;
                    pipe_out_cnt <= 3'd0;
                    init_wait    <= 2'd3;  // 3 cycles for round keys to settle
                    state        <= ST_INIT_WAIT;
                end
            end

            // =================================================================
            // Wait for combinational key expansion to settle through
            // the registered round key pipeline
            // =================================================================
            ST_INIT_WAIT: begin
                if (init_wait == 0)
                    state <= ST_SEND_H;
                else
                    init_wait <= init_wait - 1;
            end

            // =================================================================
            // Send AES(K, 0) — output will be H key for GHASH
            // =================================================================
            ST_SEND_H: begin
                aes_plaintext <= 128'b0;
                aes_valid_in  <= 1'b1;
                state         <= ST_SEND_EY0;
            end

            // =================================================================
            // Send AES(K, IV||1) — output will be E(Y0) for tag
            // =================================================================
            ST_SEND_EY0: begin
                aes_plaintext <= {iv_r, 32'h0000_0001};
                aes_valid_in  <= 1'b1;
                state         <= ST_SEND_CTR2;
            end

            // =================================================================
            // Send AES(K, IV||2) — keystream for block 0
            // =================================================================
            ST_SEND_CTR2: begin
                aes_plaintext <= {iv_r, 32'h0000_0002};
                aes_valid_in  <= 1'b1;
                state         <= ST_SEND_CTR3;
            end

            // =================================================================
            // Send AES(K, IV||3) — keystream for block 1
            // =================================================================
            ST_SEND_CTR3: begin
                aes_plaintext <= {iv_r, 32'h0000_0003};
                aes_valid_in  <= 1'b1;
                state         <= ST_WAIT_PIPE;
            end

            // =================================================================
            // Wait for pipeline outputs (4 results, 11 cycles apart each,
            // but they come out on consecutive cycles since inputs were
            // consecutive)
            // =================================================================
            ST_WAIT_PIPE: begin
                if (aes_valid_out) begin
                    case (pipe_out_cnt)
                        3'd0: begin
                            h_key <= aes_ciphertext;  // H = AES(K, 0)
                            // Start GHASH now that we have H
                            ghash_start <= 1'b1;
                        end
                        3'd1: begin
                            e_y0 <= aes_ciphertext;   // E(Y0) = AES(K, IV||1)
                        end
                        3'd2: begin
                            // ct0 = blk0 ^ AES(K, IV||2)
                            ct0_r <= blk0_r ^ aes_ciphertext;
                        end
                        3'd3: begin
                            // ct1 = (blk1 ^ AES(K, IV||3)) & MASK_8B
                            ct1_r <= (blk1_r ^ aes_ciphertext) & MASK_8B;
                            state <= ST_GHASH_1;
                        end
                    endcase
                    pipe_out_cnt <= pipe_out_cnt + 1;
                end
            end

            // =================================================================
            // Feed ciphertext blocks to GHASH
            // GHASH is 2-stage pipeline: feed, wait 2 cycles for result
            // =================================================================
            ST_GHASH_1: begin
                if (ghash_ready) begin
                    ghash_data       <= ct0_r;
                    ghash_data_valid <= 1'b1;
                    state            <= ST_GHASH_W1;
                end
            end

            ST_GHASH_W1: begin
                // Wait for GHASH to be ready for next input
                if (ghash_ready) begin
                    ghash_data       <= ct1_r;
                    ghash_data_valid <= 1'b1;
                    state            <= ST_GHASH_W2;
                end
            end

            ST_GHASH_W2: begin
                // Wait for GHASH to be ready for length block
                if (ghash_ready) begin
                    ghash_data       <= LEN_BLOCK;
                    ghash_data_valid <= 1'b1;
                    state            <= ST_TAG;
                end
            end

            // =================================================================
            // Wait for final GHASH result, compute tag
            // =================================================================
            ST_TAG: begin
                if (ghash_result_valid) begin
                    tag_out <= ghash_result ^ e_y0;
                    ct0     <= ct0_r;
                    ct1     <= ct1_r;
                    done    <= 1'b1;
                    state   <= ST_DONE;
                end
            end

            // =================================================================
            ST_DONE: begin
                state <= ST_IDLE;
            end

            default: state <= ST_IDLE;

            endcase
        end
    end

// ---------------------------------------------------------------------------
// Formal property attachment. Inert unless FORMAL is defined, which only the
// SymbiYosys flow does. Vivado never defines it.
// ---------------------------------------------------------------------------
`ifdef FORMAL
`include "aes_gcm_props_inst.vh"
`endif

endmodule
