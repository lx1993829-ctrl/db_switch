// ============================================================================
// pilot_keyprov.sv -- AES key provisioning for the PILOT MPC switch (stage 1)
//
// Gatekeeper for aes_key_s0 / aes_key_s1. Collects the two 128-bit keys over
// a narrow write port at boot, checks them at commit, publishes them ONCE,
// then locks. bmt_pregen is held in reset until keys_valid.
//
// Stage 1: the controller writes the derived keys themselves.
// Stage 2: the controller writes the servers' public points (and a nonce);
//          an X25519 + HKDF core inside this module derives the keys. The
//          port list, the k_* properties and everything outside are unchanged.
//
// Written to the constraints this project's Yosys flow has taught:
//   - no `automatic int x = 0;` initialisers, no pilot_pkg functions
//   - negedge rst_n, like every other module (async2sync handling carries)
//   - flops, not memories (no memory-init ordering problem)
//   - widths sized to COUNT, not index
// ============================================================================
module pilot_keyprov (
    input  logic         clk,
    input  logic         rst_n,

    // ---- Write port (valid/ready; wrap in AXI-Lite if the board has it) ----
    //   wr_sel  0 : key_s0 word wr_idx        1 : key_s1 word wr_idx
    //           2 : commit (wr_idx, wr_data ignored)
    //           3 : reserved (accepted, no effect)
    input  logic         wr_valid,
    input  logic [1:0]   wr_sel,
    input  logic [1:0]   wr_idx,
    input  logic [31:0]  wr_data,
    output logic         wr_ready,

    // ---- Status ----
    output logic         keys_valid,
    output logic         commit_rejected,   // one-cycle pulse: commit refused

    // ---- To the switch / bmt_pregen ----
    output logic [127:0] aes_key_s0,
    output logic [127:0] aes_key_s1,
    output logic         bmt_rst_n
);
    localparam logic [1:0] SEL_K0     = 2'd0;
    localparam logic [1:0] SEL_K1     = 2'd1;
    localparam logic [1:0] SEL_COMMIT = 2'd2;

    // Shadow registers, written word by word. Never visible downstream.
    logic [127:0] k0_sh, k1_sh;
    // One bit per (key, word): 8 pieces must all arrive before a commit.
    logic [3:0]   k0_filled, k1_filled;

    wire wr_fire   = wr_valid && wr_ready;
    wire all_in    = (&k0_filled) && (&k1_filled);
    wire commit_ok = all_in && (k0_sh != k1_sh);

    // The write port closes the cycle keys_valid rises and never reopens
    // without reset. That is what makes the keys stable by construction.
    assign wr_ready  = !keys_valid;
    assign bmt_rst_n = rst_n & keys_valid;

    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            k0_sh           <= '0;
            k1_sh           <= '0;
            k0_filled       <= '0;
            k1_filled       <= '0;
            aes_key_s0      <= '0;
            aes_key_s1      <= '0;
            keys_valid      <= 1'b0;
            commit_rejected <= 1'b0;
        end else begin
            commit_rejected <= 1'b0;
            if (wr_fire) begin
                case (wr_sel)
                    SEL_K0: begin
                        k0_sh[wr_idx*32 +: 32] <= wr_data;
                        k0_filled[wr_idx]      <= 1'b1;
                    end
                    SEL_K1: begin
                        k1_sh[wr_idx*32 +: 32] <= wr_data;
                        k1_filled[wr_idx]      <= 1'b1;
                    end
                    SEL_COMMIT: begin
                        if (commit_ok) begin
                            aes_key_s0 <= k0_sh;
                            aes_key_s1 <= k1_sh;
                            keys_valid <= 1'b1;
                            // Scrub the shadows: after commit the only copy
                            // of each key is the published register.
                            k0_sh      <= '0;
                            k1_sh      <= '0;
                        end else begin
                            commit_rejected <= 1'b1;
                        end
                    end
                    default: ;
                endcase
            end
        end
    end

`ifdef FORMAL
`include "pilot_keyprov_props_inst.vh"
`endif
endmodule
