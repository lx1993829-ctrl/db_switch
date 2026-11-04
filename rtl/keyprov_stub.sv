// ============================================================================
// keyprov_stub.sv -- abstraction of pilot_keyprov for switch-level proofs
//
// Promises LESS than the implementation, never more (bug 2 in the handoff
// was a stub that promised more): keys are anyconst, distinct by assumption,
// and keys_valid rises at an ARBITRARY cycle after reset -- any moment the
// solver likes -- then sticks. Everything the switch proofs need is exactly
// the k_* contract, restated as assumptions on this stub's outputs.
// ============================================================================
module keyprov_stub (
    input  logic         clk,
    input  logic         rst_n,
    input  logic         wr_valid,
    input  logic [1:0]   wr_sel,
    input  logic [1:0]   wr_idx,
    input  logic [31:0]  wr_data,
    output logic         wr_ready,
    output logic         keys_valid,
    output logic         commit_rejected,
    output logic [127:0] aes_key_s0,
    output logic [127:0] aes_key_s1,
    output logic         bmt_rst_n
);
`ifdef KEYPROV_FIXED
    localparam bit IS_FIXED = 1'b1;
    // Deterministic form for the MCY campaigns: two instances in a miter
    // must agree on the keys and on when they appear, or the unmutated
    // design is inequivalent to itself. Distinct constants, keys_valid the
    // cycle after reset. The proofs use the free form below.
    localparam logic [127:0] f_k0 = 128'h0123_4567_89ab_cdef_0f1e_2d3c_4b5a_6978;
    localparam logic [127:0] f_k1 = 128'hfedc_ba98_7654_3210_8796_a5b4_c3d2_e1f0;
    wire f_go = 1'b1;
`else
    localparam bit IS_FIXED = 1'b0;
    (* anyconst *) logic [127:0] f_k0, f_k1;
    (* anyseq  *) logic          f_go;
    always @(*) assume (f_k0 != f_k1);
`endif

    always_ff @(posedge clk or negedge rst_n)
        if (!rst_n) keys_valid <= 1'b0;
        else if (f_go) keys_valid <= 1'b1;

    assign aes_key_s0      = keys_valid ? f_k0 : '0;
    assign aes_key_s1      = keys_valid ? f_k1 : '0;
    assign bmt_rst_n       = rst_n & keys_valid;
    assign wr_ready        = !keys_valid;
    assign commit_rejected = 1'b0;
endmodule