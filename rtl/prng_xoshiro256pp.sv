// ============================================================================
// prng_xoshiro256pp.sv — xoshiro256++ PRNG
// Produces 64 bits of output every cycle when 'advance' is asserted.
// Reference: https://prng.di.unimi.it/xoshiro256plusplus.c
//
// The C reference update is sequential:
//   const uint64_t t = s[1] << 17;
//   s[2] ^= s[0];
//   s[3] ^= s[1];
//   s[1] ^= s[2];
//   s[0] ^= s[3];
//   s[2] ^= t;
//   s[3] = rotl(s[3], 45);
//
// We convert to parallel (all reads from old state):
//   s0_new = s0 ^ (s1 ^ s3)         // s0 ^= s3_new where s3_new = s3^s1
//   s1_new = s1 ^ (s2 ^ s0)         // s1 ^= s2_new where s2_new = s2^s0
//   s2_new = (s2 ^ s0) ^ (s1 << 17) // s2 ^= s0, then s2 ^= t
//   s3_new = rotl(s3 ^ s1, 45)      // s3 ^= s1, then s3 = rotl(s3, 45)
// ============================================================================
module prng_xoshiro256pp (
    input  logic        clk,
    input  logic        rst_n,
    input  logic        seed_valid,
    input  logic [255:0] seed_data,   // {s0, s1, s2, s3} packed big-endian
    input  logic        advance,      // pulse high to step the PRNG
    output logic [63:0] rnd_out
);

    logic [63:0] s0, s1, s2, s3;

    // ---- Rotate-left ----
    function automatic [63:0] rotl(input [63:0] x, input int unsigned k);
        rotl = (x << k) | (x >> (64 - k));
    endfunction

    // ---- Output: rotl(s0 + s3, 23) + s0 ----
    assign rnd_out = rotl(s0 + s3, 23) + s0;

    // ---- Next-state combinational logic ----
    wire [63:0] s0_next = s0 ^ s1 ^ s3;
    wire [63:0] s1_next = s1 ^ s2 ^ s0;
    wire [63:0] s2_next = s2 ^ s0 ^ (s1 << 17);
    wire [63:0] s3_next = rotl(s3 ^ s1, 45);

    // ---- State register ----
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            s0 <= 64'h5041525345434550;
            s1 <= 64'hDEADBEEFCAFEBABE;
            s2 <= 64'h0123456789ABCDEF;
            s3 <= 64'hFEDCBA9876543210;
        end else if (seed_valid) begin
            s0 <= seed_data[255:192];
            s1 <= seed_data[191:128];
            s2 <= seed_data[127:64];
            s3 <= seed_data[63:0];
        end else if (advance) begin
            s0 <= s0_next;
            s1 <= s1_next;
            s2 <= s2_next;
            s3 <= s3_next;
        end
    end

// Formal properties (prng.sby only). Uses its own define, not FORMAL, so the
// flows that read this file with -formal (bmt_pregen realaes, the switch)
// are unaffected.
`ifdef PRNG_PROPS
`include "prng_xoshiro256pp_props_inst.vh"
`endif

endmodule
