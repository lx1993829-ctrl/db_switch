`timescale 1ns / 1ps
// ============================================================================
// pilot_switch_top.sv — PILOT in-path BMT switch (v2)
//
// Changes from v1:
//   - BMT shares are pre-generated and pre-encrypted in the background
//     by bmt_pregen. The packet FSM just pops from the FIFO.
//   - No CAM needed: each triple is independently encrypted and popped.
//     Both servers get fresh entries from their respective FIFOs.
//   - BMT trailer format: per triple = [IV 12B][CT0 16B][CT1_hi 8B][TAG 16B]
//     = 52 bytes per triple.
//   - No more pairing / two-arrival logic. Each request is processed
//     independently.
//
// Request authentication (2026-10-01):
//   The link to the servers is untrusted, so every request is authenticated
//   before it consumes triples. A request now carries
//     bytes 42..45   SEQ  (the former reserved word of the PILOT header),
//                    32-bit big-endian, strictly increasing per server
//     bytes T..T+15  TAG = HMAC-SHA256(mac_key_s<sender>, bytes 14..T-1)[0:16]
//                    with T = 86 + payload_size*8 (right after the payload)
//   mac_key_s0/s1 are hardcoded (see "Keys" below). S_AUTH runs pilot_hmac over ibuf and serves the
//   request only if the tag matches AND SEQ is greater than the last SEQ
//   accepted from that server; otherwise the request is dropped and counted
//   (auth_drops / replay_drops). The SEQ high-water mark moves only on an
//   authenticated request, so a forged SEQ cannot burn sequence numbers.
//   Ethernet bytes 0..13 are not covered (rewritten by the network); every
//   PILOT field the switch acts on is.
//
// Response authentication (2026-10-02):
//   The triples are encrypted by bmt_pregen BEFORE any request exists, so their
//   GCM encryption cannot name the request. Instead the assembled response is
//   MAC'd as a whole, with the DESTINATION server's MAC key:
//     bytes 42..45   RSEQ, 32-bit big-endian, per destination server, 1, 2, ...
//                    (the response's reserved word, formerly zero)
//     bytes L..L+15  RTAG = HMAC-SHA256(mac_key_s<dst>, bytes 14..L-1)[0:16],
//                    L = 102 + payload*8 + bmt_count*52 (end of the trailer)
//   RTAG covers the header (incl. the echoed request tag, ranks and RSEQ), the
//   e/f payload and every triple's IV, ciphertext and GCM tag. A server accepts
//   a response only if RTAG verifies and RSEQ is above the last it accepted, so
//   triples cannot be replayed, reordered between responses or moved to
//   another request's response. S_RMAC runs the same pilot_hmac as S_AUTH (the
//   two never overlap). A request's MAC'd bytes cannot be read as a response's
//   or vice versa: requests carry flags bit 0 and REQUEST_MAGIC at 46..53,
//   responses FLAG_SWITCH_ENV and ENVELOPE_MAGIC.
//
// Keys (2026-10-07): HARDCODED, key provisioning deferred (pilot_keyprov.sv,
//   X25519 + HKDF, stays on the shelf). The four keys are the parameters
//   AES_KEY_S0/S1 and MAC_KEY_S0/S1; each server must be given its pair
//   (AES_KEY_Si, MAC_KEY_Si) out of band. Formal uses free constants instead
//   (see "Keys: hardcoded" below), so the proofs hold for any keys.
//
//   SEED GATE: with fixed keys, a PRNG seed that repeats across boots repeats
//   the GCM IVs under the same key (IV reuse breaks GCM) and repeats the
//   triples. So keys_valid -- which releases bmt_pregen and enables request
//   service -- rises only after a seed has arrived on seed_valid/seed_data,
//   and the seed is loaded before the first PRNG draw. Until then every
//   request is dropped as unprovisioned (unprovisioned_drops). The seed must
//   be fresh TRNG data on every boot. SEED_GATE=0 disables the gate
//   (keys_valid the cycle after reset; the default seed is then used).
//
//   (2026-10-07) An ALL-ZERO seed is ignored: it is xoshiro256++'s fixed
//   point, so it would freeze the PRNG at zero -- every triple zero, every
//   GCM IV identical. Exactly one seed is used per reset: bmt_pregen now
//   admits one nonzero seed and ignores every later one (its own gate,
//   proven by bmt_seed.sby), so the old re-seed pass-through is gone.
//   SEED_GATE=0 loads DEFAULT_SEED (the PRNG's former reset state) instead,
//   because bmt_pregen generates nothing until it has been seeded.
// ============================================================================
import pilot_pkg::*;

module pilot_switch_top #(
    // Must fit the largest PILOT request. With the default
    // IN_PATH_BMT_BUNDLE_SIZE=64, a bundle request carries bmt_count=64 and
    // payload_size=128, giving 102 + 128*8 + 64*52 = 4454 output bytes.
    // 2048 silently wraps obuf_wr; 8192 leaves headroom for a larger bundle.
    parameter MAX_FRAME_BYTES = 8192,
    parameter BMT_FIFO_DEPTH  = 128,
    // Hardware-side padding of the BMT trailer. Any request asking for a
    // nonzero number of triples is rounded UP to BMT_BUNDLE_SIZE, so the
    // encrypted trailer is always the same length and never reveals how many
    // triples the caller actually wanted. e/f payload is NOT padded here: it
    // is forwarded verbatim at whatever length the request specifies.
    // Set to 0 to disable padding and honour bmt_count exactly.
    parameter BMT_BUNDLE_SIZE = 64,
    // AXI-Stream data width in bits. Must be a power of 2, >= 8.
    parameter DATA_W = 512,
    // Keys, HARDCODED into the bitstream. The defaults are PLACEHOLDERS --
    // override at integration and keep the real values out of version
    // control. The two AES keys must differ (checked at elaboration below).
    parameter logic [127:0] AES_KEY_S0 = 128'h000102030405060708090a0b0c0d0e0f,
    parameter logic [127:0] AES_KEY_S1 = 128'h101112131415161718191a1b1c1d1e1f,
    parameter logic [255:0] MAC_KEY_S0 = 256'h202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f,
    parameter logic [255:0] MAC_KEY_S1 = 256'h404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f,
    // 1: hold request service and triple generation until a PRNG seed has
    //    arrived (see SEED GATE in the header). 0: start after reset.
    parameter bit SEED_GATE = 1'b1
) (
    input  logic        clk,
    input  logic        rst_n,


    // PRNG seed: REQUIRED with SEED_GATE=1 -- fresh TRNG data every boot
    input  logic         seed_valid,
    input  logic [255:0]  seed_data,

    // --- Port 0: Server 0 ---
    input  logic [DATA_W-1:0]   s0_tdata,
    input  logic [DATA_W/8-1:0] s0_tkeep,
    input  logic                s0_tlast,
    input  logic                s0_tvalid,
    output logic                s0_tready,

    output logic [DATA_W-1:0]   m0_tdata,
    output logic [DATA_W/8-1:0] m0_tkeep,
    output logic                m0_tlast,
    output logic                m0_tvalid,
    input  logic                m0_tready,

    // --- Port 1: Server 1 ---
    input  logic [DATA_W-1:0]   s1_tdata,
    input  logic [DATA_W/8-1:0] s1_tkeep,
    input  logic                s1_tlast,
    input  logic                s1_tvalid,
    output logic                s1_tready,

    output logic [DATA_W-1:0]   m1_tdata,
    output logic [DATA_W/8-1:0] m1_tkeep,
    output logic                m1_tlast,
    output logic                m1_tvalid,
    input  logic                m1_tready,

    // --- Port 2: Client ---
    input  logic [DATA_W-1:0]   s2_tdata,
    input  logic [DATA_W/8-1:0] s2_tkeep,
    input  logic                s2_tlast,
    input  logic                s2_tvalid,
    output logic                s2_tready,

    output logic [DATA_W-1:0]   m2_tdata,
    output logic [DATA_W/8-1:0] m2_tkeep,
    output logic                m2_tlast,
    output logic                m2_tvalid,
    input  logic                m2_tready
);

    localparam ADDR_W = $clog2(MAX_FRAME_BYTES);

    // COUNT width, one bit wider than the INDEX width.
    //
    // ADDR_W indexes the buffers: 0 .. MAX_FRAME_BYTES-1. But wr_byte,
    // ibuf_len, obuf_wr, obuf_len, out_byte_ptr and copy_idx are COUNTS, and
    // a full frame makes them reach MAX_FRAME_BYTES itself -- one value too
    // many. At ADDR_W bits that truncates to zero: an 8192-byte frame set
    // ibuf_len to 0, and wr_byte wrapped to 0 mid-ingest so the next writes
    // landed on top of the header.
    //
    // Found by pilot_switch.sby: a_wr_byte_no_wrap failed at step 7 with
    // wr_byte going backwards while still in S_INGEST.
    localparam CNT_W  = ADDR_W + 1;

    // Largest payload, in 8-byte words, whose assembled response still fits.
    //
    //   102 header + payload*8 + BMT_BUNDLE_SIZE*52 <= MAX_FRAME_BYTES
    //
    // req_payload_size comes off the wire as a full 32-bit field with no
    // clamp -- req_bmt_count is clamped, so the omission looks accidental.
    // S_COPY_EF and S_POP_BMT then both write at obuf_wr with no bound check,
    // so a large declared payload walks obuf_wr past the end of the buffer.
    //
    // Checking once here rather than guarding every write site: the request
    // is rejected before any work is done, and no partial frame is built.
    //
    // Rejection is a SILENT DROP, matching the software switch
    // (pilot_tap_switch.cpp), which does `continue` on any frame it cannot
    // handle -- no error response, no reply. Note the software has a 64 KB
    // receive buffer and no size limit of its own, so this rejection is a
    // hardware-imposed behaviour the reference does not have.
    //   ... + 16 bytes of RTAG (response authentication, see the header).
    //   MAX_FRAME_BYTES must be >= 118 + BMT_BUNDLE_SIZE*52 (else no response
    //   fits at all); the proof configurations use 176 with a bundle of 1.
    localparam integer MAX_PAYLOAD_WORDS =
        (MAX_FRAME_BYTES - 102 - 16 - BMT_BUNDLE_SIZE * 52) / 8;
    localparam KEEP_W = DATA_W / 8;  // bytes per beat

    // Request authentication (see the header comment).
    localparam int unsigned TAG_BYTES   = 16;
    localparam int unsigned MAC_START   = 14;    // first MAC'd byte (PILOT header)

    // =========================================================================
    // BMT pre-generator
    // =========================================================================
    wire pop_s0, pop_s1;
    wire [95:0]  pop_iv_s0,  pop_iv_s1;
    wire [127:0] pop_ct0_s0, pop_ct0_s1;
    wire [127:0] pop_ct1_s0, pop_ct1_s1;
    wire [127:0] pop_tag_s0, pop_tag_s1;
    wire         pop_valid_s0, pop_valid_s1;

    // ---- Keys: hardcoded ----
    // Synthesis and simulation use the parameters. Formal uses free
    // constants (the two AES keys assumed distinct), so every proof holds
    // for ANY keys, not just the defaults; the parameters are one such
    // choice, so the proofs cover the built design. Mutation campaigns
    // define PILOT_FIXED_KEYS: a miter's two instances must share the keys,
    // or the unmutated design is inequivalent to itself.
    // Equal AES keys stop elaboration. $error is the clear message where the
    // tool supports elaboration-time tasks; the missing module stops every
    // tool (Icarus ignores $error here), with its name in the error.
    if (AES_KEY_S0 == AES_KEY_S1) begin : g_key_check
        $error("pilot_switch_top: AES_KEY_S0 and AES_KEY_S1 must differ");
        ERROR_AES_KEY_S0_AND_S1_MUST_DIFFER u_err ();
    end
    logic [127:0] aes_key_s0, aes_key_s1;
    logic [255:0] mac_key_s0, mac_key_s1;
`ifdef FORMAL
`ifndef PILOT_FIXED_KEYS
    (* anyconst *) logic [127:0] f_aes_s0, f_aes_s1;
    (* anyconst *) logic [255:0] f_mac_s0, f_mac_s1;
    always @(*) assume (f_aes_s0 != f_aes_s1);
    assign aes_key_s0 = f_aes_s0;
    assign aes_key_s1 = f_aes_s1;
    assign mac_key_s0 = f_mac_s0;
    assign mac_key_s1 = f_mac_s1;
`else
    assign aes_key_s0 = AES_KEY_S0;
    assign aes_key_s1 = AES_KEY_S1;
    assign mac_key_s0 = MAC_KEY_S0;
    assign mac_key_s1 = MAC_KEY_S1;
`endif
`else
    assign aes_key_s0 = AES_KEY_S0;
    assign aes_key_s1 = AES_KEY_S1;
    assign mac_key_s0 = MAC_KEY_S0;
    assign mac_key_s1 = MAC_KEY_S1;
`endif

    // ---- Seed gate (see SEED GATE in the header) ----
    // The seed is latched; keys_valid rises the next cycle; in the first
    // cycle with keys_valid the generator has just left reset and loads the
    // latched seed on that edge, before its first draw. Later seed_valid
    // pulses are ignored until the next reset (one seed per reset).
    // DEFAULT_SEED is the PRNG's old reset state; used only with SEED_GATE=0.
    localparam logic [255:0] DEFAULT_SEED =
        {64'h5041525345434550, 64'hDEADBEEFCAFEBABE,
         64'h0123456789ABCDEF, 64'hFEDCBA9876543210};
    logic         keys_valid, have_seed, seeded;
    logic [255:0] seed_r;
    always_ff @(posedge clk or negedge rst_n)
        if (!rst_n) begin
            have_seed <= 1'b0; keys_valid <= 1'b0; seeded <= 1'b0;
            seed_r    <= SEED_GATE ? 256'b0 : DEFAULT_SEED;
        end else begin
            // A zero seed is not a seed (fixed point of xoshiro256++).
            if (seed_valid && seed_data != 256'b0 && !have_seed) begin
                seed_r    <= seed_data;
                have_seed <= 1'b1;
            end
            if (have_seed || !SEED_GATE) keys_valid <= 1'b1;
            if (keys_valid)              seeded     <= 1'b1;
        end
    // One load, in the first keys_valid cycle, of the latched (nonzero) seed.
    // seed_r is never zero here: with SEED_GATE=1 keys_valid waits for a
    // nonzero seed, with SEED_GATE=0 it holds DEFAULT_SEED or a nonzero seed.
    wire         bmt_seed_valid = keys_valid && !seeded;
    wire [255:0] bmt_seed_data  = seed_r;
    // bmt_pregen's own gate: high from the cycle after that load. Generation
    // starts only then (bmt_seed.sby).
    wire         bmt_seeded;

    // ---- Triple generator reset: held until keys_valid ----
    // (g_bmt_gate in the properties checks it)
    logic bmt_rst_n;
    assign bmt_rst_n = rst_n & keys_valid;

    bmt_pregen #(.FIFO_DEPTH(BMT_FIFO_DEPTH)) u_bmt (
        .clk(clk), .rst_n(bmt_rst_n),     // held in reset until keys_valid
        .key_s0(aes_key_s0), .key_s1(aes_key_s1),
        .seed_valid(bmt_seed_valid), .seed_data(bmt_seed_data),
        .seeded(bmt_seeded),
        .fifo_count_s0(), .fifo_count_s1(),
        .pop_s0(pop_s0), .pop_iv_s0(pop_iv_s0),
        .pop_ct0_s0(pop_ct0_s0), .pop_ct1_s0(pop_ct1_s0),
        .pop_tag_s0(pop_tag_s0), .pop_valid_s0(pop_valid_s0),
        .pop_s1(pop_s1), .pop_iv_s1(pop_iv_s1),
        .pop_ct0_s1(pop_ct0_s1), .pop_ct1_s1(pop_ct1_s1),
        .pop_tag_s1(pop_tag_s1), .pop_valid_s1(pop_valid_s1)
    );

    // =========================================================================
    // Frame buffers
    // =========================================================================
    logic [7:0] ibuf [0:MAX_FRAME_BYTES-1];
    logic [7:0] obuf [0:MAX_FRAME_BYTES-1];
    logic [CNT_W-1:0] ibuf_len;
    logic [CNT_W-1:0] obuf_len;

    // =========================================================================
    // State machine
    // =========================================================================
    typedef enum logic [3:0] {
        S_IDLE,
        S_INGEST,
        S_PARSE,
        S_BUILD_HDR,
        S_COPY_EF,
        S_POP_BMT,
        S_OUTPUT,
        S_DONE,
        S_DISCARD,  // oversized frame: consume to tlast, emit nothing
        S_AUTH,     // request: verify TAG and SEQ before serving it
        S_RMAC      // response: append RTAG before sending it
    } state_t;

    state_t state;

    // Oversized frames are counted rather than dropped silently. Without an
    // observable signal an operator cannot distinguish "no traffic" from
    // "every frame discarded", and the switch would look healthy while
    // dropping everything.
    logic [31:0] oversize_drops;
    // BUG 6 (2026-09-14): S_PARSE classified and routed on ibuf bytes the
    // frame never delivered. A 51-byte frame was parsed as a request with
    // payload_size read from stale ibuf[82..85], and S_COPY_EF then copied
    // the previous frame's bytes into a response. Found by
    // a_copy_src_in_len (pilot_switch_props.sv, task `leak`).
    //   MIN_ROUTE_BYTES: bytes 0..25 hold the receiver rank -- below this a
    //                    frame cannot even be routed.
    //   REQ_HDR_BYTES:   every field the request test reads lies in
    //                    0..85; the payload starts at 86.
    localparam int unsigned MIN_ROUTE_BYTES = 26;
    localparam int unsigned REQ_HDR_BYTES   = 86;
    logic [31:0] runt_drops;
    logic [31:0] unprovisioned_drops;   // requests seen while !keys_valid
    logic [31:0] auth_drops;            // requests with a wrong TAG
    logic [31:0] replay_drops;          // authentic requests with a stale SEQ
    logic [31:0] last_seq_s0, last_seq_s1;  // highest SEQ accepted per server
    logic [31:0] resp_seq_s0, resp_seq_s1;  // last RSEQ sent to each server

    // Parsed header fields
    logic [15:0] hdr_sender_rank, hdr_receiver_rank;
    logic [7:0]  hdr_msg_type;
    logic [31:0] hdr_tag, hdr_flags;
    logic [31:0] req_lane, req_bmt_count, req_bmt_count_raw, req_payload_size;
    logic        is_request;

    // Port selection
    logic [1:0]  in_port, out_port;

    // Counters
    logic [CNT_W-1:0] wr_byte, out_byte_ptr, obuf_wr, copy_idx;
    logic [31:0]       bmt_idx;

    // Pop control
    reg pop_s0_r, pop_s1_r;
    assign pop_s0 = pop_s0_r;
    assign pop_s1 = pop_s1_r;

    // Destination FIFO mux — selects the right server's FIFO outputs
    // based on out_port so S_POP_BMT doesn't duplicate the write logic.
    // A pop strobe already issued but not yet reflected in the FIFO count.
    //
    // pop_s0_r / pop_s1_r are REGISTERED, so a strobe reaches bmt_pregen one
    // cycle after the pop_valid that justified it. S_POP_BMT pops on
    // consecutive cycles, so when a FIFO drains the switch issues one strobe
    // too many:
    //
    //   cycle   count   switch sees        strobe out
    //     t       2     valid, set strobe    --
    //     t+1     2     valid, set strobe    pop (2->1)
    //     t+2     1     valid, set strobe    pop (1->0)
    //     t+3     0     invalid, stalls      POP ON EMPTY
    //
    // That breaks the assumption bmt_pregen_props.sv makes of its consumer:
    //     assume (!(pop_s0 && count_s0 == 0));
    // The generator guards its own pop, so nothing is corrupted today, but
    // the obligation was being violated. Found by pilot_switch.sby: the
    // assertion g_pop_s0_nonempty, added specifically to discharge that
    // assumption, failed at step 27.
    //
    // FIX: do not issue a strobe while one is in flight. That pops every
    // other cycle instead of every cycle.
    //
    // The alternative -- tracking the count and subtracting in-flight pops --
    // keeps full rate but needs fifo_count_s0/s1 wired out of bmt_pregen
    // (currently left unconnected) and a comparison rather than a boolean.
    // Not worth it: tb_pregen_rate measured 4928 cycles to GENERATE a bundle
    // against 894 to deliver one, so the design is generator-bound by 5.5x
    // and BMT_BUNDLE_SIZE extra cycles here disappear into that.
    wire         pop_inflight  = pop_s0_r || pop_s1_r;
    wire         dst_pop_valid = ((out_port == 2'd1) ? pop_valid_s1 : pop_valid_s0)
                                 && !pop_inflight;
    wire [95:0]  dst_pop_iv    = (out_port == 2'd1) ? pop_iv_s1    : pop_iv_s0;
    wire [127:0] dst_pop_ct0   = (out_port == 2'd1) ? pop_ct0_s1   : pop_ct0_s0;
    wire [127:0] dst_pop_ct1   = (out_port == 2'd1) ? pop_ct1_s1   : pop_ct1_s0;
    wire [127:0] dst_pop_tag   = (out_port == 2'd1) ? pop_tag_s1   : pop_tag_s0;

    // =========================================================================
    // Request authentication: HMAC-SHA256 over ibuf[MAC_START .. T-1]
    // =========================================================================
    logic         hmac_start;            // one-cycle pulse, first cycle of S_AUTH
    logic [255:0] hmac_key;
    logic [15:0]  hmac_len;
    wire          hmac_busy, hmac_done, hmac_err;
    wire  [255:0] hmac_mac;
    wire  [10:0]  hmac_msg_idx;
    logic [511:0] hmac_msg_blk;

    // Message window: block j is ibuf[MAC_START + 64*j .. +63] (request), or
    // obuf[...] in S_RMAC (response). ibuf is written only in S_INGEST and obuf
    // not at all during S_RMAC, so the message is fixed for the whole run.
    // Bytes at or beyond MAX_FRAME_BYTES, and blocks j >= WIN_BLKS, read 0.
    //
    // Written as a select on the BLOCK index: lane k of block j can only be
    // byte MAC_START + 64*j + k, so each lane is a WIN_BLKS-way mux (4 at
    // 256-byte frames, 128 at 8192) rather than a mux over the whole buffer
    // indexed by a computed address. Same function; the computed-address
    // form cost 64 full-buffer muxes per buffer, per clock, in every proof.
    localparam int unsigned WIN_BLKS = (MAX_FRAME_BYTES - MAC_START + 63) / 64;
    always_comb
        for (int k = 0; k < 64; k++) begin
            automatic logic [7:0] bi, bo;
            bi = 8'h00;
            bo = 8'h00;
            for (int j = 0; j < WIN_BLKS; j++)
                if (hmac_msg_idx == j && MAC_START + 64 * j + k < MAX_FRAME_BYTES) begin
                    bi = ibuf[(MAC_START + 64 * j + k < MAX_FRAME_BYTES) ? MAC_START + 64 * j + k : 0];
                    bo = obuf[(MAC_START + 64 * j + k < MAX_FRAME_BYTES) ? MAC_START + 64 * j + k : 0];
                end
            // S_AUTH MACs the request in ibuf, S_RMAC the response in obuf
            hmac_msg_blk[(63 - k)*8 +: 8] = (state == S_RMAC) ? bo : bi;
        end

`ifdef HMAC_STUB
    // Formal: arbitrary MAC and latency (hmac_stub.sv); pilot_hmac is proven
    // on its own by pilot_hmac.sby.
    hmac_stub u_hmac (
        .clk(clk), .rst_n(rst_n), .start(hmac_start), .key(hmac_key),
        .msg_len(hmac_len), .busy(hmac_busy), .done(hmac_done), .err(hmac_err),
        .mac(hmac_mac), .msg_idx(hmac_msg_idx), .msg_blk(hmac_msg_blk));
`else
    wire         ah_init, ah_next, ah_ready, ah_dv;
    wire [511:0] ah_block;
    wire [255:0] ah_digest;
    pilot_hmac #(.MAX_LEN(MAX_FRAME_BYTES)) u_hmac (
        .clk(clk), .rst_n(rst_n), .start(hmac_start), .key(hmac_key),
        .msg_len(hmac_len), .busy(hmac_busy), .done(hmac_done), .err(hmac_err),
        .mac(hmac_mac), .msg_idx(hmac_msg_idx), .msg_blk(hmac_msg_blk),
        .sha_init(ah_init), .sha_next(ah_next), .sha_block(ah_block),
        .sha_ready(ah_ready), .sha_digest(ah_digest));
    sha256_core u_sha_auth (
        .clk(clk), .reset_n(rst_n), .init(ah_init), .next(ah_next), .mode(1'b1),
        .block(ah_block), .ready(ah_ready), .digest(ah_digest), .digest_valid(ah_dv));
`endif

    // Received TAG and SEQ of the request being authenticated (S_AUTH).
    // TAG = ibuf[86 + 8P .. +15]. Only read in S_AUTH, which S_PARSE enters
    // only with P <= MAX_PAYLOAD_WORDS, so it is selected by P over that range
    // (a (MAX_PAYLOAD_WORDS+1)-way mux per byte instead of a whole-buffer mux);
    // it reads 0 for any larger P. Every index is inside ibuf:
    // 86 + 8*MAX_PAYLOAD_WORDS + 15 < MAX_FRAME_BYTES by MAX_PAYLOAD_WORDS'
    // definition.
    logic [127:0] rx_tag;
    always_comb begin
        rx_tag = '0;
        for (int p = 0; p <= MAX_PAYLOAD_WORDS; p++)
            if (req_payload_size == p)
                for (int b = 0; b < 16; b++)
                    rx_tag[(15 - b)*8 +: 8] = ibuf[REQ_HDR_BYTES + 8 * p + b];
    end
    wire [31:0] rx_seq   = {ibuf[42], ibuf[43], ibuf[44], ibuf[45]};
    wire        rx_srv1  = (hdr_sender_rank == RANK_SERVER1);
    wire [31:0] last_seq = rx_srv1 ? last_seq_s1 : last_seq_s0;
    wire        tag_ok   = !hmac_err && (hmac_mac[255:128] == rx_tag);
    wire        seq_ok   = (rx_seq > last_seq);

    // =========================================================================
    // Input mux
    // =========================================================================
    logic [DATA_W-1:0] in_tdata;
    logic [KEEP_W-1:0] in_tkeep;
    logic              in_tlast, in_tvalid;

    always_comb begin
        case (in_port)
            2'd0: begin in_tdata=s0_tdata; in_tkeep=s0_tkeep; in_tlast=s0_tlast; in_tvalid=s0_tvalid; end
            2'd1: begin in_tdata=s1_tdata; in_tkeep=s1_tkeep; in_tlast=s1_tlast; in_tvalid=s1_tvalid; end
            2'd2: begin in_tdata=s2_tdata; in_tkeep=s2_tkeep; in_tlast=s2_tlast; in_tvalid=s2_tvalid; end
            default: begin in_tdata='0; in_tkeep='0; in_tlast=0; in_tvalid=0; end
        endcase
    end

    // Only accept beats in S_INGEST. S_IDLE snoops tvalid to pick the port and
    // transition, but must NOT assert tready there: it has no write path into
    // ibuf, so a beat accepted in S_IDLE would be silently dropped. The master
    // holds tdata/tvalid until tready, so nothing is lost by waiting one cycle.
    wire in_accept = (state == S_INGEST);
    assign s0_tready = in_accept && (in_port == 2'd0);
    assign s1_tready = in_accept && (in_port == 2'd1);
    assign s2_tready = in_accept && (in_port == 2'd2);

    // =========================================================================
    // Output mux
    // =========================================================================
    logic [DATA_W-1:0] out_tdata_r;
    logic [KEEP_W-1:0] out_tkeep_r;
    logic              out_tlast_r, out_tvalid_r, out_tready_w;

    always_comb begin
        m0_tdata='0; m0_tkeep='0; m0_tlast=0; m0_tvalid=0;
        m1_tdata='0; m1_tkeep='0; m1_tlast=0; m1_tvalid=0;
        m2_tdata='0; m2_tkeep='0; m2_tlast=0; m2_tvalid=0;
        out_tready_w = 0;
        if (state == S_OUTPUT) begin
            case (out_port)
                2'd0: begin m0_tdata=out_tdata_r; m0_tkeep=out_tkeep_r;
                            m0_tlast=out_tlast_r; m0_tvalid=out_tvalid_r;
                            out_tready_w=m0_tready; end
                2'd1: begin m1_tdata=out_tdata_r; m1_tkeep=out_tkeep_r;
                            m1_tlast=out_tlast_r; m1_tvalid=out_tvalid_r;
                            out_tready_w=m1_tready; end
                2'd2: begin m2_tdata=out_tdata_r; m2_tkeep=out_tkeep_r;
                            m2_tlast=out_tlast_r; m2_tvalid=out_tvalid_r;
                            out_tready_w=m2_tready; end
                default: out_tready_w = 1;
            endcase
        end
    end

    // =========================================================================
    // Byte write helpers
    // =========================================================================
    integer _i;

    // =========================================================================
    // Main FSM
    // =========================================================================
    always_ff @(posedge clk or negedge rst_n) begin
        if (!rst_n) begin
            state        <= S_IDLE;
            in_port      <= 2'd0;
            out_port     <= 2'd0;
            wr_byte      <= '0;
            ibuf_len     <= '0;
            obuf_len     <= '0;
            obuf_wr      <= '0;
            out_byte_ptr <= '0;
            copy_idx     <= '0;
            bmt_idx      <= '0;
            is_request   <= 0;
            pop_s0_r     <= 0;
            pop_s1_r     <= 0;
            out_tvalid_r <= 0;
            out_tdata_r  <= '0;
            out_tkeep_r  <= '0;
            out_tlast_r  <= 0;
            oversize_drops <= '0;
            runt_drops     <= '0;
            unprovisioned_drops <= '0;
            auth_drops   <= '0;
            replay_drops <= '0;
            last_seq_s0  <= '0;
            last_seq_s1  <= '0;
            resp_seq_s0  <= '0;
            resp_seq_s1  <= '0;
            hmac_start   <= 1'b0;
            hmac_key     <= '0;
            hmac_len     <= '0;
        end else begin
            pop_s0_r <= 0;
            pop_s1_r <= 0;
            hmac_start <= 1'b0;

            case (state)

            // =================================================================
            S_IDLE: begin
                wr_byte      <= '0;
                ibuf_len     <= '0;
                out_tvalid_r <= 0;

                if (s0_tvalid)      begin in_port <= 2'd0; state <= S_INGEST; end
                else if (s1_tvalid) begin in_port <= 2'd1; state <= S_INGEST; end
                else if (s2_tvalid) begin in_port <= 2'd2; state <= S_INGEST; end
            end

            // =================================================================
            S_INGEST: begin
                if (in_tvalid) begin
                    // OVERSIZED FRAME GUARD.
                    //
                    // Ingest was previously unbounded: a frame longer than
                    // MAX_FRAME_BYTES kept writing, and wr_byte is only
                    // ADDR_W bits, so it WRAPPED rather than saturating --
                    // byte MAX_FRAME_BYTES landed at ibuf[0], overwriting the
                    // header the parser was about to read. ibuf_len wrapped
                    // with it. At the production 8192 that is reachable from
                    // the wire with a jumbo frame, which is under active
                    // consideration for this design because the 4454-byte
                    // output already exceeds the 1500-byte MTU.
                    //
                    // Found by pilot_switch.sby: a_ingest_in_range failed at
                    // step 7 on a six-beat frame, 384 bytes into a 256-byte
                    // buffer at the reduced proof size.
                    //
                    // The frame is discarded rather than truncated. Truncating
                    // would hand the parser a partial header and let it act on
                    // whatever the length fields happened to contain.
                    if (wr_byte + KEEP_W > MAX_FRAME_BYTES) begin
                        oversize_drops <= oversize_drops + 1;
                        state          <= in_tlast ? S_IDLE : S_DISCARD;
                    end else begin
                    for (_i = 0; _i < KEEP_W; _i++) begin
                        if (in_tkeep[KEEP_W-1-_i])
                            ibuf[wr_byte + _i] <= in_tdata[(KEEP_W-1-_i)*8 +: 8];
                    end
                    begin
                        automatic int vb;
                        vb = 0;
                        for (int i = 0; i < KEEP_W; i++)
                            if (in_tkeep[i]) vb++;
                        wr_byte <= wr_byte + vb[CNT_W-1:0];
                    end
                    if (in_tlast) begin
                        begin
                            automatic int vb;
                            vb = 0;
                            for (int i = 0; i < KEEP_W; i++)
                                if (in_tkeep[i]) vb++;
                            ibuf_len <= wr_byte + vb[CNT_W-1:0];
                        end
                        state <= S_PARSE;
                    end
                    end
                end
            end

            // =================================================================
            // Consume the rest of an oversized frame and emit nothing. Without
            // this the next beat would be taken as the start of a new frame
            // and the tail of the old one parsed as a header.
            // =================================================================
            S_DISCARD: begin
                if (in_tvalid && in_tlast)
                    state <= S_IDLE;
            end

            // =================================================================
            S_PARSE: begin
                hdr_msg_type      <= ibuf[19];
                hdr_sender_rank   <= {ibuf[22], ibuf[23]};
                hdr_receiver_rank <= {ibuf[24], ibuf[25]};
                hdr_tag           <= {ibuf[26], ibuf[27], ibuf[28], ibuf[29]};
                hdr_flags         <= {ibuf[38], ibuf[39], ibuf[40], ibuf[41]};

                begin
                    automatic logic [15:0] sr;
                    automatic logic [15:0] rr;
                    automatic logic [7:0] mt;
                    automatic logic [31:0] fl;
                    automatic logic [63:0] pw0;
                    sr = {ibuf[22], ibuf[23]};
                    rr = {ibuf[24], ibuf[25]};
                    mt = ibuf[19];
                    fl = {ibuf[38], ibuf[39], ibuf[40], ibuf[41]};
                    pw0 = {ibuf[46], ibuf[47], ibuf[48], ibuf[49], ibuf[50], ibuf[51], ibuf[52], ibuf[53]};

                    // Functions from pilot_pkg inlined by hand.
                    //
                    // Yosys inlines SV functions into scopes named like
                    //     is_server_rank$func$pilot_switch_top.sv:412$15429
                    // and those names do not survive MCY's export: write_verilog
                    // dies with an internal assertion (count_id(wire->name)==0),
                    // write_rtlil produces "used but has no driver" warnings, and
                    // port connections into the property module are silently
                    // dropped -- the counterexample VCD showed
                    // pilot_switch_top.m0_tvalid = 1 while u_props.m0_tvalid = 0
                    // on the UNMUTATED design.
                    //
                    // The three functions are one-liners, so inlining them costs
                    // nothing and removes the mangled scopes entirely.
                    if (ibuf_len < MIN_ROUTE_BYTES) begin
                        // Runt: not even the receiver rank arrived. Drop.
                        runt_drops <= runt_drops + 1;
                        is_request <= 0;
                        state      <= S_IDLE;
                    end else if (ibuf_len >= REQ_HDR_BYTES &&
                        ((sr == RANK_SERVER0) || (sr == RANK_SERVER1)) &&
                        ((rr == RANK_SERVER0) || (rr == RANK_SERVER1)) &&
                        mt == MSG_TYPE_VECTOR && fl[0] && pw0 == REQUEST_MAGIC) begin

                        is_request       <= 1;
                        req_lane         <= {ibuf[66], ibuf[67], ibuf[68], ibuf[69]};
                        // Store both counts:
                        //   req_bmt_count     = padded (for header + trailer size)
                        //   req_bmt_count_raw = original (for real FIFO pops)
                        // S_POP_BMT pops real triples for [0..raw), then
                        // zero-fills entries [raw..padded) so the trailer is
                        // always BMT_BUNDLE_SIZE entries. bmt_count=0 stays 0.
                        begin
                            automatic logic [31:0] raw_bmt;
                            raw_bmt =  {ibuf[74], ibuf[75], ibuf[76], ibuf[77]};
                            req_bmt_count_raw <= raw_bmt;
                            if (BMT_BUNDLE_SIZE != 0 && raw_bmt != 32'd0)
                                req_bmt_count <= BMT_BUNDLE_SIZE[31:0];
                            else
                                req_bmt_count <= raw_bmt;
                        end
                        req_payload_size <= {ibuf[82], ibuf[83], ibuf[84], ibuf[85]};
                        out_port         <= (sr == RANK_SERVER0) ? 2'd1 : 2'd0;
                        obuf_wr          <= '0;
                        copy_idx         <= '0;

                        // Reject a request before keys are provisioned
                        // (u_bmt is in reset; there is nothing to serve),
                        // one whose response could not fit, or one whose
                        // declared payload plus TAG exceeds what actually
                        // arrived (the copy would read stale ibuf -- bug 6;
                        // so would the TAG read).
                        if (!keys_valid) begin
                            unprovisioned_drops <= unprovisioned_drops + 1;
                            state               <= S_IDLE;
                        end else if ({ibuf[82], ibuf[83], ibuf[84], ibuf[85]} > MAX_PAYLOAD_WORDS
                            || REQ_HDR_BYTES + {ibuf[82], ibuf[83], ibuf[84], ibuf[85]} * 8
                               + TAG_BYTES > ibuf_len) begin
                            oversize_drops <= oversize_drops + 1;
                            state          <= S_IDLE;
                        end else begin
                            // Authenticate first: MAC over bytes 14 .. T-1,
                            // T = 86 + payload*8, with the sender's key.
                            hmac_start <= 1'b1;
                            hmac_key   <= (sr == RANK_SERVER1) ? mac_key_s1 : mac_key_s0;
                            hmac_len   <= 16'(REQ_HDR_BYTES - MAC_START
                                              + {ibuf[82], ibuf[83], ibuf[84], ibuf[85]} * 8);
                            state      <= S_AUTH;
                        end
                    end else begin
                        is_request   <= 0;
                        out_port     <= rr[1:0];
                        obuf_len     <= ibuf_len;
                        out_byte_ptr <= '0;
                        state        <= S_OUTPUT;
                    end
                end
            end

            // =================================================================
            // Wait for the MAC. Serve only an authentic, fresh request; the
            // SEQ high-water mark moves only on an authentic one.
            // =================================================================
            S_AUTH: begin
                if (hmac_done) begin
                    if (!tag_ok) begin
                        auth_drops <= auth_drops + 1;
                        state      <= S_IDLE;
                    end else if (!seq_ok) begin
                        replay_drops <= replay_drops + 1;
                        state        <= S_IDLE;
                    end else begin
                        if (rx_srv1) last_seq_s1 <= rx_seq;
                        else         last_seq_s0 <= rx_seq;
                        state <= S_BUILD_HDR;
                    end
                end
            end

            // =================================================================
            S_BUILD_HDR: begin
                begin
                    automatic logic [15:0] dst_rank;
                    automatic logic [47:0] dst_mac;
                    automatic logic [47:0] src_mac;
                    automatic logic [31:0] env_pl_size;
                    automatic logic [31:0] env_tr_words;
                    automatic logic [31:0] env_items;
                    automatic logic [31:0] env_bytes;
                    dst_rank = (hdr_sender_rank == RANK_SERVER0) ? RANK_SERVER1
                                                                 : RANK_SERVER0;
                    dst_mac  = {MAC_PREFIX, dst_rank[7:0]};
                    src_mac = {MAC_PREFIX, 8'h03};
                    env_pl_size = req_payload_size;
                    // Trailer: bmt_count triples, each 52 bytes
                    // But in the envelope word layout, trailer_words = bmt_count * 3
                    // (for compatibility with software decoder)
                    // Actually, the encrypted trailer is raw bytes, not 64-bit words.
                    // The envelope sub-header still reports trailer_words for software.
                    env_tr_words = req_bmt_count * 3;
                    env_items = 32'd7 + env_pl_size + env_tr_words;
                    env_bytes = env_items << 3;

                    // Ethernet header
                    obuf[0]  <= dst_mac[47:40]; obuf[1]  <= dst_mac[39:32];
                    obuf[2]  <= dst_mac[31:24]; obuf[3]  <= dst_mac[23:16];
                    obuf[4]  <= dst_mac[15:8];  obuf[5]  <= dst_mac[7:0];
                    obuf[6]  <= src_mac[47:40]; obuf[7]  <= src_mac[39:32];
                    obuf[8]  <= src_mac[31:24]; obuf[9]  <= src_mac[23:16];
                    obuf[10] <= src_mac[15:8];  obuf[11] <= src_mac[7:0];
                    obuf[12] <= ETHERTYPE[15:8]; obuf[13] <= ETHERTYPE[7:0];

                    // Pilot header
                    obuf[14] <= PILOT_MAGIC[31:24]; obuf[15] <= PILOT_MAGIC[23:16];
                    obuf[16] <= PILOT_MAGIC[15:8];  obuf[17] <= PILOT_MAGIC[7:0];
                    obuf[18] <= PILOT_VERSION;
                    obuf[19] <= MSG_TYPE_VECTOR;
                    obuf[20] <= PILOT_HEADER_LEN[15:8]; obuf[21] <= PILOT_HEADER_LEN[7:0];
                    obuf[22] <= hdr_sender_rank[15:8];  obuf[23] <= hdr_sender_rank[7:0];
                    obuf[24] <= dst_rank[15:8];         obuf[25] <= dst_rank[7:0];
                    obuf[26] <= hdr_tag[31:24]; obuf[27] <= hdr_tag[23:16];
                    obuf[28] <= hdr_tag[15:8];  obuf[29] <= hdr_tag[7:0];
                    obuf[30] <= env_items[31:24]; obuf[31] <= env_items[23:16];
                    obuf[32] <= env_items[15:8];  obuf[33] <= env_items[7:0];
                    obuf[34] <= env_bytes[31:24]; obuf[35] <= env_bytes[23:16];
                    obuf[36] <= env_bytes[15:8];  obuf[37] <= env_bytes[7:0];
                    obuf[38] <= FLAG_SWITCH_ENV[31:24]; obuf[39] <= FLAG_SWITCH_ENV[23:16];
                    obuf[40] <= FLAG_SWITCH_ENV[15:8];  obuf[41] <= FLAG_SWITCH_ENV[7:0];
                    // RSEQ: next response number for this destination
                    begin
                        automatic logic [31:0] rseq;
                        rseq = ((out_port == 2'd1) ? resp_seq_s1 : resp_seq_s0) + 32'd1;
                        obuf[42] <= rseq[31:24]; obuf[43] <= rseq[23:16];
                        obuf[44] <= rseq[15:8];  obuf[45] <= rseq[7:0];
                        if (out_port == 2'd1) resp_seq_s1 <= rseq;
                        else                  resp_seq_s0 <= rseq;
                    end

                    // Envelope sub-header
                    obuf[46] <= ENVELOPE_MAGIC[63:56]; obuf[47] <= ENVELOPE_MAGIC[55:48];
                    obuf[48] <= ENVELOPE_MAGIC[47:40]; obuf[49] <= ENVELOPE_MAGIC[39:32];
                    obuf[50] <= ENVELOPE_MAGIC[31:24]; obuf[51] <= ENVELOPE_MAGIC[23:16];
                    obuf[52] <= ENVELOPE_MAGIC[15:8];  obuf[53] <= ENVELOPE_MAGIC[7:0];

                    // payload_size (64-bit)
                    obuf[54] <= 8'h00; obuf[55] <= 8'h00; obuf[56] <= 8'h00; obuf[57] <= 8'h00;
                    obuf[58] <= env_pl_size[31:24]; obuf[59] <= env_pl_size[23:16];
                    obuf[60] <= env_pl_size[15:8];  obuf[61] <= env_pl_size[7:0];

                    // trailer_words (64-bit)
                    obuf[62] <= 8'h00; obuf[63] <= 8'h00; obuf[64] <= 8'h00; obuf[65] <= 8'h00;
                    obuf[66] <= env_tr_words[31:24]; obuf[67] <= env_tr_words[23:16];
                    obuf[68] <= env_tr_words[15:8];  obuf[69] <= env_tr_words[7:0];

                    // src_rank (64-bit)
                    obuf[70] <= 8'h00; obuf[71] <= 8'h00; obuf[72] <= 8'h00; obuf[73] <= 8'h00;
                    obuf[74] <= 8'h00; obuf[75] <= 8'h00;
                    obuf[76] <= hdr_sender_rank[15:8]; obuf[77] <= hdr_sender_rank[7:0];

                    // dst_rank (64-bit)
                    obuf[78] <= 8'h00; obuf[79] <= 8'h00; obuf[80] <= 8'h00; obuf[81] <= 8'h00;
                    obuf[82] <= 8'h00; obuf[83] <= 8'h00;
                    obuf[84] <= dst_rank[15:8]; obuf[85] <= dst_rank[7:0];

                    // tag (64-bit)
                    obuf[86] <= 8'h00; obuf[87] <= 8'h00; obuf[88] <= 8'h00; obuf[89] <= 8'h00;
                    obuf[90] <= hdr_tag[31:24]; obuf[91] <= hdr_tag[23:16];
                    obuf[92] <= hdr_tag[15:8];  obuf[93] <= hdr_tag[7:0];

                    // lane (64-bit)
                    obuf[94] <= 8'h00; obuf[95] <= 8'h00; obuf[96] <= 8'h00; obuf[97] <= 8'h00;
                    obuf[98] <= req_lane[31:24]; obuf[99] <= req_lane[23:16];
                    obuf[100] <= req_lane[15:8]; obuf[101] <= req_lane[7:0];

                    obuf_wr  <= 102;
                    copy_idx <= '0;
                    state    <= S_COPY_EF;
                end
            end

            // =================================================================
            S_COPY_EF: begin
                if (copy_idx < req_payload_size) begin
                    begin
                        automatic int unsigned src_off;
                        automatic int unsigned dst_off;
                        src_off = 86 + (copy_idx * 8);
                        dst_off = obuf_wr;
                        for (int b = 0; b < 8; b++)
                            obuf[dst_off + b] <= ibuf[src_off + b];
                    end
                    obuf_wr  <= obuf_wr + 8;
                    copy_idx <= copy_idx + 1;
                end else begin
                    bmt_idx <= '0;
                    state   <= S_POP_BMT;
                end
            end

            // =================================================================
            // Pop pre-encrypted BMT entries from the destination server's FIFO
            // Each entry: IV (12B) + CT0 (16B) + CT1_hi (8B) + TAG (16B) = 52B
            // =================================================================
            S_POP_BMT: begin
                if (bmt_idx < req_bmt_count) begin
                    if (bmt_idx < req_bmt_count_raw) begin
                        // --- Real triple: pop from destination FIFO ---
                        if (dst_pop_valid) begin
                            begin
                                automatic int unsigned off;
                                off = obuf_wr;
                                for (int b = 0; b < 12; b++)
                                    obuf[off + b] <= dst_pop_iv[(11-b)*8 +: 8];
                                for (int b = 0; b < 16; b++)
                                    obuf[off + 12 + b] <= dst_pop_ct0[(15-b)*8 +: 8];
                                for (int b = 0; b < 8; b++)
                                    obuf[off + 28 + b] <= dst_pop_ct1[(15-b)*8 +: 8];
                                for (int b = 0; b < 16; b++)
                                    obuf[off + 36 + b] <= dst_pop_tag[(15-b)*8 +: 8];
                            end
                            if (out_port == 2'd1) pop_s1_r <= 1;
                            else                  pop_s0_r <= 1;
                            obuf_wr <= obuf_wr + 52;
                            bmt_idx <= bmt_idx + 1;
                        end
                        // else: FIFO empty, stall
                    end else begin
                        // --- Padding: write 52 zero bytes ---
                        begin
                            automatic int unsigned off;
                            off = obuf_wr;
                            for (int b = 0; b < 52; b++)
                                obuf[off + b] <= 8'h00;
                        end
                        obuf_wr <= obuf_wr + 52;
                        bmt_idx <= bmt_idx + 1;
                    end
                end else begin
                    // Trailer done: MAC bytes 14 .. obuf_wr-1 with the
                    // destination server's key, then append the RTAG.
                    hmac_start <= 1'b1;
                    hmac_key   <= (out_port == 2'd1) ? mac_key_s1 : mac_key_s0;
                    hmac_len   <= 16'(obuf_wr - MAC_START);
                    state      <= S_RMAC;
                end
            end

            // =================================================================
            S_RMAC: begin
                if (hmac_done) begin
                    for (int b = 0; b < 16; b++)
                        obuf[obuf_wr + b] <= hmac_mac[255 - 8*b -: 8];
                    obuf_len     <= obuf_wr + TAG_BYTES;
                    out_byte_ptr <= '0;
                    state        <= S_OUTPUT;
                end
            end

            // =================================================================
            S_OUTPUT: begin
                if (!out_tvalid_r || out_tready_w) begin
                    if (out_byte_ptr < obuf_len) begin
                        begin
                            automatic logic [CNT_W-1:0] remaining;
                            automatic int unsigned nb;
                            automatic logic [DATA_W-1:0] d;
                            automatic logic [KEEP_W-1:0] k;
                            remaining = obuf_len - out_byte_ptr;
                            nb = (remaining >= KEEP_W) ? KEEP_W : remaining;
                            d = '0;
                            k = '0;
                            for (int i = 0; i < KEEP_W; i++) begin
                                if (i < nb) begin
                                    d[(KEEP_W-1-i)*8 +: 8] = is_request ? obuf[out_byte_ptr + i]
                                                                         : ibuf[out_byte_ptr + i];
                                    k[KEEP_W-1-i] = 1'b1;
                                end
                            end
                            out_tdata_r  <= d;
                            out_tkeep_r  <= k;
                            out_tlast_r  <= (out_byte_ptr + nb >= obuf_len);
                            out_tvalid_r <= 1;
                            out_byte_ptr <= out_byte_ptr + nb[CNT_W-1:0];
                        end
                    end else begin
                        out_tvalid_r <= 0;
                        state <= S_DONE;
                    end
                end
            end

            // =================================================================
            S_DONE: begin
                out_tvalid_r <= 0;
                is_request   <= 0;
                bmt_idx      <= '0;
                state        <= S_IDLE;
            end

            default: state <= S_IDLE;

            endcase
        end
    end

// ---------------------------------------------------------------------------
// Formal property attachment. Inert unless FORMAL is defined, which only
// `read -define FORMAL` in the SymbiYosys flow does. Vivado never defines it,
// so the synthesized netlist is unaffected.
// ---------------------------------------------------------------------------
`ifdef FORMAL
`include "pilot_switch_props_inst.vh"
`endif

endmodule
