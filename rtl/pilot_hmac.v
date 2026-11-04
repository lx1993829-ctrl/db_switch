// ============================================================================
// pilot_hmac.v -- HMAC-SHA256 (RFC 2104) over a variable-length message, for
// request authentication in pilot_switch_top.
//
//   mac = SHA256((K0 ^ opad) || SHA256((K0 ^ ipad) || msg))
//   K0  = key || 0^256            (32-byte key, zero-padded to the block)
//
// The message is NOT passed in: it stays in the switch's ibuf. The engine
// asks for it one 64-byte block at a time:
//   msg_idx  (output) block index j
//   msg_blk  (input)  message bytes 64*j .. 64*j+63, byte 0 in [511:504];
//                     must be a combinational function of msg_idx
// Bytes at or past msg_len are ignored (replaced by padding), so the caller
// need not mask them.
//
// One run: 1 + N + 2 SHA-256 blocks, N = floor((msg_len + 8) / 64) + 1.
//   step 0      : K0 ^ ipad                                  (init)
//   step 1..N   : message blocks 0..N-1, FIPS 180-4 padded,
//                 bit length (64 + msg_len) * 8              (next)
//   step N+1    : K0 ^ opad                                  (init)
//   step N+2    : inner digest || 0x80 || 0 || len 768       (next)
//
// Interface rules (asserted in pilot_hmac_props.sv):
//   - key and msg_len are latched at an accepted start (start && !busy);
//     msg_blk must hold the same message for the whole run
//   - done pulses once per accepted start; err is valid with it
//   - err: msg_len > MAX_LEN (rejected at once, no SHA traffic)
//   - mac is zero from an accepted start until the run's done, then held
//   - init and next to the core are never high together
// ============================================================================
`default_nettype none
module pilot_hmac #(
    parameter integer MAX_LEN = 8192          // bytes; 65535 at most
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire         start,
    input  wire [255:0] key,
    input  wire [15:0]  msg_len,
    output wire         busy,
    output reg          done,
    output reg          err,
    output reg  [255:0] mac,
    // message window
    output wire [10:0]  msg_idx,
    input  wire [511:0] msg_blk,
    // SHA-256 core
    output wire         sha_init,
    output wire         sha_next,
    output wire [511:0] sha_block,
    input  wire         sha_ready,
    input  wire [255:0] sha_digest
);
    localparam [1:0] S_IDLE = 2'd0, S_ISSUE = 2'd1, S_WAIT = 2'd2;
    localparam [1:0] P_IKEY = 2'd0, P_MSG = 2'd1, P_OKEY = 2'd2, P_OTAIL = 2'd3;
    localparam [255:0] IPAD = {32{8'h36}};
    localparam [255:0] OPAD = {32{8'h5c}};

    reg [1:0]   state;
    reg [1:0]   ph;
    reg [10:0]  j;            // message block index (P_MSG)
    reg [10:0]  nblk;         // N, message blocks in this run
    reg [15:0]  len_r;
    reg [255:0] key_r;
    reg [255:0] inner;        // inner hash result
    reg         armed;        // ready has dropped since the command

    assign msg_idx = j;

    // ---- padded message block j ------------------------------------------------
    // byte k of the block is message position p = 64*j + k
    wire [63:0] lbits = {45'd0, len_r + 16'd64, 3'b000};   // (64 + len) * 8
    wire        last  = (j == nblk - 11'd1);
    reg  [511:0] mblk;
    integer k;
    always @(*) begin
        for (k = 0; k < 64; k = k + 1) begin
            // p as 17 bits: j < 2048, so 64*j + k < 2^17
            if ({j, 6'd0} + k < {1'b0, len_r})
                mblk[511 - 8*k -: 8] = msg_blk[511 - 8*k -: 8];
            else if ({j, 6'd0} + k == {1'b0, len_r})
                mblk[511 - 8*k -: 8] = 8'h80;
            else if (last && k >= 56)
                mblk[511 - 8*k -: 8] = lbits >> (8*(63 - k));   // byte k-56 of lbits
            else
                mblk[511 - 8*k -: 8] = 8'h00;
        end
    end

    reg [511:0] blk;
    always @(*)
        case (ph)
            P_IKEY:  blk = {key_r ^ IPAD, IPAD};
            P_MSG:   blk = mblk;
            P_OKEY:  blk = {key_r ^ OPAD, OPAD};
            default: blk = {inner, 8'h80, 184'd0, 64'd768};
        endcase

    wire issue = (state == S_ISSUE) && sha_ready;
    wire first = (ph == P_IKEY) || (ph == P_OKEY);
    assign sha_init  = issue &&  first;
    assign sha_next  = issue && !first;
    assign sha_block = blk;
    assign busy      = (state != S_IDLE);

    // N = floor((len + 8) / 64) + 1
    wire [16:0] len8   = {1'b0, msg_len} + 17'd8;
    wire [10:0] n_new  = len8[16:6] + 11'd1;

    always @(posedge clk or negedge rst_n)
        if (!rst_n) begin
            state <= S_IDLE; ph <= P_IKEY; j <= 11'd0; nblk <= 11'd0;
            len_r <= 16'd0; key_r <= 256'd0; inner <= 256'd0; armed <= 1'b0;
            done <= 1'b0; err <= 1'b0; mac <= 256'd0;
        end else begin
            done <= 1'b0;
            case (state)
                S_IDLE:
                    if (start) begin
                        key_r <= key; len_r <= msg_len; nblk <= n_new;
                        ph <= P_IKEY; j <= 11'd0; mac <= 256'd0;
                        if (msg_len > MAX_LEN[15:0]) begin
                            err <= 1'b1; done <= 1'b1;            // stay idle
                        end else begin
                            err <= 1'b0; state <= S_ISSUE;
                        end
                    end
                S_ISSUE:
                    if (sha_ready) begin
                        armed <= 1'b0;
                        state <= S_WAIT;
                    end
                S_WAIT:
                    if (!sha_ready)
                        armed <= 1'b1;
                    else if (armed) begin                        // block finished
                        state <= S_ISSUE;
                        case (ph)
                            P_IKEY: ph <= P_MSG;
                            P_MSG:
                                if (last) begin inner <= sha_digest; ph <= P_OKEY; end
                                else j <= j + 11'd1;
                            P_OKEY: ph <= P_OTAIL;
                            default: begin
                                mac   <= sha_digest;
                                done  <= 1'b1;
                                state <= S_IDLE;
                            end
                        endcase
                    end
                default: state <= S_IDLE;
            endcase
        end
endmodule
`default_nettype wire
