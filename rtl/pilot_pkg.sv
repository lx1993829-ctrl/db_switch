// ============================================================================
// pilot_pkg.sv — Constants and types for the PILOT hardware switch
// ============================================================================
package pilot_pkg;

    // ---- Ethernet ----
    localparam [15:0] ETHERTYPE          = 16'h88B5;
    localparam [39:0] MAC_PREFIX         = 40'h02_50_49_4C_4F; // 5 bytes

    // ---- Pilot wire header ----
    localparam [31:0] PILOT_MAGIC        = 32'h50494C54; // "PILT"
    localparam [7:0]  PILOT_VERSION      = 8'h01;
    localparam [15:0] PILOT_HEADER_LEN   = 16'h0020;     // 32 bytes
    localparam        PILOT_HDR_BYTES    = 32;
    localparam        ETH_HDR_BYTES      = 14;
    localparam        FULL_HDR_BYTES     = ETH_HDR_BYTES + PILOT_HDR_BYTES; // 46

    // ---- Pilot message types ----
    localparam [7:0]  MSG_TYPE_SCALAR    = 8'd1;
    localparam [7:0]  MSG_TYPE_VECTOR    = 8'd2;
    localparam [7:0]  MSG_TYPE_STRING    = 8'd3;

    // ---- Pilot flags ----
    localparam [31:0] FLAG_SWITCH_REQ    = 32'h0000_0001;
    localparam [31:0] FLAG_SWITCH_ENV    = 32'h0000_0002;

    // ---- Payload magic (64-bit, big-endian) ----
    localparam [63:0] REQUEST_MAGIC      = 64'h5041525352455154; // "PARSREQT"
    localparam [63:0] ENVELOPE_MAGIC     = 64'h5041525345434550; // "PARSECEP"

    // ---- Ranks ----
    localparam [15:0] RANK_SERVER0       = 16'd0;
    localparam [15:0] RANK_SERVER1       = 16'd1;
    localparam [15:0] RANK_CLIENT        = 16'd2;

    // ---- Pending share CAM ----
    localparam        PENDING_DEPTH      = 16;

    // ---- Structures ----
    typedef struct packed {
        logic [47:0] dst_mac;
        logic [47:0] src_mac;
        logic [15:0] ethertype;
    } eth_hdr_t; // 14 bytes

    typedef struct packed {
        logic [31:0] magic;
        logic [7:0]  version;
        logic [7:0]  msg_type;
        logic [15:0] header_len;
        logic [15:0] sender_rank;
        logic [15:0] receiver_rank;
        logic [31:0] tag;
        logic [31:0] payload_items;
        logic [31:0] payload_bytes;
        logic [31:0] flags;
        logic [31:0] reserved;
    } pilot_hdr_t; // 32 bytes = 256 bits

    // Request sub-header (first 5 words of payload)
    typedef struct packed {
        logic [63:0] magic;          // REQUEST_MAGIC
        logic [63:0] tag;            // same as pilot header tag (as 64-bit)
        logic [63:0] lane;
        logic [63:0] bmt_count;
        logic [63:0] payload_size;   // number of e/f data words following
    } request_hdr_t; // 40 bytes = 320 bits

    // A single BMT triple (for one server's share)
    typedef struct packed {
        logic [63:0] a;
        logic [63:0] b;
        logic [63:0] c;
    } bmt_share_t; // 24 bytes = 192 bits

    // ---- Helper functions ----
    function automatic [47:0] mac_for_rank(input [15:0] rank);
        mac_for_rank = {MAC_PREFIX, rank[7:0]};
    endfunction

    function automatic logic is_server_rank(input [15:0] rank);
        is_server_rank = (rank == RANK_SERVER0) || (rank == RANK_SERVER1);
    endfunction

    function automatic [15:0] peer_server_rank(input [15:0] rank);
        peer_server_rank = (rank == RANK_SERVER0) ? RANK_SERVER1 : RANK_SERVER0;
    endfunction

endpackage
