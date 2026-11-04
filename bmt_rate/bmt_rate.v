`timescale 1ns / 1ps
// ============================================================================
// bmt_rate.v -- Vitis RTL kernel: measures bmt_pregen's triple generation rate
//
// Wraps bmt_pregen unchanged. One kernel run (ap_start .. ap_done):
//   1. Release bmt_pregen from reset and present the host's seed. seed_valid
//      is held for the whole run; bmt_pregen admits only the first nonzero
//      seed per reset, so this loads it exactly once.
//   2. For run_cycles cycles, pop BOTH FIFOs on every cycle they are
//      non-empty, so the generator never stalls on any_full and the count is
//      the pure generation rate. Count pops and cycles, record the cycle of
//      the first and last pop, and capture the first NCAP entries of each
//      FIFO for the host to decrypt and check.
//   3. Put bmt_pregen back in reset (each run starts cold with a new seed),
//      write the 576-byte result block to `out` in one 9-beat burst, and
//      raise ap_done.
//
// Result block (64-byte beats, little-endian uint64 words):
//   beat 0          [0] magic "BMTRATE1"  [1] cycles     [2] pops_s0
//                   [3] pops_s1  [4] first_pop_cycle  [5] last_pop_cycle
//                   [6] NCAP     [7] 0
//   beat 1+k        server 0 FIFO entry k
//   beat 1+NCAP+k   server 1 FIFO entry k
//   An entry is bytes 0..51 = IV(12) CT0(16) CT1_hi(8) TAG(16), the order in
//   which pilot_switch_top writes it into a response trailer. Entry k of the
//   two servers are the two shares of the same triple.
//
// Control registers (ap_ctrl_hs, offsets as in kernel.xml):
//   0x00 ctrl  0x04 GIE  0x08 IER  0x0C ISR
//   0x10 run_cycles  0x18 seed0  0x20 seed1  0x28 seed2  0x30 seed3  0x38 out
//   (each argument 64-bit, low word first)
// ============================================================================

module bmt_rate #(
    // Must match the keys the host checks with (host --key0/--key1).
    parameter [127:0] AES_KEY_S0 = 128'h000102030405060708090a0b0c0d0e0f,
    parameter [127:0] AES_KEY_S1 = 128'h101112131415161718191a1b1c1d1e1f,
    parameter         FIFO_DEPTH = 128
) (
    input  wire         ap_clk,
    input  wire         ap_rst_n,
    output wire         interrupt,

    // ---- m00_axi: result block (write only) ----
    output wire         m00_axi_awvalid,
    input  wire         m00_axi_awready,
    output wire [63:0]  m00_axi_awaddr,
    output wire [7:0]   m00_axi_awlen,
    output wire         m00_axi_wvalid,
    input  wire         m00_axi_wready,
    output wire [511:0] m00_axi_wdata,
    output wire [63:0]  m00_axi_wstrb,
    output wire         m00_axi_wlast,
    input  wire         m00_axi_bvalid,
    output wire         m00_axi_bready,
    output wire         m00_axi_arvalid,
    input  wire         m00_axi_arready,
    output wire [63:0]  m00_axi_araddr,
    output wire [7:0]   m00_axi_arlen,
    input  wire         m00_axi_rvalid,
    output wire         m00_axi_rready,
    input  wire [511:0] m00_axi_rdata,
    input  wire         m00_axi_rlast,

    // ---- s_axi_control ----
    input  wire         s_axi_control_awvalid,
    output wire         s_axi_control_awready,
    input  wire [11:0]  s_axi_control_awaddr,
    input  wire         s_axi_control_wvalid,
    output wire         s_axi_control_wready,
    input  wire [31:0]  s_axi_control_wdata,
    input  wire [3:0]   s_axi_control_wstrb,
    input  wire         s_axi_control_arvalid,
    output wire         s_axi_control_arready,
    input  wire [11:0]  s_axi_control_araddr,
    output wire         s_axi_control_rvalid,
    input  wire         s_axi_control_rready,
    output wire [31:0]  s_axi_control_rdata,
    output wire [1:0]   s_axi_control_rresp,
    output wire         s_axi_control_bvalid,
    input  wire         s_axi_control_bready,
    output wire [1:0]   s_axi_control_bresp
);

    localparam        NCAP  = 4;              // entries captured per server (index logic assumes 4)
    localparam        NBEAT = 1 + 2 * NCAP;   // 9 beats = 576 bytes
    localparam [63:0] MAGIC = 64'h3145544152544D42;  // "BMTRATE1" as little-endian bytes

    localparam [2:0]
        K_IDLE = 3'd0,
        K_RUN  = 3'd1,
        K_AW   = 3'd2,
        K_W    = 3'd3,
        K_B    = 3'd4,
        K_DONE = 3'd5;

    reg [2:0] k_state;

    // =========================================================================
    // Control registers
    // =========================================================================
    reg         ap_start_r, ap_done_r, ap_ready_r, auto_restart_r;
    reg         gie_r;
    reg  [1:0]  ier_r, isr_r;
    reg  [63:0] run_cycles_r;
    reg  [255:0] seed_r;
    reg  [63:0] out_r;
    wire        ap_idle = (k_state == K_IDLE);

    function [31:0] apply_strb(input [31:0] old, input [31:0] d, input [3:0] s);
        apply_strb = {s[3] ? d[31:24] : old[31:24], s[2] ? d[23:16] : old[23:16],
                      s[1] ? d[15:8]  : old[15:8],  s[0] ? d[7:0]   : old[7:0]};
    endfunction

    // ---- AXI4-Lite write ----
    localparam [1:0] WR_IDLE = 2'd0, WR_DATA = 2'd1, WR_RESP = 2'd2;
    reg [1:0]  wr_state;
    reg [11:0] waddr;

    assign s_axi_control_awready = (wr_state == WR_IDLE);
    assign s_axi_control_wready  = (wr_state == WR_DATA);
    assign s_axi_control_bvalid  = (wr_state == WR_RESP);
    assign s_axi_control_bresp   = 2'b00;

    wire w_hs = s_axi_control_wvalid && s_axi_control_wready;

    always @(posedge ap_clk) begin
        if (!ap_rst_n) begin
            wr_state <= WR_IDLE;
            waddr    <= 12'd0;
        end else begin
            case (wr_state)
                WR_IDLE: if (s_axi_control_awvalid) begin
                             waddr    <= s_axi_control_awaddr;
                             wr_state <= WR_DATA;
                         end
                WR_DATA: if (s_axi_control_wvalid) wr_state <= WR_RESP;
                WR_RESP: if (s_axi_control_bready) wr_state <= WR_IDLE;
                default: wr_state <= WR_IDLE;
            endcase
        end
    end

    // ---- AXI4-Lite read ----
    localparam RD_IDLE = 1'b0, RD_DATA = 1'b1;
    reg        rd_state;
    reg [31:0] rdata_r;

    assign s_axi_control_arready = (rd_state == RD_IDLE);
    assign s_axi_control_rvalid  = (rd_state == RD_DATA);
    assign s_axi_control_rdata   = rdata_r;
    assign s_axi_control_rresp   = 2'b00;

    wire ar_hs = s_axi_control_arvalid && s_axi_control_arready;

    reg [31:0] rmux;
    always @(*) begin
        case (s_axi_control_araddr)
            12'h000: rmux = {24'd0, auto_restart_r, 3'd0, ap_ready_r, ap_idle, ap_done_r, ap_start_r};
            12'h004: rmux = {31'd0, gie_r};
            12'h008: rmux = {30'd0, ier_r};
            12'h00C: rmux = {30'd0, isr_r};
            12'h010: rmux = run_cycles_r[31:0];
            12'h014: rmux = run_cycles_r[63:32];
            12'h018: rmux = seed_r[31:0];
            12'h01C: rmux = seed_r[63:32];
            12'h020: rmux = seed_r[95:64];
            12'h024: rmux = seed_r[127:96];
            12'h028: rmux = seed_r[159:128];
            12'h02C: rmux = seed_r[191:160];
            12'h030: rmux = seed_r[223:192];
            12'h034: rmux = seed_r[255:224];
            12'h038: rmux = out_r[31:0];
            12'h03C: rmux = out_r[63:32];
            default: rmux = 32'd0;
        endcase
    end

    always @(posedge ap_clk) begin
        if (!ap_rst_n) begin
            rd_state <= RD_IDLE;
            rdata_r  <= 32'd0;
        end else begin
            case (rd_state)
                RD_IDLE: if (s_axi_control_arvalid) begin
                             rdata_r  <= rmux;
                             rd_state <= RD_DATA;
                         end
                RD_DATA: if (s_axi_control_rready) rd_state <= RD_IDLE;
            endcase
        end
    end

    // ---- Register file ----
    integer i;
    always @(posedge ap_clk) begin
        if (!ap_rst_n) begin
            ap_start_r     <= 1'b0;
            ap_done_r      <= 1'b0;
            ap_ready_r     <= 1'b0;
            auto_restart_r <= 1'b0;
            gie_r          <= 1'b0;
            ier_r          <= 2'b0;
            isr_r          <= 2'b0;
            run_cycles_r   <= 64'd0;
            seed_r         <= 256'd0;
            out_r          <= 64'd0;
        end else begin
            // ap_done / ap_ready are clear-on-read
            if (ar_hs && s_axi_control_araddr == 12'h000) begin
                ap_done_r  <= 1'b0;
                ap_ready_r <= 1'b0;
            end
            if (k_state == K_DONE) begin
                ap_start_r <= 1'b0;
                ap_done_r  <= 1'b1;
                ap_ready_r <= 1'b1;
                if (ier_r[0]) isr_r[0] <= 1'b1;
                if (ier_r[1]) isr_r[1] <= 1'b1;
            end

            if (w_hs) begin
                case (waddr)
                    12'h000: if (s_axi_control_wstrb[0]) begin
                                 if (s_axi_control_wdata[0]) ap_start_r <= 1'b1;
                                 auto_restart_r <= s_axi_control_wdata[7];
                             end
                    12'h004: if (s_axi_control_wstrb[0]) gie_r <= s_axi_control_wdata[0];
                    12'h008: if (s_axi_control_wstrb[0]) ier_r <= s_axi_control_wdata[1:0];
                    12'h00C: if (s_axi_control_wstrb[0]) isr_r <= isr_r ^ s_axi_control_wdata[1:0];
                    12'h010: run_cycles_r[31:0]  <= apply_strb(run_cycles_r[31:0],  s_axi_control_wdata, s_axi_control_wstrb);
                    12'h014: run_cycles_r[63:32] <= apply_strb(run_cycles_r[63:32], s_axi_control_wdata, s_axi_control_wstrb);
                    12'h038: out_r[31:0]  <= apply_strb(out_r[31:0],  s_axi_control_wdata, s_axi_control_wstrb);
                    12'h03C: out_r[63:32] <= apply_strb(out_r[63:32], s_axi_control_wdata, s_axi_control_wstrb);
                    default: ;
                endcase
                // seed0..seed3: eight 32-bit words at 0x18..0x34
                for (i = 0; i < 8; i = i + 1)
                    if (waddr == 12'h018 + 4 * i)
                        seed_r[32*i +: 32] <= apply_strb(seed_r[32*i +: 32], s_axi_control_wdata,
                                                         s_axi_control_wstrb);
            end
        end
    end

    assign interrupt = gie_r && (|isr_r);

    // =========================================================================
    // Device under test
    // =========================================================================
    reg          bmt_rst_n;
    wire         pop_valid_s0, pop_valid_s1;
    wire         pop_s0 = (k_state == K_RUN) && pop_valid_s0;
    wire         pop_s1 = (k_state == K_RUN) && pop_valid_s1;
    wire [95:0]  pop_iv_s0,  pop_iv_s1;
    wire [127:0] pop_ct0_s0, pop_ct0_s1;
    wire [127:0] pop_ct1_s0, pop_ct1_s1;
    wire [127:0] pop_tag_s0, pop_tag_s1;

    bmt_pregen #(.FIFO_DEPTH(FIFO_DEPTH)) u_bmt (
        .clk(ap_clk), .rst_n(bmt_rst_n),
        .key_s0(AES_KEY_S0), .key_s1(AES_KEY_S1),
        .seed_valid(k_state == K_RUN), .seed_data(seed_r),
        .seeded(),
        .fifo_count_s0(), .fifo_count_s1(),
        .pop_s0(pop_s0), .pop_iv_s0(pop_iv_s0),
        .pop_ct0_s0(pop_ct0_s0), .pop_ct1_s0(pop_ct1_s0),
        .pop_tag_s0(pop_tag_s0), .pop_valid_s0(pop_valid_s0),
        .pop_s1(pop_s1), .pop_iv_s1(pop_iv_s1),
        .pop_ct0_s1(pop_ct0_s1), .pop_ct1_s1(pop_ct1_s1),
        .pop_tag_s1(pop_tag_s1), .pop_valid_s1(pop_valid_s1)
    );

    // An entry in trailer byte order: IV, CT0, CT1 upper 64 bits, TAG
    wire [415:0] entry_s0 = {pop_iv_s0, pop_ct0_s0, pop_ct1_s0[127:64], pop_tag_s0};
    wire [415:0] entry_s1 = {pop_iv_s1, pop_ct0_s1, pop_ct1_s1[127:64], pop_tag_s1};

    // =========================================================================
    // Run FSM and counters
    // =========================================================================
    reg [63:0]  run_len, cyc, pops_s0, pops_s1, first_pop, last_pop;
    reg [415:0] cap_s0 [0:NCAP-1];
    reg [415:0] cap_s1 [0:NCAP-1];
    reg [3:0]   beat;

    always @(posedge ap_clk) begin
        if (!ap_rst_n) begin
            k_state   <= K_IDLE;
            bmt_rst_n <= 1'b0;
            run_len   <= 64'd0;
            cyc       <= 64'd0;
            pops_s0   <= 64'd0;
            pops_s1   <= 64'd0;
            first_pop <= 64'd0;
            last_pop  <= 64'd0;
            beat      <= 4'd0;
        end else begin
            case (k_state)
                K_IDLE: if (ap_start_r) begin
                    run_len   <= (run_cycles_r == 64'd0) ? 64'd1 : run_cycles_r;
                    cyc       <= 64'd0;
                    pops_s0   <= 64'd0;
                    pops_s1   <= 64'd0;
                    first_pop <= 64'd0;
                    last_pop  <= 64'd0;
                    bmt_rst_n <= 1'b1;
                    k_state   <= K_RUN;
                end

                K_RUN: begin
                    cyc <= cyc + 64'd1;
                    if (pop_s0) begin
                        pops_s0  <= pops_s0 + 64'd1;
                        last_pop <= cyc;
                        if (pops_s0 == 64'd0) first_pop <= cyc;
                        if (pops_s0 < NCAP) cap_s0[pops_s0[1:0]] <= entry_s0;
                    end
                    if (pop_s1) begin
                        pops_s1 <= pops_s1 + 64'd1;
                        if (pops_s1 < NCAP) cap_s1[pops_s1[1:0]] <= entry_s1;
                    end
                    if (cyc + 64'd1 == run_len) begin
                        bmt_rst_n <= 1'b0;
                        k_state   <= K_AW;
                    end
                end

                K_AW: if (m00_axi_awready) begin
                    beat    <= 4'd0;
                    k_state <= K_W;
                end

                K_W: if (m00_axi_wready) begin
                    if (beat == NBEAT - 1) k_state <= K_B;
                    else                   beat    <= beat + 4'd1;
                end

                K_B: if (m00_axi_bvalid) k_state <= K_DONE;

                K_DONE: k_state <= K_IDLE;

                default: k_state <= K_IDLE;
            endcase
        end
    end

    // =========================================================================
    // Result write (one burst of NBEAT beats to `out`)
    // =========================================================================
    function [511:0] pack_entry(input [415:0] e);
        integer j;
        begin
            pack_entry = 512'd0;
            for (j = 0; j < 52; j = j + 1)
                pack_entry[8*j +: 8] = e[415 - 8*j -: 8];
        end
    endfunction

    wire [511:0] header = {64'd0, 64'd4, last_pop, first_pop, pops_s1, pops_s0, cyc, MAGIC};
    wire [3:0]   bm1    = beat - 4'd1;   // beats 1..4 -> s0 entry 0..3, 5..8 -> s1 entry 0..3

    reg [511:0] wdata_mux;
    always @(*) begin
        if (beat == 4'd0)       wdata_mux = header;
        else if (beat <= NCAP)  wdata_mux = pack_entry(cap_s0[bm1[1:0]]);
        else                    wdata_mux = pack_entry(cap_s1[bm1[1:0]]);
    end

    assign m00_axi_awvalid = (k_state == K_AW);
    assign m00_axi_awaddr  = out_r;
    assign m00_axi_awlen   = NBEAT - 1;
    assign m00_axi_wvalid  = (k_state == K_W);
    assign m00_axi_wdata   = wdata_mux;
    assign m00_axi_wstrb   = {64{1'b1}};
    assign m00_axi_wlast   = (beat == NBEAT - 1);
    assign m00_axi_bready  = (k_state == K_B);

    // Read channel unused
    assign m00_axi_arvalid = 1'b0;
    assign m00_axi_araddr  = 64'd0;
    assign m00_axi_arlen   = 8'd0;
    assign m00_axi_rready  = 1'b1;

endmodule
