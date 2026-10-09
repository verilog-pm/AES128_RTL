// =============================================================================
// AES-128 Top Module
// One instance is either an encryptor or a decryptor, selected by the
// `mode` parameter. The unused pipeline is not instantiated.
//   mode = 0 : encryption pipeline (ECB / CBC-encrypt / CTR)
//   mode = 1 : decryption pipeline (ECB / CBC-decrypt)
// CTR encrypt and CTR decrypt are the same operation (XOR with E(counter)),
// so both directions use an encrypt instance (mode = 0).
// Block-cipher operating modes: ECB, CBC, and CTR.
// Based on FIPS-197 (core cipher) and NIST SP 800-38A (ECB/CBC/CTR modes)
//
// -----------------------------------------------------------------------------
// Operating mode notes
// -----------------------------------------------------------------------------
// - ECB : each block is encrypted/decrypted independently. Fully pipelined.
// - CBC : encrypt: C_i = E(P_i XOR C_{i-1}), C_0 seed = IV.
//         decrypt: P_i = D(C_i) XOR C_{i-1}, C_0 seed = IV.
//         CBC-encrypt has a genuine data dependency between blocks (the next
//         block's input depends on the previous block's ciphertext), so this
//         module only allows one CBC-encrypt block in flight at a time
//         (throughput ~= 1 block per AES pipeline latency, not 1 block/cycle).
//         CBC-decrypt has no such dependency (the XOR operand is the
//         *incoming* ciphertext, known immediately) and stays fully pipelined.
// - CTR : keystream_i = E(counter_i); C_i = P_i XOR keystream_i (encrypt),
//         P_i = C_i XOR keystream_i (decrypt). Implemented only when mode = 0.
//         Fully pipelined; the counter increments when each block is accepted.
//
// `iv` + `iv_valid` seeds the CBC previous-ciphertext register or the CTR
// counter. There is no iv_ready handshake: while `iv_valid` is high the IV
// on the bus is latched, and it is written into the chain register only when
// the cipher is idle. A new assertion of `iv_valid` reloads the chain even
// if the IV value is unchanged (CTR/CBC state may have advanced). Holding
// `iv_valid` high does not reload every cycle. `data_in_ready` stays low
// until that IV is installed, so blocks already in flight keep the old chain.
// `op_mode` should only be changed while idle.
//
// Data bus (AXI-Stream style valid/ready, plus last and keep):
//   DATA_WIDTH is 32 or 64, default 32. Beats are packed MSB-first into the
//   128-bit AES block: beat 0 occupies block[127 -: DATA_WIDTH].
//   keep[i] qualifies data[8*i +: 8] (AXI-Stream byte lanes). Bytes with
//   keep=0, and beats that were never sent, are zero inside the block.
//   data_in_last ends the block early. The cipher still runs on the full
//   zero-padded block. Only the beats that arrived are shifted back out,
//   and data_out_keep / data_out_last repeat the input tail.
//   A partial ECB/CBC block therefore does not round-trip: the unsent tail
//   of the ciphertext block is dropped. CTR does round-trip, because both
//   directions discard the unused keystream bytes.
//
// The key port is `key` + `key_valid` only. There is no key_ready handshake:
// while `key_valid` is high the key on the bus is latched. The latched key is
// loaded into the key schedule only when the cipher is idle (no block in
// flight). `data_in_ready` stays low until that new key's round keys are
// installed, so blocks already in flight keep the previous key.
// =============================================================================

module aes128_top #(
    parameter mode       = 1'b0,  // 0 = encrypt, 1 = decrypt
    parameter DATA_WIDTH = 32     // 32 or 64
) (
    input  wire         clk,
    input  wire         rst_n,

    // Key interface: key_valid latches `key`. The cipher consumes the latched
    // key on its own once it is idle. There is no key_ready output.
    input  wire [127:0] key,
    input  wire         key_valid,

    // Block-cipher operating mode. CTR is honored only on an encrypt instance.
    input  wire [1:0]   op_mode,  // 00=ECB, 01=CBC, 10=CTR (11 reserved -> ECB)

    // IV / initial counter (CBC and CTR; ignored by ECB).
    // iv_valid latches `iv`. The cipher writes it into the chain register
    // once it is idle. There is no iv_ready output.
    input  wire [127:0] iv,
    input  wire         iv_valid,

    // Narrow data interface. See the header for beat order and keep.
    input  wire [DATA_WIDTH-1:0]   data_in,
    input  wire                    data_in_valid,
    input  wire                    data_in_last,
    input  wire [DATA_WIDTH/8-1:0] data_in_keep,
    output wire                    data_in_ready,

    output wire [DATA_WIDTH-1:0]   data_out,
    output wire                    data_out_valid,
    output wire                    data_out_last,
    output wire [DATA_WIDTH/8-1:0] data_out_keep,
    input  wire                    data_out_ready
);

// ============================================================================
// Configuration
// ============================================================================
localparam IS_ENCRYPT       = (mode == 1'b0);
localparam OP_MODE_CBC      = 2'b01;
localparam OP_MODE_CTR      = 2'b10;
localparam BEATS_PER_BLOCK  = 128 / DATA_WIDTH;
localparam KEEP_W           = DATA_WIDTH / 8;

generate
if (!((DATA_WIDTH == 32) || (DATA_WIDTH == 64))) begin : g_bad_width
    illegal_data_width_must_be_32_or_64 u_bad();
end
endgenerate

function [DATA_WIDTH-1:0] apply_keep;
    input [DATA_WIDTH-1:0]   data;
    input [KEEP_W-1:0]       keep;
    integer                  bi;
    begin
        apply_keep = {DATA_WIDTH{1'b0}};
        for (bi = 0; bi < KEEP_W; bi = bi + 1)
            if (keep[bi])
                apply_keep[8*bi +: 8] = data[8*bi +: 8];
    end
endfunction

// CTR keystream generation is encryption. A decrypt instance ignores it.
wire is_cbc = (op_mode == OP_MODE_CBC);
wire is_ctr = IS_ENCRYPT && (op_mode == OP_MODE_CTR);

// ============================================================================
// Internal signals
// ============================================================================
wire [1408-1:0] round_key_enc;  // 11 * 128 = 1408 bits
wire [1408-1:0] round_key_dec;  // 11 * 128 = 1408 bits
wire key_ready_int;

wire [127:0] pipe_data_out;
wire         pipe_data_out_valid;
wire         pipe_data_in_ready;
wire [127:0] pipe_aux_out;
wire [19:0]  pipe_meta_out;

// Packer: narrow beats -> one 128-bit block. blk_* holds a finished block
// that the pipeline has not accepted yet.
reg [127:0] pack_data;
reg [15:0]  pack_keep;
reg [2:0]   pack_beat;
reg [127:0] blk_data;
reg [15:0]  blk_keep;
reg [2:0]   blk_beats;
reg         blk_last;
reg         blk_valid;

// Unpacker: one cipher block -> the beats that were actually received.
reg [127:0] buf_data;
reg [15:0]  buf_keep;
reg [2:0]   buf_beat;
reg [2:0]   buf_beats;
reg         buf_last;
reg         buf_valid;
reg [DATA_WIDTH-1:0] skid_data;
reg [KEEP_W-1:0]     skid_keep;
reg                  skid_valid;
reg                  skid_last;
reg                  skid_eob;

// ============================================================================
// Chain state: previous ciphertext (CBC) or running counter (CTR)
// ============================================================================
reg [127:0] chain_reg;
reg         cbc_enc_busy;  // serializes CBC-encrypt: 1 block in flight at a time

// Number of blocks accepted on data_in but not yet delivered on data_out.
// A new IV is written into chain_reg only after this count returns to zero.
reg [5:0] in_flight_count;

// ============================================================================
// Key capture
// key_valid high: latch the key presented on this cycle.
// The latched key is handed to key_schedule only while the cipher is idle
// and the previous expansion has finished. A pending new key also withholds
// data_in so the pipeline can drain and then switch keys.
// ============================================================================
reg [127:0] key_latched;
reg         key_captured;
reg [127:0] key_applied;
reg         key_applied_valid;
reg         key_expand_busy;

wire [127:0] key_candidate = key_valid ? key : key_latched;
wire key_update_req =
    (key_valid && (!key_applied_valid || (key != key_applied))) ||
    (!key_valid && key_captured && (!key_applied_valid || (key_latched != key_applied)));

// Idle means no partial beat, no held block, and no block still in the
// pipeline or the output gearbox. Key and IV updates wait for this.
wire stream_idle = (in_flight_count == 6'd0) && !blk_valid && (pack_beat == 3'd0)
                   && !buf_valid && !skid_valid;
wire cipher_idle = stream_idle && !cbc_enc_busy;
wire key_load    = key_update_req && cipher_idle && !key_expand_busy;

// ============================================================================
// IV capture
// A rising iv_valid, or a change of iv while iv_valid stays high, requests
// a chain reload. The reload happens on the next idle cycle. The same value
// can be loaded again by pulsing iv_valid, which restarts CBC/CTR state.
// ============================================================================
reg [127:0] iv_latched;
reg         iv_pending;
reg         iv_valid_d;

wire iv_rise = iv_valid && !iv_valid_d;
wire [127:0] iv_candidate = iv_valid ? iv : iv_latched;
wire iv_update_req = iv_pending || iv_rise || (iv_valid && (iv != iv_latched));
wire iv_install    = iv_update_req && cipher_idle;
wire allow_data    = !key_update_req && !iv_update_req;

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        iv_latched <= 128'h0;
        iv_pending <= 1'b0;
        iv_valid_d <= 1'b0;
    end else begin
        iv_valid_d <= iv_valid;
        if (iv_valid) begin
            iv_latched <= iv;
        end
        if (iv_install) begin
            iv_pending <= 1'b0;
        end else if (iv_rise || (iv_valid && (iv != iv_latched))) begin
            iv_pending <= 1'b1;
        end
    end
end

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        key_latched       <= 128'h0;
        key_captured      <= 1'b0;
        key_applied       <= 128'h0;
        key_applied_valid <= 1'b0;
        key_expand_busy   <= 1'b0;
    end else begin
        if (key_valid) begin
            key_latched  <= key;
            key_captured <= 1'b1;
        end
        if (key_load) begin
            key_applied       <= key_candidate;
            key_applied_valid <= 1'b1;
            key_expand_busy   <= 1'b1;
        end else if (key_ready_int) begin
            key_expand_busy   <= 1'b0;
        end
    end
end

// ============================================================================
// Key schedule. Encrypt instances skip inverse-round-key derivation.
// ============================================================================
key_schedule #(.DECRYPT(IS_ENCRYPT ? 0 : 1)) key_sched (
    .clk(clk),
    .rst_n(rst_n),
    .key(key_candidate),
    .key_valid(key_load),
    .key_ready(key_ready_int),
    .round_key_enc(round_key_enc),
    .round_key_dec(round_key_dec)
);

// ============================================================================
// Beat packer. A block is committed on data_in_last or when BEATS_PER_BLOCK
// beats have arrived. If the pipeline can take it this cycle, it goes
// straight in; otherwise it sits in blk_* until the pipeline is ready.
// Mid-block beats are still accepted while a key/IV update is pending so a
// block is not split across two keys.
// ============================================================================
wire enc_gate = is_cbc ? !cbc_enc_busy : 1'b1;
wire block_select = IS_ENCRYPT ? enc_gate : 1'b1;
wire assembling = (pack_beat != 3'd0);
wire beat_completes = data_in_last || (pack_beat == (BEATS_PER_BLOCK - 1));

assign data_in_ready = !blk_valid && block_select && (allow_data || assembling)
                       && (pipe_data_in_ready || assembling);

wire in_fire = data_in_valid && data_in_ready;

reg [127:0] pack_next_data;
reg [15:0]  pack_next_keep;
always @(*) begin
    pack_next_data = (pack_beat == 3'd0) ? 128'h0 : pack_data;
    pack_next_keep = (pack_beat == 3'd0) ? 16'h0 : pack_keep;
    pack_next_data[127 - pack_beat*DATA_WIDTH -: DATA_WIDTH] = apply_keep(data_in, data_in_keep);
    pack_next_keep[15 - pack_beat*KEEP_W -: KEEP_W] = data_in_keep;
end

wire held_hs    = blk_valid && block_select && pipe_data_in_ready;
wire live_commit = in_fire && beat_completes && block_select && pipe_data_in_ready && !blk_valid;
wire block_hs   = held_hs || live_commit;

wire [127:0] xfer_data  = blk_valid ? blk_data : pack_next_data;
wire [15:0]  xfer_keep  = blk_valid ? blk_keep : pack_next_keep;
wire [2:0]   xfer_beats = blk_valid ? blk_beats : (pack_beat + 3'd1);
wire         xfer_last  = blk_valid ? blk_last : data_in_last;
wire [19:0]  pipe_meta_in = {xfer_last, xfer_beats, xfer_keep};

// ============================================================================
// Pipeline input uses the packed 128-bit block
//   Encrypt ECB : block
//   Encrypt CBC : block XOR chain_reg
//   Encrypt CTR : chain_reg (counter), aux = block
//   Decrypt ECB : block
//   Decrypt CBC : block, aux = chain_reg (previous ciphertext)
// ============================================================================
wire [127:0] pipe_data_in = IS_ENCRYPT
    ? (is_ctr ? chain_reg : is_cbc ? (xfer_data ^ chain_reg) : xfer_data)
    : xfer_data;
wire [127:0] pipe_aux_in = IS_ENCRYPT
    ? (is_ctr ? xfer_data : 128'h0)
    : (is_cbc ? chain_reg : 128'h0);
wire pipe_data_in_valid = (blk_valid && block_select) ||
                          (in_fire && beat_completes && block_select && !blk_valid);

wire [127:0] result_block = IS_ENCRYPT
    ? (is_ctr ? (pipe_data_out ^ pipe_aux_out) : pipe_data_out)
    : (is_cbc ? (pipe_data_out ^ pipe_aux_out) : pipe_data_out);

wire [2:0] buf_last_idx = (buf_beats == 3'd0) ? 3'd0 : (buf_beats - 3'd1);
wire buf_on_last = buf_valid && (buf_beats != 3'd0) && (buf_beat == buf_last_idx);
wire skid_fire = skid_valid && data_out_ready;
wire take_beat = buf_valid && (buf_beats != 3'd0) && (!skid_valid || skid_fire);
wire buf_done = take_beat && buf_on_last;
wire pipe_out_ready = !buf_valid || buf_done;
wire pipe_take = pipe_data_out_valid && pipe_out_ready;

wire [DATA_WIDTH-1:0] buf_beat_data = buf_data[127 - buf_beat*DATA_WIDTH -: DATA_WIDTH];
wire [KEEP_W-1:0]     buf_beat_keep = buf_keep[15 - buf_beat*KEEP_W -: KEEP_W];

assign data_out_valid = skid_valid;
assign data_out       = skid_valid ? skid_data : {DATA_WIDTH{1'b0}};
assign data_out_keep  = skid_valid ? skid_keep : {KEEP_W{1'b0}};
assign data_out_last  = skid_valid && skid_last;

wire accept_fires  = block_hs;
wire consume_fires = skid_fire && skid_eob;

generate
if (IS_ENCRYPT) begin : g_enc
    aes128_pipeline_enc enc_pipe (
        .clk(clk),
        .rst_n(rst_n),
        .data_in(pipe_data_in),
        .data_in_valid(pipe_data_in_valid),
        .data_in_ready(pipe_data_in_ready),
        .aux_in(pipe_aux_in),
        .meta_in(pipe_meta_in),
        .round_keys(round_key_enc),
        .key_ready(key_ready_int),
        .data_out(pipe_data_out),
        .data_out_valid(pipe_data_out_valid),
        .aux_out(pipe_aux_out),
        .meta_out(pipe_meta_out),
        .data_out_ready(pipe_out_ready)
    );
end else begin : g_dec
    aes128_pipeline_dec dec_pipe (
        .clk(clk),
        .rst_n(rst_n),
        .data_in(pipe_data_in),
        .data_in_valid(pipe_data_in_valid),
        .data_in_ready(pipe_data_in_ready),
        .aux_in(pipe_aux_in),
        .meta_in(pipe_meta_in),
        .round_keys(round_key_dec),
        .key_ready(key_ready_int),
        .data_out(pipe_data_out),
        .data_out_valid(pipe_data_out_valid),
        .aux_out(pipe_aux_out),
        .meta_out(pipe_meta_out),
        .data_out_ready(pipe_out_ready)
    );
end
endgenerate

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        pack_data  <= 128'h0;
        pack_keep  <= 16'h0;
        pack_beat  <= 3'd0;
        blk_data   <= 128'h0;
        blk_keep   <= 16'h0;
        blk_beats  <= 3'd0;
        blk_last   <= 1'b0;
        blk_valid  <= 1'b0;
    end else if (in_fire) begin
        if (live_commit) begin
            pack_data <= 128'h0;
            pack_keep <= 16'h0;
            pack_beat <= 3'd0;
        end else if (beat_completes) begin
            blk_data  <= pack_next_data;
            blk_keep  <= pack_next_keep;
            blk_beats <= pack_beat + 3'd1;
            blk_last  <= data_in_last;
            blk_valid <= 1'b1;
            pack_data <= 128'h0;
            pack_keep <= 16'h0;
            pack_beat <= 3'd0;
        end else begin
            pack_data <= pack_next_data;
            pack_keep <= pack_next_keep;
            pack_beat <= pack_beat + 3'd1;
        end
    end else if (held_hs) begin
        blk_valid <= 1'b0;
    end
end

always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        buf_data  <= 128'h0;
        buf_keep  <= 16'h0;
        buf_beat  <= 3'd0;
        buf_beats <= 3'd0;
        buf_last  <= 1'b0;
        buf_valid <= 1'b0;
        skid_data  <= {DATA_WIDTH{1'b0}};
        skid_keep  <= {KEEP_W{1'b0}};
        skid_valid <= 1'b0;
        skid_last  <= 1'b0;
        skid_eob   <= 1'b0;
    end else begin
        if (take_beat) begin
            skid_data  <= apply_keep(buf_beat_data, buf_beat_keep);
            skid_keep  <= buf_beat_keep;
            skid_last  <= buf_last && (buf_beat == buf_last_idx);
            skid_eob   <= (buf_beat == buf_last_idx);
            skid_valid <= 1'b1;
        end else if (skid_fire) begin
            skid_valid <= 1'b0;
            skid_last  <= 1'b0;
            skid_eob   <= 1'b0;
        end

        if (pipe_take) begin
            buf_data  <= result_block;
            buf_keep  <= pipe_meta_out[15:0];
            buf_beats <= pipe_meta_out[18:16];
            buf_last  <= pipe_meta_out[19];
            buf_beat  <= 3'd0;
            buf_valid <= 1'b1;
        end else if (take_beat) begin
            if (buf_beat == buf_last_idx)
                buf_valid <= 1'b0;
            else
                buf_beat <= buf_beat + 3'd1;
        end
    end
end

// ============================================================================
// Chain register, CBC-encrypt busy flag, and in-flight block counter.
// accept_fires / consume_fires count 128-bit blocks, not narrow beats.
// A pending IV is installed only while idle, and it wins over the CBC/CTR
// chain update so a new message does not mix with the previous one.
// ============================================================================
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        chain_reg       <= 128'h0;
        cbc_enc_busy    <= 1'b0;
        in_flight_count <= 6'd0;
    end else begin
        if (iv_install) begin
            chain_reg <= iv_candidate;
        end else if (IS_ENCRYPT && is_cbc && cbc_enc_busy && pipe_data_out_valid) begin
            chain_reg <= pipe_data_out;
        end else if (!IS_ENCRYPT && is_cbc && accept_fires) begin
            chain_reg <= xfer_data;
        end else if (IS_ENCRYPT && is_ctr && accept_fires) begin
            chain_reg <= chain_reg + 128'h1;
        end

        if (IS_ENCRYPT && is_cbc) begin
            if (accept_fires) begin
                cbc_enc_busy <= 1'b1;
            end else if (cbc_enc_busy && pipe_data_out_valid) begin
                cbc_enc_busy <= 1'b0;
            end
        end else begin
            cbc_enc_busy <= 1'b0;
        end

        case ({accept_fires, consume_fires})
            2'b10:   in_flight_count <= in_flight_count + 6'd1;
            2'b01:   in_flight_count <= in_flight_count - 6'd1;
            default: in_flight_count <= in_flight_count;
        endcase
    end
end

endmodule
