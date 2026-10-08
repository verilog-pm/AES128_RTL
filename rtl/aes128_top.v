// =============================================================================
// AES-128 Top Module
// Integrates encryption/decryption pipelines with key schedule
// Supports mode switching between encryption and decryption, and multiple
// block-cipher operating modes: ECB, CBC, and CTR.
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
//         P_i = C_i XOR keystream_i (decrypt) -- the operation is symmetric,
//         so CTR always uses the encryption pipeline to generate the
//         keystream regardless of the `mode` input. Fully pipelined; the
//         counter is incremented immediately on acceptance of each block.
//
// `iv` seeds the CBC previous-ciphertext register or the CTR counter. It must
// only be (re)loaded while the pipeline is idle (see `iv_ready`), i.e. before
// starting a new message / stream. Likewise `mode` and `op_mode` should only
// be changed while idle.
// =============================================================================

module aes128_top (
    input  wire         clk,
    input  wire         rst_n,

    // Key interface
    input  wire [127:0] key,
    input  wire         key_valid,
    output wire         key_ready,

    // Mode selection
    input  wire         mode,     // 0=encrypt, 1=decrypt (ignored by CTR)
    input  wire [1:0]   op_mode,  // 00=ECB, 01=CBC, 10=CTR (11 reserved -> ECB)

    // IV / initial counter interface (used by CBC and CTR; ignored by ECB).
    // Load a fresh IV before starting a new message/stream. Only sample when
    // iv_ready is asserted (pipeline idle, i.e. no blocks in flight).
    input  wire [127:0] iv,
    input  wire         iv_valid,
    output wire         iv_ready,

    // Data interface
    input  wire [127:0] data_in,
    input  wire         data_in_valid,
    output wire         data_in_ready,

    output wire [127:0] data_out,
    output wire         data_out_valid,
    input  wire         data_out_ready
);

// ============================================================================
// Operating-mode decode
// ============================================================================
localparam OP_MODE_CBC = 2'b01;
localparam OP_MODE_CTR = 2'b10;

wire is_cbc = (op_mode == OP_MODE_CBC);
wire is_ctr = (op_mode == OP_MODE_CTR);
wire is_ecb = !is_cbc && !is_ctr;  // covers 2'b00 and the reserved 2'b11

// ============================================================================
// Internal signals
// ============================================================================
wire [1408-1:0] round_key_enc;  // 11 * 128 = 1408 bits
wire [1408-1:0] round_key_dec;  // 11 * 128 = 1408 bits
wire key_ready_int;

// Encryption pipeline signals
wire [127:0] enc_data_out;
wire         enc_data_out_valid;
wire         enc_data_in_ready;
wire [127:0] enc_aux_out;

// Decryption pipeline signals
wire [127:0] dec_data_out;
wire         dec_data_out_valid;
wire         dec_data_in_ready;
wire [127:0] dec_aux_out;

// Data output mux based on active pipeline / mode
reg [127:0] data_out_int;

// ============================================================================
// Chain state: previous ciphertext (CBC) or running counter (CTR)
// ============================================================================
reg [127:0] chain_reg;
reg         cbc_enc_busy;  // serializes CBC-encrypt: 1 block in flight at a time

// Number of blocks accepted on data_in but not yet delivered on data_out.
// Used to gate iv_ready so a new IV/counter is only loaded while the
// pipeline and output FIFO are fully drained.
reg [5:0] in_flight_count;

// ============================================================================
// Key Schedule Module
// ============================================================================
key_schedule key_sched (
    .clk(clk),
    .rst_n(rst_n),
    .key(key),
    .key_valid(key_valid),
    .key_ready(key_ready_int),
    .round_key_enc(round_key_enc),
    .round_key_dec(round_key_dec)
);

assign key_ready = key_ready_int;

// ============================================================================
// Path selection
//   enc_path : ECB-encrypt, CBC-encrypt, and CTR (both directions)
//   dec_path : ECB-decrypt, CBC-decrypt
// ============================================================================
wire enc_path_active = is_ctr || (mode == 1'b0);
wire dec_path_active = !is_ctr && (mode == 1'b1);

// CBC-encrypt may only accept a new block while the previous one has
// finished (its ciphertext is needed as the next block's XOR operand).
wire enc_gate   = (is_cbc && mode == 1'b0) ? !cbc_enc_busy : 1'b1;
wire enc_select = enc_path_active && enc_gate;
wire dec_select = dec_path_active;

// ============================================================================
// Encryption pipeline input wiring
//   ECB-encrypt : data_in                      , aux unused
//   CBC-encrypt : data_in XOR chain_reg         , aux unused
//   CTR         : chain_reg (counter)           , aux = data_in (P or C block)
// ============================================================================
wire [127:0] enc_pipe_data_in = is_ctr ? chain_reg :
                                 is_cbc ? (data_in ^ chain_reg) :
                                          data_in;
wire [127:0] enc_pipe_aux_in  = is_ctr ? data_in : 128'h0;

aes128_pipeline_enc enc_pipe (
    .clk(clk),
    .rst_n(rst_n),
    .data_in(enc_pipe_data_in),
    .data_in_valid(data_in_valid && enc_select),
    .data_in_ready(enc_data_in_ready),
    .aux_in(enc_pipe_aux_in),
    .round_keys(round_key_enc),
    .key_ready(key_ready_int),
    .data_out(enc_data_out),
    .data_out_valid(enc_data_out_valid),
    .aux_out(enc_aux_out),
    .data_out_ready(data_out_ready)
);

// ============================================================================
// Decryption pipeline input wiring
//   ECB-decrypt : data_in           , aux unused
//   CBC-decrypt : data_in           , aux = chain_reg (previous ciphertext)
// ============================================================================
wire [127:0] dec_pipe_aux_in = is_cbc ? chain_reg : 128'h0;

aes128_pipeline_dec dec_pipe (
    .clk(clk),
    .rst_n(rst_n),
    .data_in(data_in),
    .data_in_valid(data_in_valid && dec_select),
    .data_in_ready(dec_data_in_ready),
    .aux_in(dec_pipe_aux_in),
    .round_keys(round_key_dec),
    .key_ready(key_ready_int),
    .data_out(dec_data_out),
    .data_out_valid(dec_data_out_valid),
    .aux_out(dec_aux_out),
    .data_out_ready(data_out_ready)
);

// ============================================================================
// Data input ready: forwarded from whichever pipeline is currently selected
// ============================================================================
assign data_in_ready = enc_select ? enc_data_in_ready :
                        dec_select ? dec_data_in_ready :
                                     1'b0;

wire accept_fires  = data_in_valid && data_in_ready;
wire enc_accept_fires = data_in_valid && enc_select && enc_data_in_ready;
wire dec_accept_fires = data_in_valid && dec_select && dec_data_in_ready;

// ============================================================================
// Data output mux
//   CTR         : enc_data_out XOR enc_aux_out (keystream XOR block)
//   CBC-decrypt : dec_data_out XOR dec_aux_out (AES output XOR prev cipher)
//   ECB / CBC-encrypt : pipeline output taken directly
// ============================================================================
always @(*) begin
    if (enc_data_out_valid) begin
        data_out_int = is_ctr ? (enc_data_out ^ enc_aux_out) : enc_data_out;
    end else if (dec_data_out_valid) begin
        data_out_int = is_cbc ? (dec_data_out ^ dec_aux_out) : dec_data_out;
    end else begin
        data_out_int = 128'h0;
    end
end

assign data_out = data_out_int;
assign data_out_valid = enc_data_out_valid || dec_data_out_valid;

wire consume_fires = data_out_valid && data_out_ready;

// ============================================================================
// IV / counter loading: only while no blocks are in flight
// ============================================================================
assign iv_ready = (in_flight_count == 6'd0);

// ============================================================================
// Chain register, CBC-encrypt busy flag, and in-flight block counter
// ============================================================================
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        chain_reg    <= 128'h0;
        cbc_enc_busy <= 1'b0;
        in_flight_count <= 6'd0;
    end else begin
        // --- Chain register update -----------------------------------
        if (iv_valid && iv_ready) begin
            chain_reg <= iv;
        end else if (is_cbc && mode == 1'b0 && cbc_enc_busy && enc_data_out_valid) begin
            // CBC-encrypt: next block's XOR operand is this block's ciphertext
            chain_reg <= enc_data_out;
        end else if (is_cbc && mode == 1'b1 && dec_accept_fires) begin
            // CBC-decrypt: next block's XOR operand is this incoming ciphertext
            chain_reg <= data_in;
        end else if (is_ctr && enc_accept_fires) begin
            // CTR: advance the counter once its block has been accepted
            chain_reg <= chain_reg + 128'h1;
        end

        // --- CBC-encrypt serialization flag ---------------------------
        if (is_cbc && mode == 1'b0) begin
            if (enc_accept_fires) begin
                cbc_enc_busy <= 1'b1;
            end else if (cbc_enc_busy && enc_data_out_valid) begin
                cbc_enc_busy <= 1'b0;
            end
        end else begin
            cbc_enc_busy <= 1'b0;
        end

        // --- In-flight block counter -----------------------------------
        case ({accept_fires, consume_fires})
            2'b10: in_flight_count <= in_flight_count + 6'd1;
            2'b01: in_flight_count <= in_flight_count - 6'd1;
            default: in_flight_count <= in_flight_count;
        endcase
    end
end

endmodule
