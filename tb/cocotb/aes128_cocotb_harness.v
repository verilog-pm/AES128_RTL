// =============================================================================
// Simulation-only harness. aes128_top itself instantiates one pipeline.
// This wrapper keeps the cocotb bench able to cover encrypt and decrypt by
// muxing two separately parameterized cores. CTR always uses the encrypt core.
// Data beats are DATA_WIDTH bits (default 32), MSB-first within a 128-bit block.
// =============================================================================

module aes128_cocotb_harness #(
    parameter DATA_WIDTH = 32
) (
    input  wire         clk,
    input  wire         rst_n,

    input  wire [127:0] key,
    input  wire         key_valid,

    input  wire         mode,       // 0=encrypt core, 1=decrypt core
    input  wire [1:0]   op_mode,

    input  wire [127:0] iv,
    input  wire         iv_valid,

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

// CTR encrypt and decrypt both use the encryption pipeline.
wire use_enc = (mode == 1'b0) || (op_mode == 2'b10);

wire         enc_ready, dec_ready;
wire         enc_out_valid, dec_out_valid;
wire         enc_last, dec_last;
wire [DATA_WIDTH-1:0] enc_out, dec_out;
wire [DATA_WIDTH/8-1:0] enc_keep, dec_keep;

aes128_top #(.mode(1'b0), .DATA_WIDTH(DATA_WIDTH)) u_enc (
    .clk(clk),
    .rst_n(rst_n),
    .key(key),
    .key_valid(key_valid),
    .op_mode(op_mode),
    .iv(iv),
    .iv_valid(iv_valid && use_enc),
    .data_in(data_in),
    .data_in_valid(data_in_valid && use_enc),
    .data_in_last(data_in_last && use_enc),
    .data_in_keep(data_in_keep),
    .data_in_ready(enc_ready),
    .data_out(enc_out),
    .data_out_valid(enc_out_valid),
    .data_out_last(enc_last),
    .data_out_keep(enc_keep),
    .data_out_ready(data_out_ready)
);

aes128_top #(.mode(1'b1), .DATA_WIDTH(DATA_WIDTH)) u_dec (
    .clk(clk),
    .rst_n(rst_n),
    .key(key),
    .key_valid(key_valid),
    .op_mode(op_mode),
    .iv(iv),
    .iv_valid(iv_valid && !use_enc),
    .data_in(data_in),
    .data_in_valid(data_in_valid && !use_enc),
    .data_in_last(data_in_last && !use_enc),
    .data_in_keep(data_in_keep),
    .data_in_ready(dec_ready),
    .data_out(dec_out),
    .data_out_valid(dec_out_valid),
    .data_out_last(dec_last),
    .data_out_keep(dec_keep),
    .data_out_ready(data_out_ready)
);

assign data_in_ready  = use_enc ? enc_ready : dec_ready;
assign data_out       = use_enc ? enc_out : dec_out;
assign data_out_valid = use_enc ? enc_out_valid : dec_out_valid;
assign data_out_last  = use_enc ? enc_last : dec_last;
assign data_out_keep  = use_enc ? enc_keep : dec_keep;

endmodule
