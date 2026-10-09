// =============================================================================
// AES-128 Decryption Pipeline (Structural)
// 10-stage pipelined architecture
// Stage 0: AddRoundKey(dec_key[10]) - initial inverse round key
// Stages 1-9: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns
// Stage 10: InvShiftRows -> InvSubBytes -> AddRoundKey(dec_key[0]) (no InvMixColumns)
// Based on FIPS-197 Section 5.3
// =============================================================================

module aes128_pipeline_dec (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [127:0] data_in,
    input  wire         data_in_valid,
    output wire         data_in_ready,
    input  wire [127:0] aux_in,       // side-channel value carried through the
                                       // pipeline/FIFO in lockstep with data_in.
                                       // CBC-decrypt uses this to carry the
                                       // previous ciphertext block so it can be
                                       // XORed with the AES core output once it
                                       // finally emerges from the pipeline.
                                       // Unused (tie to 0) for ECB.
    input  wire [19:0]  meta_in,      // {packet_last, beat_count[2:0], byte_keep[15:0]}
    input  wire [1407:0] round_keys,  // 11 * 128 = 1408 bits for decryption round keys
    input  wire         key_ready,
    output reg  [127:0] data_out,
    output reg          data_out_valid,
    output reg  [127:0] aux_out,      // aux_in delayed by the same latency as data_out
    output reg  [19:0]  meta_out,
    input  wire         data_out_ready
);

// ============================================================================
// Pipeline registers - 11 stages (declared first for use in control logic)
// ============================================================================
reg [127:0] pipe_data [0:10];
reg         pipe_valid [0:10];
reg [127:0] pipe_aux  [0:10];  // shadow pipeline carrying aux_in alongside data
reg [19:0]  pipe_meta [0:10];

// ============================================================================
// Control signals - Optimized for continuous throughput
// ============================================================================
// Output FIFO signals
reg  [127:0] fifo_data [0:15];
reg  [127:0] fifo_aux  [0:15];
reg  [19:0]  fifo_meta [0:15];
reg          fifo_valid [0:15];
reg  [3:0]   fifo_wr_ptr;
reg  [3:0]   fifo_rd_ptr;
reg  [4:0]   fifo_count;

wire         fifo_full;
wire         fifo_empty;
wire         fifo_wr_en;
wire         fifo_rd_en;

assign fifo_full  = (fifo_count == 5'd16);
assign fifo_empty = (fifo_count == 5'd0);
assign fifo_wr_en = pipe_valid[10] && !fifo_full;
assign fifo_rd_en = !fifo_empty && data_out_ready;

// Pipeline enable: only stall if FIFO is full (prevents data loss)
wire pipe_en;
assign pipe_en = key_ready && !fifo_full;

// Input ready: can accept new data when pipeline is enabled
assign data_in_ready = pipe_en;

// ============================================================================
// InvShiftRows function (inverse of ShiftRows)
// Row 0: no shift
// Row 1: shift right by 1 [s0,s4,s8,s12] -> [s0,s13,s10,s7]
// Row 2: shift right by 2
// Row 3: shift right by 3
// ============================================================================
// State byte s_i occupies row (i%4), column (i/4), matching the column-major
// layout used by inv_mix_columns (column c = bytes {4c, 4c+1, 4c+2, 4c+3}).
// InvShiftRows: new[row][col] = old[row][(col-row) mod 4]
function [127:0] inv_shift_rows_func;
    input [127:0] data;
    reg [7:0] s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;
begin
    s0  = data[127:120]; s1  = data[119:112]; s2  = data[111:104]; s3  = data[103:96];
    s4  = data[95:88];   s5  = data[87:80];   s6  = data[79:72];   s7  = data[71:64];
    s8  = data[63:56];   s9  = data[55:48];   s10 = data[47:40];   s11 = data[39:32];
    s12 = data[31:24];   s13 = data[23:16];   s14 = data[15:8];    s15 = data[7:0];
    inv_shift_rows_func = {s0,s13,s10,s7, s4,s1,s14,s11, s8,s5,s2,s15, s12,s9,s6,s3};
end
endfunction

// ============================================================================
// S-box for InvSubBytes (inverse S-box)
// We'll use the inv_sbox module
// ============================================================================

// ============================================================================
// Stage 0: Initial AddRoundKey with decryption key[10]
// ============================================================================

// ============================================================================
// S-box instances for each stage (using inv_sbox)
// ============================================================================
wire [7:0] s1_isb_out [0:15];
wire [7:0] s2_isb_out [0:15];
wire [7:0] s3_isb_out [0:15];
wire [7:0] s4_isb_out [0:15];
wire [7:0] s5_isb_out [0:15];
wire [7:0] s6_isb_out [0:15];
wire [7:0] s7_isb_out [0:15];
wire [7:0] s8_isb_out [0:15];
wire [7:0] s9_isb_out [0:15];
wire [7:0] s10_isb_out [0:15];

// Stage 1 inv_sboxes
inv_sbox s1_isb0  (.in_data(pipe_data[0][127:120]), .out_data(s1_isb_out[0]));
inv_sbox s1_isb1  (.in_data(pipe_data[0][119:112]), .out_data(s1_isb_out[1]));
inv_sbox s1_isb2  (.in_data(pipe_data[0][111:104]), .out_data(s1_isb_out[2]));
inv_sbox s1_isb3  (.in_data(pipe_data[0][103:96]),  .out_data(s1_isb_out[3]));
inv_sbox s1_isb4  (.in_data(pipe_data[0][95:88]),   .out_data(s1_isb_out[4]));
inv_sbox s1_isb5  (.in_data(pipe_data[0][87:80]),   .out_data(s1_isb_out[5]));
inv_sbox s1_isb6  (.in_data(pipe_data[0][79:72]),   .out_data(s1_isb_out[6]));
inv_sbox s1_isb7  (.in_data(pipe_data[0][71:64]),   .out_data(s1_isb_out[7]));
inv_sbox s1_isb8  (.in_data(pipe_data[0][63:56]),   .out_data(s1_isb_out[8]));
inv_sbox s1_isb9  (.in_data(pipe_data[0][55:48]),   .out_data(s1_isb_out[9]));
inv_sbox s1_isb10 (.in_data(pipe_data[0][47:40]),   .out_data(s1_isb_out[10]));
inv_sbox s1_isb11 (.in_data(pipe_data[0][39:32]),   .out_data(s1_isb_out[11]));
inv_sbox s1_isb12 (.in_data(pipe_data[0][31:24]),   .out_data(s1_isb_out[12]));
inv_sbox s1_isb13 (.in_data(pipe_data[0][23:16]),   .out_data(s1_isb_out[13]));
inv_sbox s1_isb14 (.in_data(pipe_data[0][15:8]),    .out_data(s1_isb_out[14]));
inv_sbox s1_isb15 (.in_data(pipe_data[0][7:0]),     .out_data(s1_isb_out[15]));

// Stage 1 InvShiftRows output
wire [127:0] s1_isr_out = inv_shift_rows_func(
    {s1_isb_out[0],s1_isb_out[1],s1_isb_out[2],s1_isb_out[3],
     s1_isb_out[4],s1_isb_out[5],s1_isb_out[6],s1_isb_out[7],
     s1_isb_out[8],s1_isb_out[9],s1_isb_out[10],s1_isb_out[11],
     s1_isb_out[12],s1_isb_out[13],s1_isb_out[14],s1_isb_out[15]}
);

// Stage 1 InvMixColumns (applied BEFORE AddRoundKey in the equivalent inverse
// cipher, since round_keys[] here are pre-transformed with InvMixColumns)
wire [31:0] s1_imc_col0, s1_imc_col1, s1_imc_col2, s1_imc_col3;
inv_mix_columns s1_imc0 (.col_in(s1_isr_out[127:96]), .col_out(s1_imc_col0));
inv_mix_columns s1_imc1 (.col_in(s1_isr_out[95:64]),  .col_out(s1_imc_col1));
inv_mix_columns s1_imc2 (.col_in(s1_isr_out[63:32]),  .col_out(s1_imc_col2));
inv_mix_columns s1_imc3 (.col_in(s1_isr_out[31:0]),   .col_out(s1_imc_col3));

wire [127:0] s1_imc_out = {s1_imc_col0, s1_imc_col1, s1_imc_col2, s1_imc_col3};

// Stage 1 AddRoundKey
wire [127:0] s1_out = s1_imc_out ^ round_keys[128 +: 128];

// ============================================================================
// Stages 2-9 (following the same pattern)
// ============================================================================

// Stage 2 inv_sboxes
inv_sbox s2_isb0  (.in_data(pipe_data[1][127:120]), .out_data(s2_isb_out[0]));
inv_sbox s2_isb1  (.in_data(pipe_data[1][119:112]), .out_data(s2_isb_out[1]));
inv_sbox s2_isb2  (.in_data(pipe_data[1][111:104]), .out_data(s2_isb_out[2]));
inv_sbox s2_isb3  (.in_data(pipe_data[1][103:96]),  .out_data(s2_isb_out[3]));
inv_sbox s2_isb4  (.in_data(pipe_data[1][95:88]),   .out_data(s2_isb_out[4]));
inv_sbox s2_isb5  (.in_data(pipe_data[1][87:80]),   .out_data(s2_isb_out[5]));
inv_sbox s2_isb6  (.in_data(pipe_data[1][79:72]),   .out_data(s2_isb_out[6]));
inv_sbox s2_isb7  (.in_data(pipe_data[1][71:64]),   .out_data(s2_isb_out[7]));
inv_sbox s2_isb8  (.in_data(pipe_data[1][63:56]),   .out_data(s2_isb_out[8]));
inv_sbox s2_isb9  (.in_data(pipe_data[1][55:48]),   .out_data(s2_isb_out[9]));
inv_sbox s2_isb10 (.in_data(pipe_data[1][47:40]),   .out_data(s2_isb_out[10]));
inv_sbox s2_isb11 (.in_data(pipe_data[1][39:32]),   .out_data(s2_isb_out[11]));
inv_sbox s2_isb12 (.in_data(pipe_data[1][31:24]),   .out_data(s2_isb_out[12]));
inv_sbox s2_isb13 (.in_data(pipe_data[1][23:16]),   .out_data(s2_isb_out[13]));
inv_sbox s2_isb14 (.in_data(pipe_data[1][15:8]),    .out_data(s2_isb_out[14]));
inv_sbox s2_isb15 (.in_data(pipe_data[1][7:0]),     .out_data(s2_isb_out[15]));

wire [127:0] s2_isr_out = inv_shift_rows_func(
    {s2_isb_out[0],s2_isb_out[1],s2_isb_out[2],s2_isb_out[3],
     s2_isb_out[4],s2_isb_out[5],s2_isb_out[6],s2_isb_out[7],
     s2_isb_out[8],s2_isb_out[9],s2_isb_out[10],s2_isb_out[11],
     s2_isb_out[12],s2_isb_out[13],s2_isb_out[14],s2_isb_out[15]}
);

wire [31:0] s2_imc_col0, s2_imc_col1, s2_imc_col2, s2_imc_col3;
inv_mix_columns s2_imc0 (.col_in(s2_isr_out[127:96]), .col_out(s2_imc_col0));
inv_mix_columns s2_imc1 (.col_in(s2_isr_out[95:64]),  .col_out(s2_imc_col1));
inv_mix_columns s2_imc2 (.col_in(s2_isr_out[63:32]),  .col_out(s2_imc_col2));
inv_mix_columns s2_imc3 (.col_in(s2_isr_out[31:0]),   .col_out(s2_imc_col3));

wire [127:0] s2_imc_out = {s2_imc_col0, s2_imc_col1, s2_imc_col2, s2_imc_col3};
wire [127:0] s2_out = s2_imc_out ^ round_keys[256 +: 128];

// Stage 3
inv_sbox s3_isb0  (.in_data(pipe_data[2][127:120]), .out_data(s3_isb_out[0]));
inv_sbox s3_isb1  (.in_data(pipe_data[2][119:112]), .out_data(s3_isb_out[1]));
inv_sbox s3_isb2  (.in_data(pipe_data[2][111:104]), .out_data(s3_isb_out[2]));
inv_sbox s3_isb3  (.in_data(pipe_data[2][103:96]),  .out_data(s3_isb_out[3]));
inv_sbox s3_isb4  (.in_data(pipe_data[2][95:88]),   .out_data(s3_isb_out[4]));
inv_sbox s3_isb5  (.in_data(pipe_data[2][87:80]),   .out_data(s3_isb_out[5]));
inv_sbox s3_isb6  (.in_data(pipe_data[2][79:72]),   .out_data(s3_isb_out[6]));
inv_sbox s3_isb7  (.in_data(pipe_data[2][71:64]),   .out_data(s3_isb_out[7]));
inv_sbox s3_isb8  (.in_data(pipe_data[2][63:56]),   .out_data(s3_isb_out[8]));
inv_sbox s3_isb9  (.in_data(pipe_data[2][55:48]),   .out_data(s3_isb_out[9]));
inv_sbox s3_isb10 (.in_data(pipe_data[2][47:40]),   .out_data(s3_isb_out[10]));
inv_sbox s3_isb11 (.in_data(pipe_data[2][39:32]),   .out_data(s3_isb_out[11]));
inv_sbox s3_isb12 (.in_data(pipe_data[2][31:24]),   .out_data(s3_isb_out[12]));
inv_sbox s3_isb13 (.in_data(pipe_data[2][23:16]),   .out_data(s3_isb_out[13]));
inv_sbox s3_isb14 (.in_data(pipe_data[2][15:8]),    .out_data(s3_isb_out[14]));
inv_sbox s3_isb15 (.in_data(pipe_data[2][7:0]),     .out_data(s3_isb_out[15]));

wire [127:0] s3_isr_out = inv_shift_rows_func(
    {s3_isb_out[0],s3_isb_out[1],s3_isb_out[2],s3_isb_out[3],
     s3_isb_out[4],s3_isb_out[5],s3_isb_out[6],s3_isb_out[7],
     s3_isb_out[8],s3_isb_out[9],s3_isb_out[10],s3_isb_out[11],
     s3_isb_out[12],s3_isb_out[13],s3_isb_out[14],s3_isb_out[15]}
);

wire [31:0] s3_imc_col0, s3_imc_col1, s3_imc_col2, s3_imc_col3;
inv_mix_columns s3_imc0 (.col_in(s3_isr_out[127:96]), .col_out(s3_imc_col0));
inv_mix_columns s3_imc1 (.col_in(s3_isr_out[95:64]),  .col_out(s3_imc_col1));
inv_mix_columns s3_imc2 (.col_in(s3_isr_out[63:32]),  .col_out(s3_imc_col2));
inv_mix_columns s3_imc3 (.col_in(s3_isr_out[31:0]),   .col_out(s3_imc_col3));

wire [127:0] s3_imc_out = {s3_imc_col0, s3_imc_col1, s3_imc_col2, s3_imc_col3};
wire [127:0] s3_out = s3_imc_out ^ round_keys[384 +: 128];

// Due to space, stages 4-9 are abbreviated similarly
// Each follows the pattern: InvSubBytes -> InvShiftRows -> AddRoundKey -> InvMixColumns
// For round keys 4-9, InvMixColumns is applied
// For final round (10), InvMixColumns is NOT applied

// Stage 4-9 follow the same pattern
inv_sbox s4_isb0  (.in_data(pipe_data[3][127:120]), .out_data(s4_isb_out[0]));
inv_sbox s4_isb1  (.in_data(pipe_data[3][119:112]), .out_data(s4_isb_out[1]));
inv_sbox s4_isb2  (.in_data(pipe_data[3][111:104]), .out_data(s4_isb_out[2]));
inv_sbox s4_isb3  (.in_data(pipe_data[3][103:96]),  .out_data(s4_isb_out[3]));
inv_sbox s4_isb4  (.in_data(pipe_data[3][95:88]),   .out_data(s4_isb_out[4]));
inv_sbox s4_isb5  (.in_data(pipe_data[3][87:80]),   .out_data(s4_isb_out[5]));
inv_sbox s4_isb6  (.in_data(pipe_data[3][79:72]),   .out_data(s4_isb_out[6]));
inv_sbox s4_isb7  (.in_data(pipe_data[3][71:64]),   .out_data(s4_isb_out[7]));
inv_sbox s4_isb8  (.in_data(pipe_data[3][63:56]),   .out_data(s4_isb_out[8]));
inv_sbox s4_isb9  (.in_data(pipe_data[3][55:48]),   .out_data(s4_isb_out[9]));
inv_sbox s4_isb10 (.in_data(pipe_data[3][47:40]),   .out_data(s4_isb_out[10]));
inv_sbox s4_isb11 (.in_data(pipe_data[3][39:32]),   .out_data(s4_isb_out[11]));
inv_sbox s4_isb12 (.in_data(pipe_data[3][31:24]),   .out_data(s4_isb_out[12]));
inv_sbox s4_isb13 (.in_data(pipe_data[3][23:16]),   .out_data(s4_isb_out[13]));
inv_sbox s4_isb14 (.in_data(pipe_data[3][15:8]),    .out_data(s4_isb_out[14]));
inv_sbox s4_isb15 (.in_data(pipe_data[3][7:0]),     .out_data(s4_isb_out[15]));

wire [127:0] s4_isr_out = inv_shift_rows_func(
    {s4_isb_out[0],s4_isb_out[1],s4_isb_out[2],s4_isb_out[3],
     s4_isb_out[4],s4_isb_out[5],s4_isb_out[6],s4_isb_out[7],
     s4_isb_out[8],s4_isb_out[9],s4_isb_out[10],s4_isb_out[11],
     s4_isb_out[12],s4_isb_out[13],s4_isb_out[14],s4_isb_out[15]}
);

wire [31:0] s4_imc_col0, s4_imc_col1, s4_imc_col2, s4_imc_col3;
inv_mix_columns s4_imc0 (.col_in(s4_isr_out[127:96]), .col_out(s4_imc_col0));
inv_mix_columns s4_imc1 (.col_in(s4_isr_out[95:64]),  .col_out(s4_imc_col1));
inv_mix_columns s4_imc2 (.col_in(s4_isr_out[63:32]),  .col_out(s4_imc_col2));
inv_mix_columns s4_imc3 (.col_in(s4_isr_out[31:0]),   .col_out(s4_imc_col3));
wire [127:0] s4_imc_out = {s4_imc_col0, s4_imc_col1, s4_imc_col2, s4_imc_col3};
wire [127:0] s4_out = s4_imc_out ^ round_keys[512 +: 128];

// Stage 5
inv_sbox s5_isb0  (.in_data(pipe_data[4][127:120]), .out_data(s5_isb_out[0]));
inv_sbox s5_isb1  (.in_data(pipe_data[4][119:112]), .out_data(s5_isb_out[1]));
inv_sbox s5_isb2  (.in_data(pipe_data[4][111:104]), .out_data(s5_isb_out[2]));
inv_sbox s5_isb3  (.in_data(pipe_data[4][103:96]),  .out_data(s5_isb_out[3]));
inv_sbox s5_isb4  (.in_data(pipe_data[4][95:88]),   .out_data(s5_isb_out[4]));
inv_sbox s5_isb5  (.in_data(pipe_data[4][87:80]),   .out_data(s5_isb_out[5]));
inv_sbox s5_isb6  (.in_data(pipe_data[4][79:72]),   .out_data(s5_isb_out[6]));
inv_sbox s5_isb7  (.in_data(pipe_data[4][71:64]),   .out_data(s5_isb_out[7]));
inv_sbox s5_isb8  (.in_data(pipe_data[4][63:56]),   .out_data(s5_isb_out[8]));
inv_sbox s5_isb9  (.in_data(pipe_data[4][55:48]),   .out_data(s5_isb_out[9]));
inv_sbox s5_isb10 (.in_data(pipe_data[4][47:40]),   .out_data(s5_isb_out[10]));
inv_sbox s5_isb11 (.in_data(pipe_data[4][39:32]),   .out_data(s5_isb_out[11]));
inv_sbox s5_isb12 (.in_data(pipe_data[4][31:24]),   .out_data(s5_isb_out[12]));
inv_sbox s5_isb13 (.in_data(pipe_data[4][23:16]),   .out_data(s5_isb_out[13]));
inv_sbox s5_isb14 (.in_data(pipe_data[4][15:8]),    .out_data(s5_isb_out[14]));
inv_sbox s5_isb15 (.in_data(pipe_data[4][7:0]),     .out_data(s5_isb_out[15]));

wire [127:0] s5_isr_out = inv_shift_rows_func(
    {s5_isb_out[0],s5_isb_out[1],s5_isb_out[2],s5_isb_out[3],
     s5_isb_out[4],s5_isb_out[5],s5_isb_out[6],s5_isb_out[7],
     s5_isb_out[8],s5_isb_out[9],s5_isb_out[10],s5_isb_out[11],
     s5_isb_out[12],s5_isb_out[13],s5_isb_out[14],s5_isb_out[15]}
);

wire [31:0] s5_imc_col0, s5_imc_col1, s5_imc_col2, s5_imc_col3;
inv_mix_columns s5_imc0 (.col_in(s5_isr_out[127:96]), .col_out(s5_imc_col0));
inv_mix_columns s5_imc1 (.col_in(s5_isr_out[95:64]),  .col_out(s5_imc_col1));
inv_mix_columns s5_imc2 (.col_in(s5_isr_out[63:32]),  .col_out(s5_imc_col2));
inv_mix_columns s5_imc3 (.col_in(s5_isr_out[31:0]),   .col_out(s5_imc_col3));
wire [127:0] s5_imc_out = {s5_imc_col0, s5_imc_col1, s5_imc_col2, s5_imc_col3};
wire [127:0] s5_out = s5_imc_out ^ round_keys[640 +: 128];

// Stage 6
inv_sbox s6_isb0  (.in_data(pipe_data[5][127:120]), .out_data(s6_isb_out[0]));
inv_sbox s6_isb1  (.in_data(pipe_data[5][119:112]), .out_data(s6_isb_out[1]));
inv_sbox s6_isb2  (.in_data(pipe_data[5][111:104]), .out_data(s6_isb_out[2]));
inv_sbox s6_isb3  (.in_data(pipe_data[5][103:96]),  .out_data(s6_isb_out[3]));
inv_sbox s6_isb4  (.in_data(pipe_data[5][95:88]),   .out_data(s6_isb_out[4]));
inv_sbox s6_isb5  (.in_data(pipe_data[5][87:80]),   .out_data(s6_isb_out[5]));
inv_sbox s6_isb6  (.in_data(pipe_data[5][79:72]),   .out_data(s6_isb_out[6]));
inv_sbox s6_isb7  (.in_data(pipe_data[5][71:64]),   .out_data(s6_isb_out[7]));
inv_sbox s6_isb8  (.in_data(pipe_data[5][63:56]),   .out_data(s6_isb_out[8]));
inv_sbox s6_isb9  (.in_data(pipe_data[5][55:48]),   .out_data(s6_isb_out[9]));
inv_sbox s6_isb10 (.in_data(pipe_data[5][47:40]),   .out_data(s6_isb_out[10]));
inv_sbox s6_isb11 (.in_data(pipe_data[5][39:32]),   .out_data(s6_isb_out[11]));
inv_sbox s6_isb12 (.in_data(pipe_data[5][31:24]),   .out_data(s6_isb_out[12]));
inv_sbox s6_isb13 (.in_data(pipe_data[5][23:16]),   .out_data(s6_isb_out[13]));
inv_sbox s6_isb14 (.in_data(pipe_data[5][15:8]),    .out_data(s6_isb_out[14]));
inv_sbox s6_isb15 (.in_data(pipe_data[5][7:0]),     .out_data(s6_isb_out[15]));

wire [127:0] s6_isr_out = inv_shift_rows_func(
    {s6_isb_out[0],s6_isb_out[1],s6_isb_out[2],s6_isb_out[3],
     s6_isb_out[4],s6_isb_out[5],s6_isb_out[6],s6_isb_out[7],
     s6_isb_out[8],s6_isb_out[9],s6_isb_out[10],s6_isb_out[11],
     s6_isb_out[12],s6_isb_out[13],s6_isb_out[14],s6_isb_out[15]}
);

wire [31:0] s6_imc_col0, s6_imc_col1, s6_imc_col2, s6_imc_col3;
inv_mix_columns s6_imc0 (.col_in(s6_isr_out[127:96]), .col_out(s6_imc_col0));
inv_mix_columns s6_imc1 (.col_in(s6_isr_out[95:64]),  .col_out(s6_imc_col1));
inv_mix_columns s6_imc2 (.col_in(s6_isr_out[63:32]),  .col_out(s6_imc_col2));
inv_mix_columns s6_imc3 (.col_in(s6_isr_out[31:0]),   .col_out(s6_imc_col3));
wire [127:0] s6_imc_out = {s6_imc_col0, s6_imc_col1, s6_imc_col2, s6_imc_col3};
wire [127:0] s6_out = s6_imc_out ^ round_keys[768 +: 128];

// Stage 7
inv_sbox s7_isb0  (.in_data(pipe_data[6][127:120]), .out_data(s7_isb_out[0]));
inv_sbox s7_isb1  (.in_data(pipe_data[6][119:112]), .out_data(s7_isb_out[1]));
inv_sbox s7_isb2  (.in_data(pipe_data[6][111:104]), .out_data(s7_isb_out[2]));
inv_sbox s7_isb3  (.in_data(pipe_data[6][103:96]),  .out_data(s7_isb_out[3]));
inv_sbox s7_isb4  (.in_data(pipe_data[6][95:88]),   .out_data(s7_isb_out[4]));
inv_sbox s7_isb5  (.in_data(pipe_data[6][87:80]),   .out_data(s7_isb_out[5]));
inv_sbox s7_isb6  (.in_data(pipe_data[6][79:72]),   .out_data(s7_isb_out[6]));
inv_sbox s7_isb7  (.in_data(pipe_data[6][71:64]),   .out_data(s7_isb_out[7]));
inv_sbox s7_isb8  (.in_data(pipe_data[6][63:56]),   .out_data(s7_isb_out[8]));
inv_sbox s7_isb9  (.in_data(pipe_data[6][55:48]),   .out_data(s7_isb_out[9]));
inv_sbox s7_isb10 (.in_data(pipe_data[6][47:40]),   .out_data(s7_isb_out[10]));
inv_sbox s7_isb11 (.in_data(pipe_data[6][39:32]),   .out_data(s7_isb_out[11]));
inv_sbox s7_isb12 (.in_data(pipe_data[6][31:24]),   .out_data(s7_isb_out[12]));
inv_sbox s7_isb13 (.in_data(pipe_data[6][23:16]),   .out_data(s7_isb_out[13]));
inv_sbox s7_isb14 (.in_data(pipe_data[6][15:8]),    .out_data(s7_isb_out[14]));
inv_sbox s7_isb15 (.in_data(pipe_data[6][7:0]),     .out_data(s7_isb_out[15]));

wire [127:0] s7_isr_out = inv_shift_rows_func(
    {s7_isb_out[0],s7_isb_out[1],s7_isb_out[2],s7_isb_out[3],
     s7_isb_out[4],s7_isb_out[5],s7_isb_out[6],s7_isb_out[7],
     s7_isb_out[8],s7_isb_out[9],s7_isb_out[10],s7_isb_out[11],
     s7_isb_out[12],s7_isb_out[13],s7_isb_out[14],s7_isb_out[15]}
);

wire [31:0] s7_imc_col0, s7_imc_col1, s7_imc_col2, s7_imc_col3;
inv_mix_columns s7_imc0 (.col_in(s7_isr_out[127:96]), .col_out(s7_imc_col0));
inv_mix_columns s7_imc1 (.col_in(s7_isr_out[95:64]),  .col_out(s7_imc_col1));
inv_mix_columns s7_imc2 (.col_in(s7_isr_out[63:32]),  .col_out(s7_imc_col2));
inv_mix_columns s7_imc3 (.col_in(s7_isr_out[31:0]),   .col_out(s7_imc_col3));
wire [127:0] s7_imc_out = {s7_imc_col0, s7_imc_col1, s7_imc_col2, s7_imc_col3};
wire [127:0] s7_out = s7_imc_out ^ round_keys[896 +: 128];

// Stage 8
inv_sbox s8_isb0  (.in_data(pipe_data[7][127:120]), .out_data(s8_isb_out[0]));
inv_sbox s8_isb1  (.in_data(pipe_data[7][119:112]), .out_data(s8_isb_out[1]));
inv_sbox s8_isb2  (.in_data(pipe_data[7][111:104]), .out_data(s8_isb_out[2]));
inv_sbox s8_isb3  (.in_data(pipe_data[7][103:96]),  .out_data(s8_isb_out[3]));
inv_sbox s8_isb4  (.in_data(pipe_data[7][95:88]),   .out_data(s8_isb_out[4]));
inv_sbox s8_isb5  (.in_data(pipe_data[7][87:80]),   .out_data(s8_isb_out[5]));
inv_sbox s8_isb6  (.in_data(pipe_data[7][79:72]),   .out_data(s8_isb_out[6]));
inv_sbox s8_isb7  (.in_data(pipe_data[7][71:64]),   .out_data(s8_isb_out[7]));
inv_sbox s8_isb8  (.in_data(pipe_data[7][63:56]),   .out_data(s8_isb_out[8]));
inv_sbox s8_isb9  (.in_data(pipe_data[7][55:48]),   .out_data(s8_isb_out[9]));
inv_sbox s8_isb10 (.in_data(pipe_data[7][47:40]),   .out_data(s8_isb_out[10]));
inv_sbox s8_isb11 (.in_data(pipe_data[7][39:32]),   .out_data(s8_isb_out[11]));
inv_sbox s8_isb12 (.in_data(pipe_data[7][31:24]),   .out_data(s8_isb_out[12]));
inv_sbox s8_isb13 (.in_data(pipe_data[7][23:16]),   .out_data(s8_isb_out[13]));
inv_sbox s8_isb14 (.in_data(pipe_data[7][15:8]),    .out_data(s8_isb_out[14]));
inv_sbox s8_isb15 (.in_data(pipe_data[7][7:0]),     .out_data(s8_isb_out[15]));

wire [127:0] s8_isr_out = inv_shift_rows_func(
    {s8_isb_out[0],s8_isb_out[1],s8_isb_out[2],s8_isb_out[3],
     s8_isb_out[4],s8_isb_out[5],s8_isb_out[6],s8_isb_out[7],
     s8_isb_out[8],s8_isb_out[9],s8_isb_out[10],s8_isb_out[11],
     s8_isb_out[12],s8_isb_out[13],s8_isb_out[14],s8_isb_out[15]}
);

wire [31:0] s8_imc_col0, s8_imc_col1, s8_imc_col2, s8_imc_col3;
inv_mix_columns s8_imc0 (.col_in(s8_isr_out[127:96]), .col_out(s8_imc_col0));
inv_mix_columns s8_imc1 (.col_in(s8_isr_out[95:64]),  .col_out(s8_imc_col1));
inv_mix_columns s8_imc2 (.col_in(s8_isr_out[63:32]),  .col_out(s8_imc_col2));
inv_mix_columns s8_imc3 (.col_in(s8_isr_out[31:0]),   .col_out(s8_imc_col3));
wire [127:0] s8_imc_out = {s8_imc_col0, s8_imc_col1, s8_imc_col2, s8_imc_col3};
wire [127:0] s8_out = s8_imc_out ^ round_keys[1024 +: 128];

// Stage 9
inv_sbox s9_isb0  (.in_data(pipe_data[8][127:120]), .out_data(s9_isb_out[0]));
inv_sbox s9_isb1  (.in_data(pipe_data[8][119:112]), .out_data(s9_isb_out[1]));
inv_sbox s9_isb2  (.in_data(pipe_data[8][111:104]), .out_data(s9_isb_out[2]));
inv_sbox s9_isb3  (.in_data(pipe_data[8][103:96]),  .out_data(s9_isb_out[3]));
inv_sbox s9_isb4  (.in_data(pipe_data[8][95:88]),   .out_data(s9_isb_out[4]));
inv_sbox s9_isb5  (.in_data(pipe_data[8][87:80]),   .out_data(s9_isb_out[5]));
inv_sbox s9_isb6  (.in_data(pipe_data[8][79:72]),   .out_data(s9_isb_out[6]));
inv_sbox s9_isb7  (.in_data(pipe_data[8][71:64]),   .out_data(s9_isb_out[7]));
inv_sbox s9_isb8  (.in_data(pipe_data[8][63:56]),   .out_data(s9_isb_out[8]));
inv_sbox s9_isb9  (.in_data(pipe_data[8][55:48]),   .out_data(s9_isb_out[9]));
inv_sbox s9_isb10 (.in_data(pipe_data[8][47:40]),   .out_data(s9_isb_out[10]));
inv_sbox s9_isb11 (.in_data(pipe_data[8][39:32]),   .out_data(s9_isb_out[11]));
inv_sbox s9_isb12 (.in_data(pipe_data[8][31:24]),   .out_data(s9_isb_out[12]));
inv_sbox s9_isb13 (.in_data(pipe_data[8][23:16]),   .out_data(s9_isb_out[13]));
inv_sbox s9_isb14 (.in_data(pipe_data[8][15:8]),    .out_data(s9_isb_out[14]));
inv_sbox s9_isb15 (.in_data(pipe_data[8][7:0]),     .out_data(s9_isb_out[15]));

wire [127:0] s9_isr_out = inv_shift_rows_func(
    {s9_isb_out[0],s9_isb_out[1],s9_isb_out[2],s9_isb_out[3],
     s9_isb_out[4],s9_isb_out[5],s9_isb_out[6],s9_isb_out[7],
     s9_isb_out[8],s9_isb_out[9],s9_isb_out[10],s9_isb_out[11],
     s9_isb_out[12],s9_isb_out[13],s9_isb_out[14],s9_isb_out[15]}
);

wire [31:0] s9_imc_col0, s9_imc_col1, s9_imc_col2, s9_imc_col3;
inv_mix_columns s9_imc0 (.col_in(s9_isr_out[127:96]), .col_out(s9_imc_col0));
inv_mix_columns s9_imc1 (.col_in(s9_isr_out[95:64]),  .col_out(s9_imc_col1));
inv_mix_columns s9_imc2 (.col_in(s9_isr_out[63:32]),  .col_out(s9_imc_col2));
inv_mix_columns s9_imc3 (.col_in(s9_isr_out[31:0]),   .col_out(s9_imc_col3));
wire [127:0] s9_imc_out = {s9_imc_col0, s9_imc_col1, s9_imc_col2, s9_imc_col3};
wire [127:0] s9_out = s9_imc_out ^ round_keys[1152 +: 128];

// ============================================================================
// Final round (Stage 10) - no InvMixColumns
// ============================================================================
inv_sbox s10_isb0  (.in_data(pipe_data[9][127:120]), .out_data(s10_isb_out[0]));
inv_sbox s10_isb1  (.in_data(pipe_data[9][119:112]), .out_data(s10_isb_out[1]));
inv_sbox s10_isb2  (.in_data(pipe_data[9][111:104]), .out_data(s10_isb_out[2]));
inv_sbox s10_isb3  (.in_data(pipe_data[9][103:96]),  .out_data(s10_isb_out[3]));
inv_sbox s10_isb4  (.in_data(pipe_data[9][95:88]),   .out_data(s10_isb_out[4]));
inv_sbox s10_isb5  (.in_data(pipe_data[9][87:80]),   .out_data(s10_isb_out[5]));
inv_sbox s10_isb6  (.in_data(pipe_data[9][79:72]),   .out_data(s10_isb_out[6]));
inv_sbox s10_isb7  (.in_data(pipe_data[9][71:64]),   .out_data(s10_isb_out[7]));
inv_sbox s10_isb8  (.in_data(pipe_data[9][63:56]),   .out_data(s10_isb_out[8]));
inv_sbox s10_isb9  (.in_data(pipe_data[9][55:48]),   .out_data(s10_isb_out[9]));
inv_sbox s10_isb10 (.in_data(pipe_data[9][47:40]),   .out_data(s10_isb_out[10]));
inv_sbox s10_isb11 (.in_data(pipe_data[9][39:32]),   .out_data(s10_isb_out[11]));
inv_sbox s10_isb12 (.in_data(pipe_data[9][31:24]),   .out_data(s10_isb_out[12]));
inv_sbox s10_isb13 (.in_data(pipe_data[9][23:16]),   .out_data(s10_isb_out[13]));
inv_sbox s10_isb14 (.in_data(pipe_data[9][15:8]),    .out_data(s10_isb_out[14]));
inv_sbox s10_isb15 (.in_data(pipe_data[9][7:0]),     .out_data(s10_isb_out[15]));

wire [127:0] s10_isr_out = inv_shift_rows_func(
    {s10_isb_out[0],s10_isb_out[1],s10_isb_out[2],s10_isb_out[3],
     s10_isb_out[4],s10_isb_out[5],s10_isb_out[6],s10_isb_out[7],
     s10_isb_out[8],s10_isb_out[9],s10_isb_out[10],s10_isb_out[11],
     s10_isb_out[12],s10_isb_out[13],s10_isb_out[14],s10_isb_out[15]}
);

wire [127:0] s10_out = s10_isr_out ^ round_keys[1280 +: 128];  // Final key is key[0]

// ============================================================================
// Pipeline registers and output FIFO management
// ============================================================================
integer i;
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        for (i = 0; i <= 10; i = i + 1) begin
            pipe_data[i] <= 128'h0;
            pipe_valid[i] <= 1'b0;
            pipe_aux[i] <= 128'h0;
            pipe_meta[i] <= 20'h0;
        end
        for (i = 0; i < 16; i = i + 1) begin
            fifo_data[i] <= 128'h0;
            fifo_aux[i] <= 128'h0;
            fifo_meta[i] <= 20'h0;
            fifo_valid[i] <= 1'b0;
        end
        fifo_wr_ptr <= 4'h0;
        fifo_rd_ptr <= 4'h0;
        fifo_count <= 5'h0;
        data_out <= 128'h0;
        data_out_valid <= 1'b0;
        aux_out <= 128'h0;
        meta_out <= 20'h0;
    end else begin
        // Pipeline stage updates - always advance unless FIFO is full
        if (pipe_en) begin
            // Stage 0: Initial AddRoundKey with round_key_dec[0] (== encryption key[10])
            pipe_data[0] <= data_in ^ round_keys[0 +: 128];
            pipe_valid[0] <= data_in_valid;
            pipe_aux[0] <= aux_in;
            pipe_meta[0] <= meta_in;
            
            // Stages 1-10
            pipe_data[1] <= s1_out;
            pipe_valid[1] <= pipe_valid[0];
            pipe_aux[1] <= pipe_aux[0];
            pipe_meta[1] <= pipe_meta[0];
            
            pipe_data[2] <= s2_out;
            pipe_valid[2] <= pipe_valid[1];
            pipe_aux[2] <= pipe_aux[1];
            pipe_meta[2] <= pipe_meta[1];
            
            pipe_data[3] <= s3_out;
            pipe_valid[3] <= pipe_valid[2];
            pipe_aux[3] <= pipe_aux[2];
            pipe_meta[3] <= pipe_meta[2];
            
            pipe_data[4] <= s4_out;
            pipe_valid[4] <= pipe_valid[3];
            pipe_aux[4] <= pipe_aux[3];
            pipe_meta[4] <= pipe_meta[3];
            
            pipe_data[5] <= s5_out;
            pipe_valid[5] <= pipe_valid[4];
            pipe_aux[5] <= pipe_aux[4];
            pipe_meta[5] <= pipe_meta[4];
            
            pipe_data[6] <= s6_out;
            pipe_valid[6] <= pipe_valid[5];
            pipe_aux[6] <= pipe_aux[5];
            pipe_meta[6] <= pipe_meta[5];
            
            pipe_data[7] <= s7_out;
            pipe_valid[7] <= pipe_valid[6];
            pipe_aux[7] <= pipe_aux[6];
            pipe_meta[7] <= pipe_meta[6];
            
            pipe_data[8] <= s8_out;
            pipe_valid[8] <= pipe_valid[7];
            pipe_aux[8] <= pipe_aux[7];
            pipe_meta[8] <= pipe_meta[7];
            
            pipe_data[9] <= s9_out;
            pipe_valid[9] <= pipe_valid[8];
            pipe_aux[9] <= pipe_aux[8];
            pipe_meta[9] <= pipe_meta[8];
            
            pipe_data[10] <= s10_out;
            pipe_valid[10] <= pipe_valid[9];
            pipe_aux[10] <= pipe_aux[9];
            pipe_meta[10] <= pipe_meta[9];
        end else begin
            // Pipeline stalled, but clear pipe_valid[10] after writing to FIFO
            if (fifo_wr_en) begin
                pipe_valid[10] <= 1'b0;
            end
        end
        
        // FIFO write: pipeline output to FIFO
        if (fifo_wr_en) begin
            fifo_data[fifo_wr_ptr] <= pipe_data[10];
            fifo_aux[fifo_wr_ptr] <= pipe_aux[10];
            fifo_meta[fifo_wr_ptr] <= pipe_meta[10];
            fifo_valid[fifo_wr_ptr] <= 1'b1;
            fifo_wr_ptr <= fifo_wr_ptr + 1'b1;
        end
        
        // FIFO read: output to external interface
        // Always present data from FIFO head when not empty
        if (!fifo_empty) begin
            data_out <= fifo_data[fifo_rd_ptr];
            aux_out <= fifo_aux[fifo_rd_ptr];
            meta_out <= fifo_meta[fifo_rd_ptr];
            data_out_valid <= 1'b1;
        end else begin
            data_out_valid <= 1'b0;
        end
        
        // Advance read pointer when consumer accepts data
        if (fifo_rd_en) begin
            fifo_valid[fifo_rd_ptr] <= 1'b0;
            fifo_rd_ptr <= fifo_rd_ptr + 1'b1;
        end
        
        // FIFO count management
        if (fifo_wr_en && !fifo_rd_en) begin
            fifo_count <= fifo_count + 1'b1;
        end else if (!fifo_wr_en && fifo_rd_en) begin
            fifo_count <= fifo_count - 1'b1;
        end
    end
end

endmodule
