// =============================================================================
// AES-128 Encryption Pipeline (Structural)
// 10-stage pipelined architecture
// Each stage performs one AES round
// Stage 0: AddRoundKey(key[0])
// Stages 1-9: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey(key[n])
// Stage 10: SubBytes -> ShiftRows -> AddRoundKey(key[10]) (no MixColumns)
// Based on FIPS-197 Section 5.1
// =============================================================================

module aes128_pipeline_enc (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [127:0] data_in,
    input  wire         data_in_valid,
    output wire         data_in_ready,
    input  wire [127:0] aux_in,       // side-channel value carried through the
                                       // pipeline/FIFO in lockstep with data_in,
                                       // used by CTR mode to delay the original
                                       // plaintext/ciphertext block until the
                                       // matching keystream block is produced.
                                       // Unused (tie to 0) for ECB/CBC-encrypt.
    input  wire [19:0]  meta_in,      // {packet_last, beat_count[2:0], byte_keep[15:0]}
    input  wire [1407:0] round_keys,  // 11 * 128 = 1408 bits for encryption round keys
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
// Internal delay registers
// ============================================================================
// (Removed unused data_in_d and data_in_valid_d registers)

// ============================================================================
// Stage 0: Initial AddRoundKey
// ============================================================================
reg [127:0] stage0_result;
always @(*) begin
    stage0_result = data_in ^ round_keys[0 +: 128];
end

// ============================================================================
// S-box instances for each stage
// ============================================================================
wire [7:0] s1_sb_out [0:15];
wire [7:0] s2_sb_out [0:15];
wire [7:0] s3_sb_out [0:15];
wire [7:0] s4_sb_out [0:15];
wire [7:0] s5_sb_out [0:15];
wire [7:0] s6_sb_out [0:15];
wire [7:0] s7_sb_out [0:15];
wire [7:0] s8_sb_out [0:15];
wire [7:0] s9_sb_out [0:15];
wire [7:0] s10_sb_out [0:15];

// Stage 1 S-boxes
sbox s1_sb0  (.in_data(pipe_data[0][127:120]), .out_data(s1_sb_out[0]));
sbox s1_sb1  (.in_data(pipe_data[0][119:112]), .out_data(s1_sb_out[1]));
sbox s1_sb2  (.in_data(pipe_data[0][111:104]), .out_data(s1_sb_out[2]));
sbox s1_sb3  (.in_data(pipe_data[0][103:96]),  .out_data(s1_sb_out[3]));
sbox s1_sb4  (.in_data(pipe_data[0][95:88]),   .out_data(s1_sb_out[4]));
sbox s1_sb5  (.in_data(pipe_data[0][87:80]),   .out_data(s1_sb_out[5]));
sbox s1_sb6  (.in_data(pipe_data[0][79:72]),   .out_data(s1_sb_out[6]));
sbox s1_sb7  (.in_data(pipe_data[0][71:64]),   .out_data(s1_sb_out[7]));
sbox s1_sb8  (.in_data(pipe_data[0][63:56]),   .out_data(s1_sb_out[8]));
sbox s1_sb9  (.in_data(pipe_data[0][55:48]),   .out_data(s1_sb_out[9]));
sbox s1_sb10 (.in_data(pipe_data[0][47:40]),   .out_data(s1_sb_out[10]));
sbox s1_sb11 (.in_data(pipe_data[0][39:32]),   .out_data(s1_sb_out[11]));
sbox s1_sb12 (.in_data(pipe_data[0][31:24]),   .out_data(s1_sb_out[12]));
sbox s1_sb13 (.in_data(pipe_data[0][23:16]),   .out_data(s1_sb_out[13]));
sbox s1_sb14 (.in_data(pipe_data[0][15:8]),    .out_data(s1_sb_out[14]));
sbox s1_sb15 (.in_data(pipe_data[0][7:0]),     .out_data(s1_sb_out[15]));

// ============================================================================
// ShiftRows wiring for each stage
// ============================================================================
// ShiftRows:
// Row 0: no shift [s0,s1,s2,s3]
// Row 1: shift left by 1 [s5,s6,s7,s4]
// Row 2: shift left by 2 [s10,s11,s8,s9]
// Row 3: shift left by 3 [s15,s12,s13,s14]

// State byte s_i occupies row (i%4), column (i/4), matching the column-major
// layout used by mix_columns (column c = bytes {4c, 4c+1, 4c+2, 4c+3}).
// ShiftRows: new[row][col] = old[row][(col+row) mod 4]
function [127:0] shift_rows_func;
    input [127:0] sb_out;
    reg [7:0] s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15;
begin
    s0  = sb_out[127:120]; s1  = sb_out[119:112]; s2  = sb_out[111:104]; s3  = sb_out[103:96];
    s4  = sb_out[95:88];   s5  = sb_out[87:80];   s6  = sb_out[79:72];   s7  = sb_out[71:64];
    s8  = sb_out[63:56];   s9  = sb_out[55:48];   s10 = sb_out[47:40];   s11 = sb_out[39:32];
    s12 = sb_out[31:24];   s13 = sb_out[23:16];   s14 = sb_out[15:8];    s15 = sb_out[7:0];
    shift_rows_func = {s0,s5,s10,s15, s4,s9,s14,s3, s8,s13,s2,s7, s12,s1,s6,s11};
end
endfunction

// Stage 1 ShiftRows output
wire [127:0] s1_sr_out;
assign s1_sr_out = shift_rows_func({s1_sb_out[0],s1_sb_out[1],s1_sb_out[2],s1_sb_out[3],
                                     s1_sb_out[4],s1_sb_out[5],s1_sb_out[6],s1_sb_out[7],
                                     s1_sb_out[8],s1_sb_out[9],s1_sb_out[10],s1_sb_out[11],
                                     s1_sb_out[12],s1_sb_out[13],s1_sb_out[14],s1_sb_out[15]});

// ============================================================================
// MixColumns for Stage 1
// ============================================================================
wire [31:0] s1_mc_col0, s1_mc_col1, s1_mc_col2, s1_mc_col3;
mix_columns s1_mc0 (.col_in(s1_sr_out[127:96]), .col_out(s1_mc_col0));
mix_columns s1_mc1 (.col_in(s1_sr_out[95:64]),  .col_out(s1_mc_col1));
mix_columns s1_mc2 (.col_in(s1_sr_out[63:32]),  .col_out(s1_mc_col2));
mix_columns s1_mc3 (.col_in(s1_sr_out[31:0]),   .col_out(s1_mc_col3));

wire [127:0] s1_mc_out = {s1_mc_col0, s1_mc_col1, s1_mc_col2, s1_mc_col3};

// Stage 1 AddRoundKey
wire [127:0] s1_out = s1_mc_out ^ round_keys[128 +: 128];

// ============================================================================
// Use generate to instantiate remaining stages more efficiently
// ============================================================================

// For stages 2-9, we'll use generate loops with explicit wiring
// Due to Verilog limitations with conditional module instantiation in generate,
// we'll manually instantiate each stage

// Stage 2 S-boxes (using wire from pipe_data[1])
sbox s2_sb0  (.in_data(pipe_data[1][127:120]), .out_data(s2_sb_out[0]));
sbox s2_sb1  (.in_data(pipe_data[1][119:112]), .out_data(s2_sb_out[1]));
sbox s2_sb2  (.in_data(pipe_data[1][111:104]), .out_data(s2_sb_out[2]));
sbox s2_sb3  (.in_data(pipe_data[1][103:96]),  .out_data(s2_sb_out[3]));
sbox s2_sb4  (.in_data(pipe_data[1][95:88]),   .out_data(s2_sb_out[4]));
sbox s2_sb5  (.in_data(pipe_data[1][87:80]),   .out_data(s2_sb_out[5]));
sbox s2_sb6  (.in_data(pipe_data[1][79:72]),   .out_data(s2_sb_out[6]));
sbox s2_sb7  (.in_data(pipe_data[1][71:64]),   .out_data(s2_sb_out[7]));
sbox s2_sb8  (.in_data(pipe_data[1][63:56]),   .out_data(s2_sb_out[8]));
sbox s2_sb9  (.in_data(pipe_data[1][55:48]),   .out_data(s2_sb_out[9]));
sbox s2_sb10 (.in_data(pipe_data[1][47:40]),   .out_data(s2_sb_out[10]));
sbox s2_sb11 (.in_data(pipe_data[1][39:32]),   .out_data(s2_sb_out[11]));
sbox s2_sb12 (.in_data(pipe_data[1][31:24]),   .out_data(s2_sb_out[12]));
sbox s2_sb13 (.in_data(pipe_data[1][23:16]),   .out_data(s2_sb_out[13]));
sbox s2_sb14 (.in_data(pipe_data[1][15:8]),    .out_data(s2_sb_out[14]));
sbox s2_sb15 (.in_data(pipe_data[1][7:0]),     .out_data(s2_sb_out[15]));

wire [127:0] s2_sr_out = shift_rows_func({s2_sb_out[0],s2_sb_out[1],s2_sb_out[2],s2_sb_out[3],
                                           s2_sb_out[4],s2_sb_out[5],s2_sb_out[6],s2_sb_out[7],
                                           s2_sb_out[8],s2_sb_out[9],s2_sb_out[10],s2_sb_out[11],
                                           s2_sb_out[12],s2_sb_out[13],s2_sb_out[14],s2_sb_out[15]});

wire [31:0] s2_mc_col0, s2_mc_col1, s2_mc_col2, s2_mc_col3;
mix_columns s2_mc0 (.col_in(s2_sr_out[127:96]), .col_out(s2_mc_col0));
mix_columns s2_mc1 (.col_in(s2_sr_out[95:64]),  .col_out(s2_mc_col1));
mix_columns s2_mc2 (.col_in(s2_sr_out[63:32]),  .col_out(s2_mc_col2));
mix_columns s2_mc3 (.col_in(s2_sr_out[31:0]),   .col_out(s2_mc_col3));

wire [127:0] s2_mc_out = {s2_mc_col0, s2_mc_col1, s2_mc_col2, s2_mc_col3};
wire [127:0] s2_out = s2_mc_out ^ round_keys[256 +: 128];

// Stage 3-9 follow the same pattern
// For brevity, I'll create a more efficient version

// Due to the repetitive nature, let me use a helper module approach
// For now, complete stages 3-9 manually

// Stage 3 S-boxes
sbox s3_sb0  (.in_data(pipe_data[2][127:120]), .out_data(s3_sb_out[0]));
sbox s3_sb1  (.in_data(pipe_data[2][119:112]), .out_data(s3_sb_out[1]));
sbox s3_sb2  (.in_data(pipe_data[2][111:104]), .out_data(s3_sb_out[2]));
sbox s3_sb3  (.in_data(pipe_data[2][103:96]),  .out_data(s3_sb_out[3]));
sbox s3_sb4  (.in_data(pipe_data[2][95:88]),   .out_data(s3_sb_out[4]));
sbox s3_sb5  (.in_data(pipe_data[2][87:80]),   .out_data(s3_sb_out[5]));
sbox s3_sb6  (.in_data(pipe_data[2][79:72]),   .out_data(s3_sb_out[6]));
sbox s3_sb7  (.in_data(pipe_data[2][71:64]),   .out_data(s3_sb_out[7]));
sbox s3_sb8  (.in_data(pipe_data[2][63:56]),   .out_data(s3_sb_out[8]));
sbox s3_sb9  (.in_data(pipe_data[2][55:48]),   .out_data(s3_sb_out[9]));
sbox s3_sb10 (.in_data(pipe_data[2][47:40]),   .out_data(s3_sb_out[10]));
sbox s3_sb11 (.in_data(pipe_data[2][39:32]),   .out_data(s3_sb_out[11]));
sbox s3_sb12 (.in_data(pipe_data[2][31:24]),   .out_data(s3_sb_out[12]));
sbox s3_sb13 (.in_data(pipe_data[2][23:16]),   .out_data(s3_sb_out[13]));
sbox s3_sb14 (.in_data(pipe_data[2][15:8]),    .out_data(s3_sb_out[14]));
sbox s3_sb15 (.in_data(pipe_data[2][7:0]),     .out_data(s3_sb_out[15]));

wire [127:0] s3_sr_out = shift_rows_func({s3_sb_out[0],s3_sb_out[1],s3_sb_out[2],s3_sb_out[3],
                                           s3_sb_out[4],s3_sb_out[5],s3_sb_out[6],s3_sb_out[7],
                                           s3_sb_out[8],s3_sb_out[9],s3_sb_out[10],s3_sb_out[11],
                                           s3_sb_out[12],s3_sb_out[13],s3_sb_out[14],s3_sb_out[15]});

wire [31:0] s3_mc_col0, s3_mc_col1, s3_mc_col2, s3_mc_col3;
mix_columns s3_mc0 (.col_in(s3_sr_out[127:96]), .col_out(s3_mc_col0));
mix_columns s3_mc1 (.col_in(s3_sr_out[95:64]),  .col_out(s3_mc_col1));
mix_columns s3_mc2 (.col_in(s3_sr_out[63:32]),  .col_out(s3_mc_col2));
mix_columns s3_mc3 (.col_in(s3_sr_out[31:0]),   .col_out(s3_mc_col3));

wire [127:0] s3_mc_out = {s3_mc_col0, s3_mc_col1, s3_mc_col2, s3_mc_col3};
wire [127:0] s3_out = s3_mc_out ^ round_keys[384 +: 128];

// Stage 4
sbox s4_sb0  (.in_data(pipe_data[3][127:120]), .out_data(s4_sb_out[0]));
sbox s4_sb1  (.in_data(pipe_data[3][119:112]), .out_data(s4_sb_out[1]));
sbox s4_sb2  (.in_data(pipe_data[3][111:104]), .out_data(s4_sb_out[2]));
sbox s4_sb3  (.in_data(pipe_data[3][103:96]),  .out_data(s4_sb_out[3]));
sbox s4_sb4  (.in_data(pipe_data[3][95:88]),   .out_data(s4_sb_out[4]));
sbox s4_sb5  (.in_data(pipe_data[3][87:80]),   .out_data(s4_sb_out[5]));
sbox s4_sb6  (.in_data(pipe_data[3][79:72]),   .out_data(s4_sb_out[6]));
sbox s4_sb7  (.in_data(pipe_data[3][71:64]),   .out_data(s4_sb_out[7]));
sbox s4_sb8  (.in_data(pipe_data[3][63:56]),   .out_data(s4_sb_out[8]));
sbox s4_sb9  (.in_data(pipe_data[3][55:48]),   .out_data(s4_sb_out[9]));
sbox s4_sb10 (.in_data(pipe_data[3][47:40]),   .out_data(s4_sb_out[10]));
sbox s4_sb11 (.in_data(pipe_data[3][39:32]),   .out_data(s4_sb_out[11]));
sbox s4_sb12 (.in_data(pipe_data[3][31:24]),   .out_data(s4_sb_out[12]));
sbox s4_sb13 (.in_data(pipe_data[3][23:16]),   .out_data(s4_sb_out[13]));
sbox s4_sb14 (.in_data(pipe_data[3][15:8]),    .out_data(s4_sb_out[14]));
sbox s4_sb15 (.in_data(pipe_data[3][7:0]),     .out_data(s4_sb_out[15]));

wire [127:0] s4_sr_out = shift_rows_func({s4_sb_out[0],s4_sb_out[1],s4_sb_out[2],s4_sb_out[3],
                                           s4_sb_out[4],s4_sb_out[5],s4_sb_out[6],s4_sb_out[7],
                                           s4_sb_out[8],s4_sb_out[9],s4_sb_out[10],s4_sb_out[11],
                                           s4_sb_out[12],s4_sb_out[13],s4_sb_out[14],s4_sb_out[15]});

wire [31:0] s4_mc_col0, s4_mc_col1, s4_mc_col2, s4_mc_col3;
mix_columns s4_mc0 (.col_in(s4_sr_out[127:96]), .col_out(s4_mc_col0));
mix_columns s4_mc1 (.col_in(s4_sr_out[95:64]),  .col_out(s4_mc_col1));
mix_columns s4_mc2 (.col_in(s4_sr_out[63:32]),  .col_out(s4_mc_col2));
mix_columns s4_mc3 (.col_in(s4_sr_out[31:0]),   .col_out(s4_mc_col3));

wire [127:0] s4_mc_out = {s4_mc_col0, s4_mc_col1, s4_mc_col2, s4_mc_col3};
wire [127:0] s4_out = s4_mc_out ^ round_keys[512 +: 128];

// Stage 5
sbox s5_sb0  (.in_data(pipe_data[4][127:120]), .out_data(s5_sb_out[0]));
sbox s5_sb1  (.in_data(pipe_data[4][119:112]), .out_data(s5_sb_out[1]));
sbox s5_sb2  (.in_data(pipe_data[4][111:104]), .out_data(s5_sb_out[2]));
sbox s5_sb3  (.in_data(pipe_data[4][103:96]),  .out_data(s5_sb_out[3]));
sbox s5_sb4  (.in_data(pipe_data[4][95:88]),   .out_data(s5_sb_out[4]));
sbox s5_sb5  (.in_data(pipe_data[4][87:80]),   .out_data(s5_sb_out[5]));
sbox s5_sb6  (.in_data(pipe_data[4][79:72]),   .out_data(s5_sb_out[6]));
sbox s5_sb7  (.in_data(pipe_data[4][71:64]),   .out_data(s5_sb_out[7]));
sbox s5_sb8  (.in_data(pipe_data[4][63:56]),   .out_data(s5_sb_out[8]));
sbox s5_sb9  (.in_data(pipe_data[4][55:48]),   .out_data(s5_sb_out[9]));
sbox s5_sb10 (.in_data(pipe_data[4][47:40]),   .out_data(s5_sb_out[10]));
sbox s5_sb11 (.in_data(pipe_data[4][39:32]),   .out_data(s5_sb_out[11]));
sbox s5_sb12 (.in_data(pipe_data[4][31:24]),   .out_data(s5_sb_out[12]));
sbox s5_sb13 (.in_data(pipe_data[4][23:16]),   .out_data(s5_sb_out[13]));
sbox s5_sb14 (.in_data(pipe_data[4][15:8]),    .out_data(s5_sb_out[14]));
sbox s5_sb15 (.in_data(pipe_data[4][7:0]),     .out_data(s5_sb_out[15]));

wire [127:0] s5_sr_out = shift_rows_func({s5_sb_out[0],s5_sb_out[1],s5_sb_out[2],s5_sb_out[3],
                                           s5_sb_out[4],s5_sb_out[5],s5_sb_out[6],s5_sb_out[7],
                                           s5_sb_out[8],s5_sb_out[9],s5_sb_out[10],s5_sb_out[11],
                                           s5_sb_out[12],s5_sb_out[13],s5_sb_out[14],s5_sb_out[15]});

wire [31:0] s5_mc_col0, s5_mc_col1, s5_mc_col2, s5_mc_col3;
mix_columns s5_mc0 (.col_in(s5_sr_out[127:96]), .col_out(s5_mc_col0));
mix_columns s5_mc1 (.col_in(s5_sr_out[95:64]),  .col_out(s5_mc_col1));
mix_columns s5_mc2 (.col_in(s5_sr_out[63:32]),  .col_out(s5_mc_col2));
mix_columns s5_mc3 (.col_in(s5_sr_out[31:0]),   .col_out(s5_mc_col3));

wire [127:0] s5_mc_out = {s5_mc_col0, s5_mc_col1, s5_mc_col2, s5_mc_col3};
wire [127:0] s5_out = s5_mc_out ^ round_keys[640 +: 128];

// Stage 6
sbox s6_sb0  (.in_data(pipe_data[5][127:120]), .out_data(s6_sb_out[0]));
sbox s6_sb1  (.in_data(pipe_data[5][119:112]), .out_data(s6_sb_out[1]));
sbox s6_sb2  (.in_data(pipe_data[5][111:104]), .out_data(s6_sb_out[2]));
sbox s6_sb3  (.in_data(pipe_data[5][103:96]),  .out_data(s6_sb_out[3]));
sbox s6_sb4  (.in_data(pipe_data[5][95:88]),   .out_data(s6_sb_out[4]));
sbox s6_sb5  (.in_data(pipe_data[5][87:80]),   .out_data(s6_sb_out[5]));
sbox s6_sb6  (.in_data(pipe_data[5][79:72]),   .out_data(s6_sb_out[6]));
sbox s6_sb7  (.in_data(pipe_data[5][71:64]),   .out_data(s6_sb_out[7]));
sbox s6_sb8  (.in_data(pipe_data[5][63:56]),   .out_data(s6_sb_out[8]));
sbox s6_sb9  (.in_data(pipe_data[5][55:48]),   .out_data(s6_sb_out[9]));
sbox s6_sb10 (.in_data(pipe_data[5][47:40]),   .out_data(s6_sb_out[10]));
sbox s6_sb11 (.in_data(pipe_data[5][39:32]),   .out_data(s6_sb_out[11]));
sbox s6_sb12 (.in_data(pipe_data[5][31:24]),   .out_data(s6_sb_out[12]));
sbox s6_sb13 (.in_data(pipe_data[5][23:16]),   .out_data(s6_sb_out[13]));
sbox s6_sb14 (.in_data(pipe_data[5][15:8]),    .out_data(s6_sb_out[14]));
sbox s6_sb15 (.in_data(pipe_data[5][7:0]),     .out_data(s6_sb_out[15]));

wire [127:0] s6_sr_out = shift_rows_func({s6_sb_out[0],s6_sb_out[1],s6_sb_out[2],s6_sb_out[3],
                                           s6_sb_out[4],s6_sb_out[5],s6_sb_out[6],s6_sb_out[7],
                                           s6_sb_out[8],s6_sb_out[9],s6_sb_out[10],s6_sb_out[11],
                                           s6_sb_out[12],s6_sb_out[13],s6_sb_out[14],s6_sb_out[15]});

wire [31:0] s6_mc_col0, s6_mc_col1, s6_mc_col2, s6_mc_col3;
mix_columns s6_mc0 (.col_in(s6_sr_out[127:96]), .col_out(s6_mc_col0));
mix_columns s6_mc1 (.col_in(s6_sr_out[95:64]),  .col_out(s6_mc_col1));
mix_columns s6_mc2 (.col_in(s6_sr_out[63:32]),  .col_out(s6_mc_col2));
mix_columns s6_mc3 (.col_in(s6_sr_out[31:0]),   .col_out(s6_mc_col3));

wire [127:0] s6_mc_out = {s6_mc_col0, s6_mc_col1, s6_mc_col2, s6_mc_col3};
wire [127:0] s6_out = s6_mc_out ^ round_keys[768 +: 128];

// Stage 7
sbox s7_sb0  (.in_data(pipe_data[6][127:120]), .out_data(s7_sb_out[0]));
sbox s7_sb1  (.in_data(pipe_data[6][119:112]), .out_data(s7_sb_out[1]));
sbox s7_sb2  (.in_data(pipe_data[6][111:104]), .out_data(s7_sb_out[2]));
sbox s7_sb3  (.in_data(pipe_data[6][103:96]),  .out_data(s7_sb_out[3]));
sbox s7_sb4  (.in_data(pipe_data[6][95:88]),   .out_data(s7_sb_out[4]));
sbox s7_sb5  (.in_data(pipe_data[6][87:80]),   .out_data(s7_sb_out[5]));
sbox s7_sb6  (.in_data(pipe_data[6][79:72]),   .out_data(s7_sb_out[6]));
sbox s7_sb7  (.in_data(pipe_data[6][71:64]),   .out_data(s7_sb_out[7]));
sbox s7_sb8  (.in_data(pipe_data[6][63:56]),   .out_data(s7_sb_out[8]));
sbox s7_sb9  (.in_data(pipe_data[6][55:48]),   .out_data(s7_sb_out[9]));
sbox s7_sb10 (.in_data(pipe_data[6][47:40]),   .out_data(s7_sb_out[10]));
sbox s7_sb11 (.in_data(pipe_data[6][39:32]),   .out_data(s7_sb_out[11]));
sbox s7_sb12 (.in_data(pipe_data[6][31:24]),   .out_data(s7_sb_out[12]));
sbox s7_sb13 (.in_data(pipe_data[6][23:16]),   .out_data(s7_sb_out[13]));
sbox s7_sb14 (.in_data(pipe_data[6][15:8]),    .out_data(s7_sb_out[14]));
sbox s7_sb15 (.in_data(pipe_data[6][7:0]),     .out_data(s7_sb_out[15]));

wire [127:0] s7_sr_out = shift_rows_func({s7_sb_out[0],s7_sb_out[1],s7_sb_out[2],s7_sb_out[3],
                                           s7_sb_out[4],s7_sb_out[5],s7_sb_out[6],s7_sb_out[7],
                                           s7_sb_out[8],s7_sb_out[9],s7_sb_out[10],s7_sb_out[11],
                                           s7_sb_out[12],s7_sb_out[13],s7_sb_out[14],s7_sb_out[15]});

wire [31:0] s7_mc_col0, s7_mc_col1, s7_mc_col2, s7_mc_col3;
mix_columns s7_mc0 (.col_in(s7_sr_out[127:96]), .col_out(s7_mc_col0));
mix_columns s7_mc1 (.col_in(s7_sr_out[95:64]),  .col_out(s7_mc_col1));
mix_columns s7_mc2 (.col_in(s7_sr_out[63:32]),  .col_out(s7_mc_col2));
mix_columns s7_mc3 (.col_in(s7_sr_out[31:0]),   .col_out(s7_mc_col3));

wire [127:0] s7_mc_out = {s7_mc_col0, s7_mc_col1, s7_mc_col2, s7_mc_col3};
wire [127:0] s7_out = s7_mc_out ^ round_keys[896 +: 128];

// Stage 8
sbox s8_sb0  (.in_data(pipe_data[7][127:120]), .out_data(s8_sb_out[0]));
sbox s8_sb1  (.in_data(pipe_data[7][119:112]), .out_data(s8_sb_out[1]));
sbox s8_sb2  (.in_data(pipe_data[7][111:104]), .out_data(s8_sb_out[2]));
sbox s8_sb3  (.in_data(pipe_data[7][103:96]),  .out_data(s8_sb_out[3]));
sbox s8_sb4  (.in_data(pipe_data[7][95:88]),   .out_data(s8_sb_out[4]));
sbox s8_sb5  (.in_data(pipe_data[7][87:80]),   .out_data(s8_sb_out[5]));
sbox s8_sb6  (.in_data(pipe_data[7][79:72]),   .out_data(s8_sb_out[6]));
sbox s8_sb7  (.in_data(pipe_data[7][71:64]),   .out_data(s8_sb_out[7]));
sbox s8_sb8  (.in_data(pipe_data[7][63:56]),   .out_data(s8_sb_out[8]));
sbox s8_sb9  (.in_data(pipe_data[7][55:48]),   .out_data(s8_sb_out[9]));
sbox s8_sb10 (.in_data(pipe_data[7][47:40]),   .out_data(s8_sb_out[10]));
sbox s8_sb11 (.in_data(pipe_data[7][39:32]),   .out_data(s8_sb_out[11]));
sbox s8_sb12 (.in_data(pipe_data[7][31:24]),   .out_data(s8_sb_out[12]));
sbox s8_sb13 (.in_data(pipe_data[7][23:16]),   .out_data(s8_sb_out[13]));
sbox s8_sb14 (.in_data(pipe_data[7][15:8]),    .out_data(s8_sb_out[14]));
sbox s8_sb15 (.in_data(pipe_data[7][7:0]),     .out_data(s8_sb_out[15]));

wire [127:0] s8_sr_out = shift_rows_func({s8_sb_out[0],s8_sb_out[1],s8_sb_out[2],s8_sb_out[3],
                                           s8_sb_out[4],s8_sb_out[5],s8_sb_out[6],s8_sb_out[7],
                                           s8_sb_out[8],s8_sb_out[9],s8_sb_out[10],s8_sb_out[11],
                                           s8_sb_out[12],s8_sb_out[13],s8_sb_out[14],s8_sb_out[15]});

wire [31:0] s8_mc_col0, s8_mc_col1, s8_mc_col2, s8_mc_col3;
mix_columns s8_mc0 (.col_in(s8_sr_out[127:96]), .col_out(s8_mc_col0));
mix_columns s8_mc1 (.col_in(s8_sr_out[95:64]),  .col_out(s8_mc_col1));
mix_columns s8_mc2 (.col_in(s8_sr_out[63:32]),  .col_out(s8_mc_col2));
mix_columns s8_mc3 (.col_in(s8_sr_out[31:0]),   .col_out(s8_mc_col3));

wire [127:0] s8_mc_out = {s8_mc_col0, s8_mc_col1, s8_mc_col2, s8_mc_col3};
wire [127:0] s8_out = s8_mc_out ^ round_keys[1024 +: 128];

// Stage 9
sbox s9_sb0  (.in_data(pipe_data[8][127:120]), .out_data(s9_sb_out[0]));
sbox s9_sb1  (.in_data(pipe_data[8][119:112]), .out_data(s9_sb_out[1]));
sbox s9_sb2  (.in_data(pipe_data[8][111:104]), .out_data(s9_sb_out[2]));
sbox s9_sb3  (.in_data(pipe_data[8][103:96]),  .out_data(s9_sb_out[3]));
sbox s9_sb4  (.in_data(pipe_data[8][95:88]),   .out_data(s9_sb_out[4]));
sbox s9_sb5  (.in_data(pipe_data[8][87:80]),   .out_data(s9_sb_out[5]));
sbox s9_sb6  (.in_data(pipe_data[8][79:72]),   .out_data(s9_sb_out[6]));
sbox s9_sb7  (.in_data(pipe_data[8][71:64]),   .out_data(s9_sb_out[7]));
sbox s9_sb8  (.in_data(pipe_data[8][63:56]),   .out_data(s9_sb_out[8]));
sbox s9_sb9  (.in_data(pipe_data[8][55:48]),   .out_data(s9_sb_out[9]));
sbox s9_sb10 (.in_data(pipe_data[8][47:40]),   .out_data(s9_sb_out[10]));
sbox s9_sb11 (.in_data(pipe_data[8][39:32]),   .out_data(s9_sb_out[11]));
sbox s9_sb12 (.in_data(pipe_data[8][31:24]),   .out_data(s9_sb_out[12]));
sbox s9_sb13 (.in_data(pipe_data[8][23:16]),   .out_data(s9_sb_out[13]));
sbox s9_sb14 (.in_data(pipe_data[8][15:8]),    .out_data(s9_sb_out[14]));
sbox s9_sb15 (.in_data(pipe_data[8][7:0]),     .out_data(s9_sb_out[15]));

wire [127:0] s9_sr_out = shift_rows_func({s9_sb_out[0],s9_sb_out[1],s9_sb_out[2],s9_sb_out[3],
                                           s9_sb_out[4],s9_sb_out[5],s9_sb_out[6],s9_sb_out[7],
                                           s9_sb_out[8],s9_sb_out[9],s9_sb_out[10],s9_sb_out[11],
                                           s9_sb_out[12],s9_sb_out[13],s9_sb_out[14],s9_sb_out[15]});

wire [31:0] s9_mc_col0, s9_mc_col1, s9_mc_col2, s9_mc_col3;
mix_columns s9_mc0 (.col_in(s9_sr_out[127:96]), .col_out(s9_mc_col0));
mix_columns s9_mc1 (.col_in(s9_sr_out[95:64]),  .col_out(s9_mc_col1));
mix_columns s9_mc2 (.col_in(s9_sr_out[63:32]),  .col_out(s9_mc_col2));
mix_columns s9_mc3 (.col_in(s9_sr_out[31:0]),   .col_out(s9_mc_col3));

wire [127:0] s9_mc_out = {s9_mc_col0, s9_mc_col1, s9_mc_col2, s9_mc_col3};
wire [127:0] s9_out = s9_mc_out ^ round_keys[1152 +: 128];

// ============================================================================
// Final round (Stage 10) - no MixColumns
// ============================================================================
sbox s10_sb0  (.in_data(pipe_data[9][127:120]), .out_data(s10_sb_out[0]));
sbox s10_sb1  (.in_data(pipe_data[9][119:112]), .out_data(s10_sb_out[1]));
sbox s10_sb2  (.in_data(pipe_data[9][111:104]), .out_data(s10_sb_out[2]));
sbox s10_sb3  (.in_data(pipe_data[9][103:96]),  .out_data(s10_sb_out[3]));
sbox s10_sb4  (.in_data(pipe_data[9][95:88]),   .out_data(s10_sb_out[4]));
sbox s10_sb5  (.in_data(pipe_data[9][87:80]),   .out_data(s10_sb_out[5]));
sbox s10_sb6  (.in_data(pipe_data[9][79:72]),   .out_data(s10_sb_out[6]));
sbox s10_sb7  (.in_data(pipe_data[9][71:64]),   .out_data(s10_sb_out[7]));
sbox s10_sb8  (.in_data(pipe_data[9][63:56]),   .out_data(s10_sb_out[8]));
sbox s10_sb9  (.in_data(pipe_data[9][55:48]),   .out_data(s10_sb_out[9]));
sbox s10_sb10 (.in_data(pipe_data[9][47:40]),   .out_data(s10_sb_out[10]));
sbox s10_sb11 (.in_data(pipe_data[9][39:32]),   .out_data(s10_sb_out[11]));
sbox s10_sb12 (.in_data(pipe_data[9][31:24]),   .out_data(s10_sb_out[12]));
sbox s10_sb13 (.in_data(pipe_data[9][23:16]),   .out_data(s10_sb_out[13]));
sbox s10_sb14 (.in_data(pipe_data[9][15:8]),    .out_data(s10_sb_out[14]));
sbox s10_sb15 (.in_data(pipe_data[9][7:0]),     .out_data(s10_sb_out[15]));

wire [127:0] s10_sr_out = shift_rows_func({s10_sb_out[0],s10_sb_out[1],s10_sb_out[2],s10_sb_out[3],
                                            s10_sb_out[4],s10_sb_out[5],s10_sb_out[6],s10_sb_out[7],
                                            s10_sb_out[8],s10_sb_out[9],s10_sb_out[10],s10_sb_out[11],
                                            s10_sb_out[12],s10_sb_out[13],s10_sb_out[14],s10_sb_out[15]});

wire [127:0] s10_out = s10_sr_out ^ round_keys[1280 +: 128];

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
            // Stage 0: Load input XOR key[0]
            pipe_data[0] <= data_in ^ round_keys[0 +: 128];
            pipe_valid[0] <= data_in_valid;
            pipe_aux[0] <= aux_in;
            pipe_meta[0] <= meta_in;
            
            // Stages 1-10: Shift through pipeline with round computations
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
