// =============================================================================
// AES Inverse MixColumns Transformation
// Operates on the State column-by-column (4 bytes at a time)
// Implements inverse matrix multiplication in GF(2^8):
//   [0E 0B 0D 09]   [s0]
//   [09 0E 0B 0D] * [s1]
//   [0D 09 0E 0B]   [s2]
//   [0B 0D 09 0E]   [s3]
// Based on FIPS-197 Section 5.3.3
// =============================================================================

module inv_mix_columns (
    input  wire [31:0]  col_in,   // 4 bytes: col_in[31:24]=s0, col_in[23:16]=s1, col_in[15:8]=s2, col_in[7:0]=s3
    output wire [31:0]  col_out
);

// Split input into bytes
wire [7:0] s0, s1, s2, s3;
assign s0 = col_in[31:24];
assign s1 = col_in[23:16];
assign s2 = col_in[15:8];
assign s3 = col_in[7:0];

// GF(2^8) multiplication results for InvMixColumns matrix coefficients
wire [7:0] mult_0e_s0, mult_0b_s0, mult_0d_s0, mult_09_s0;
wire [7:0] mult_09_s1, mult_0e_s1, mult_0b_s1, mult_0d_s1;
wire [7:0] mult_0d_s2, mult_09_s2, mult_0e_s2, mult_0b_s2;
wire [7:0] mult_0b_s3, mult_0d_s3, mult_09_s3, mult_0e_s3;

// Multiply s0 by coefficients
gf_mult imc_0e_0 (.a(8'h0E), .b(s0), .result(mult_0e_s0));
gf_mult imc_0b_0 (.a(8'h0B), .b(s0), .result(mult_0b_s0));
gf_mult imc_0d_0 (.a(8'h0D), .b(s0), .result(mult_0d_s0));
gf_mult imc_09_0 (.a(8'h09), .b(s0), .result(mult_09_s0));

// Multiply s1 by coefficients
gf_mult imc_09_1 (.a(8'h09), .b(s1), .result(mult_09_s1));
gf_mult imc_0e_1 (.a(8'h0E), .b(s1), .result(mult_0e_s1));
gf_mult imc_0b_1 (.a(8'h0B), .b(s1), .result(mult_0b_s1));
gf_mult imc_0d_1 (.a(8'h0D), .b(s1), .result(mult_0d_s1));

// Multiply s2 by coefficients
gf_mult imc_0d_2 (.a(8'h0D), .b(s2), .result(mult_0d_s2));
gf_mult imc_09_2 (.a(8'h09), .b(s2), .result(mult_09_s2));
gf_mult imc_0e_2 (.a(8'h0E), .b(s2), .result(mult_0e_s2));
gf_mult imc_0b_2 (.a(8'h0B), .b(s2), .result(mult_0b_s2));

// Multiply s3 by coefficients
gf_mult imc_0b_3 (.a(8'h0B), .b(s3), .result(mult_0b_s3));
gf_mult imc_0d_3 (.a(8'h0D), .b(s3), .result(mult_0d_s3));
gf_mult imc_09_3 (.a(8'h09), .b(s3), .result(mult_09_s3));
gf_mult imc_0e_3 (.a(8'h0E), .b(s3), .result(mult_0e_s3));

// Compute inverse mix columns
// d0 = 0E*s0 XOR 0B*s1 XOR 0D*s2 XOR 09*s3
assign col_out[31:24] = mult_0e_s0 ^ mult_0b_s1 ^ mult_0d_s2 ^ mult_09_s3;
// d1 = 09*s0 XOR 0E*s1 XOR 0B*s2 XOR 0D*s3
assign col_out[23:16] = mult_09_s0 ^ mult_0e_s1 ^ mult_0b_s2 ^ mult_0d_s3;
// d2 = 0D*s0 XOR 09*s1 XOR 0E*s2 XOR 0B*s3
assign col_out[15:8]  = mult_0d_s0 ^ mult_09_s1 ^ mult_0e_s2 ^ mult_0b_s3;
// d3 = 0B*s0 XOR 0D*s1 XOR 09*s2 XOR 0E*s3
assign col_out[7:0]   = mult_0b_s0 ^ mult_0d_s1 ^ mult_09_s2 ^ mult_0e_s3;

endmodule
