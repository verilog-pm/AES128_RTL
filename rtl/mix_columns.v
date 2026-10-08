// =============================================================================
// AES MixColumns Transformation
// Operates on the State column-by-column (4 bytes at a time)
// Implements matrix multiplication in GF(2^8):
//   [2 3 1 1]   [s0]
//   [1 2 3 1] * [s1]
//   [1 1 2 3]   [s2]
//   [3 1 1 2]   [s3]
// Based on FIPS-197 Section 5.1.3
// =============================================================================

module mix_columns (
    input  wire [31:0]  col_in,   // 4 bytes: col_in[31:24]=s0, col_in[23:16]=s1, col_in[15:8]=s2, col_in[7:0]=s3
    output wire [31:0]  col_out
);

// Split input into bytes
wire [7:0] s0, s1, s2, s3;
assign s0 = col_in[31:24];
assign s1 = col_in[23:16];
assign s2 = col_in[15:8];
assign s3 = col_in[7:0];

// GF(2^8) multiplication results
wire [7:0] mult_2_s0, mult_2_s1, mult_2_s2, mult_2_s3;
wire [7:0] mult_3_s0, mult_3_s1, mult_3_s2, mult_3_s3;

// Multiply each byte by 2
gf_mult mult_2_0 (.a(8'h02), .b(s0), .result(mult_2_s0));
gf_mult mult_2_1 (.a(8'h02), .b(s1), .result(mult_2_s1));
gf_mult mult_2_2 (.a(8'h02), .b(s2), .result(mult_2_s2));
gf_mult mult_2_3 (.a(8'h02), .b(s3), .result(mult_2_s3));

// Multiply each byte by 3 (3 = 2 XOR 1)
gf_mult mult_3_0 (.a(8'h03), .b(s0), .result(mult_3_s0));
gf_mult mult_3_1 (.a(8'h03), .b(s1), .result(mult_3_s1));
gf_mult mult_3_2 (.a(8'h03), .b(s2), .result(mult_3_s2));
gf_mult mult_3_3 (.a(8'h03), .b(s3), .result(mult_3_s3));

// MixColumns matrix multiplication:
// d0 = 2*s0 XOR 3*s1 XOR s2 XOR s3
// d1 = s0 XOR 2*s1 XOR 3*s2 XOR s3
// d2 = s0 XOR s1 XOR 2*s2 XOR 3*s3
// d3 = 3*s0 XOR s1 XOR s2 XOR 2*s3
assign col_out[31:24] = mult_2_s0 ^ mult_3_s1 ^ s2 ^ s3;
assign col_out[23:16] = s0 ^ mult_2_s1 ^ mult_3_s2 ^ s3;
assign col_out[15:8]  = s0 ^ s1 ^ mult_2_s2 ^ mult_3_s3;
assign col_out[7:0]   = mult_3_s0 ^ s1 ^ s2 ^ mult_2_s3;

endmodule
