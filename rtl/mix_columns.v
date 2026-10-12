// =============================================================================
// AES MixColumns Transformation
// Operates on the State column-by-column (4 bytes at a time)
// Implements matrix multiplication in GF(2^8):
//   [2 3 1 1]   [s0]
//   [1 2 3 1] * [s1]
//   [1 1 2 3]   [s2]
//   [3 1 1 2]   [s3]
// Based on FIPS-197 Section 5.1.3
//
// Coefficients are fixed, so each byte is multiplied with xtime instead of
// the general 8-iteration gf_mult. x2 = xtime(s), x3 = x2 ^ s.
// =============================================================================

module mix_columns (
    input  wire [31:0]  col_in,   // 4 bytes: col_in[31:24]=s0, col_in[23:16]=s1, col_in[15:8]=s2, col_in[7:0]=s3
    output wire [31:0]  col_out
);

function [7:0] xtime;
    input [7:0] b;
    begin
        xtime = {b[6:0], 1'b0} ^ (8'h1b & {8{b[7]}});
    end
endfunction

wire [7:0] s0, s1, s2, s3;
assign s0 = col_in[31:24];
assign s1 = col_in[23:16];
assign s2 = col_in[15:8];
assign s3 = col_in[7:0];

wire [7:0] x2_0 = xtime(s0);
wire [7:0] x2_1 = xtime(s1);
wire [7:0] x2_2 = xtime(s2);
wire [7:0] x2_3 = xtime(s3);
wire [7:0] x3_0 = x2_0 ^ s0;
wire [7:0] x3_1 = x2_1 ^ s1;
wire [7:0] x3_2 = x2_2 ^ s2;
wire [7:0] x3_3 = x2_3 ^ s3;

// d0 = 2*s0 XOR 3*s1 XOR s2 XOR s3
// d1 = s0 XOR 2*s1 XOR 3*s2 XOR s3
// d2 = s0 XOR s1 XOR 2*s2 XOR 3*s3
// d3 = 3*s0 XOR s1 XOR s2 XOR 2*s3
assign col_out[31:24] = x2_0 ^ x3_1 ^ s2 ^ s3;
assign col_out[23:16] = s0 ^ x2_1 ^ x3_2 ^ s3;
assign col_out[15:8]  = s0 ^ s1 ^ x2_2 ^ x3_3;
assign col_out[7:0]   = x3_0 ^ s1 ^ s2 ^ x2_3;

endmodule
