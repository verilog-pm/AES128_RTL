// =============================================================================
// AES Inverse MixColumns Transformation
// Operates on the State column-by-column (4 bytes at a time)
// Implements inverse matrix multiplication in GF(2^8):
//   [0E 0B 0D 09]   [s0]
//   [09 0E 0B 0D] * [s1]
//   [0D 09 0E 0B]   [s2]
//   [0B 0D 09 0E]   [s3]
// Based on FIPS-197 Section 5.3.3
//
// Each byte builds x2/x4/x8 with three xtime steps, then:
//   09 = x8 ^ s, 0B = x8 ^ x2 ^ s, 0D = x8 ^ x4 ^ s, 0E = x8 ^ x4 ^ x2.
// =============================================================================

module inv_mix_columns (
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
wire [7:0] x4_0 = xtime(x2_0);
wire [7:0] x8_0 = xtime(x4_0);
wire [7:0] m09_0 = x8_0 ^ s0;
wire [7:0] m0b_0 = x8_0 ^ x2_0 ^ s0;
wire [7:0] m0d_0 = x8_0 ^ x4_0 ^ s0;
wire [7:0] m0e_0 = x8_0 ^ x4_0 ^ x2_0;

wire [7:0] x2_1 = xtime(s1);
wire [7:0] x4_1 = xtime(x2_1);
wire [7:0] x8_1 = xtime(x4_1);
wire [7:0] m09_1 = x8_1 ^ s1;
wire [7:0] m0b_1 = x8_1 ^ x2_1 ^ s1;
wire [7:0] m0d_1 = x8_1 ^ x4_1 ^ s1;
wire [7:0] m0e_1 = x8_1 ^ x4_1 ^ x2_1;

wire [7:0] x2_2 = xtime(s2);
wire [7:0] x4_2 = xtime(x2_2);
wire [7:0] x8_2 = xtime(x4_2);
wire [7:0] m09_2 = x8_2 ^ s2;
wire [7:0] m0b_2 = x8_2 ^ x2_2 ^ s2;
wire [7:0] m0d_2 = x8_2 ^ x4_2 ^ s2;
wire [7:0] m0e_2 = x8_2 ^ x4_2 ^ x2_2;

wire [7:0] x2_3 = xtime(s3);
wire [7:0] x4_3 = xtime(x2_3);
wire [7:0] x8_3 = xtime(x4_3);
wire [7:0] m09_3 = x8_3 ^ s3;
wire [7:0] m0b_3 = x8_3 ^ x2_3 ^ s3;
wire [7:0] m0d_3 = x8_3 ^ x4_3 ^ s3;
wire [7:0] m0e_3 = x8_3 ^ x4_3 ^ x2_3;

// d0 = 0E*s0 XOR 0B*s1 XOR 0D*s2 XOR 09*s3
assign col_out[31:24] = m0e_0 ^ m0b_1 ^ m0d_2 ^ m09_3;
// d1 = 09*s0 XOR 0E*s1 XOR 0B*s2 XOR 0D*s3
assign col_out[23:16] = m09_0 ^ m0e_1 ^ m0b_2 ^ m0d_3;
// d2 = 0D*s0 XOR 09*s1 XOR 0E*s2 XOR 0B*s3
assign col_out[15:8]  = m0d_0 ^ m09_1 ^ m0e_2 ^ m0b_3;
// d3 = 0B*s0 XOR 0D*s1 XOR 09*s2 XOR 0E*s3
assign col_out[7:0]   = m0b_0 ^ m0d_1 ^ m09_2 ^ m0e_3;

endmodule
