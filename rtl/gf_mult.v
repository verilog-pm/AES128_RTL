// =============================================================================
// GF(2^8) Multiplication Module
// Implements multiplication in GF(2^8) with irreducible polynomial
// x^8 + x^4 + x^3 + x + 1 (FIPS-197 Section 4.2).
//
// Ports stay (a, b, result) so basic_ops_tb can keep checking arbitrary
// coefficients. The AES round datapath does not instantiate this module:
// mix_columns and inv_mix_columns use a fixed-coefficient xtime network.
// =============================================================================

module gf_mult (
    input  wire [7:0]  a,
    input  wire [7:0]  b,
    output reg  [7:0]  result
);

function [7:0] xtime;
    input [7:0] v;
    begin
        xtime = {v[6:0], 1'b0} ^ (8'h1b & {8{v[7]}});
    end
endfunction

integer i;
reg [7:0] cur_a;
reg [7:0] acc;

always @(*) begin
    cur_a = a;
    acc   = 8'h00;
    for (i = 0; i < 8; i = i + 1) begin
        if (b[i])
            acc = acc ^ cur_a;
        cur_a = xtime(cur_a);
    end
    result = acc;
end

endmodule
