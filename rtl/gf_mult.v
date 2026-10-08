// =============================================================================
// GF(2^8) Multiplication Module
// Implements multiplication in GF(2^8) with irreducible polynomial x^8 + x^4 + x^3 + x + 1
// Based on FIPS-197 Section 4.2
// Uses shift-and-reduce (Russian peasant) algorithm
// =============================================================================

module gf_mult (
    input  wire [7:0]  a,
    input  wire [7:0]  b,
    output reg  [7:0]  result
);

// GF(2^8) irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B
// Reduction constant (low 8 bits, high bit x^8 is implicit): 0x1B
localparam [7:0] GF_POLY = 8'h1B;

integer i;
reg [7:0] cur_a;
reg [7:0] acc;
reg       carry;

always @(*) begin
    cur_a = a;
    acc   = 8'h00;

    for (i = 0; i < 8; i = i + 1) begin
        if (b[i]) begin
            acc = acc ^ cur_a;
        end
        // Check MSB of current a BEFORE shifting to decide if reduction is needed
        carry = cur_a[7];
        cur_a = cur_a << 1;
        if (carry) begin
            cur_a = cur_a ^ GF_POLY;
        end
    end

    result = acc;
end

endmodule
