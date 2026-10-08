// =============================================================================
// AES-128 AddRoundKey Module
// Performs XOR between state and round key (128-bit)
// =============================================================================

module add_round_key (
    input  wire [127:0] state,
    input  wire [127:0] round_key,
    output wire [127:0] result
);

assign result = state ^ round_key;

endmodule
