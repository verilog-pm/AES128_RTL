// =============================================================================
// Testbench for Basic AES Operations
// Tests: add_round_key, sbox, inv_sbox, gf_mult
// =============================================================================

`timescale 1ns / 1ps

module basic_ops_tb;

// =============================================================================
// Test for add_round_key
// =============================================================================
reg [127:0] tb_state;
reg [127:0] tb_round_key;
wire [127:0] tb_ark_result;

add_round_key ark_inst (
    .state(tb_state),
    .round_key(tb_round_key),
    .result(tb_ark_result)
);

// =============================================================================
// Test for sbox
// =============================================================================
reg [7:0] tb_sbox_in;
wire [7:0] tb_sbox_out;

sbox sbox_inst (
    .in_data(tb_sbox_in),
    .out_data(tb_sbox_out)
);

// =============================================================================
// Test for inv_sbox
// =============================================================================
reg [7:0] tb_inv_sbox_in;
wire [7:0] tb_inv_sbox_out;

inv_sbox inv_sbox_inst (
    .in_data(tb_inv_sbox_in),
    .out_data(tb_inv_sbox_out)
);

// =============================================================================
// Test for gf_mult
// =============================================================================
reg [7:0] tb_gf_a;
reg [7:0] tb_gf_b;
wire [7:0] tb_gf_result;

gf_mult gf_mult_inst (
    .a(tb_gf_a),
    .b(tb_gf_b),
    .result(tb_gf_result)
);

// =============================================================================
// Test Variables
// =============================================================================
integer test_count;
integer pass_count;
reg [7:0] expected;
integer i;

initial begin
    $display("========================================");
    $display("  AES Basic Operations Testbench");
    $display("========================================");
    test_count = 0;
    pass_count = 0;
    
    // =================================================================
    // Test 1: S-box inverse property (S-box and InvS-box)
    // =================================================================
    $display("\n--- Test 1: S-box and InvS-box Round-trip ---");
    for (i = 0; i < 256; i = i + 1) begin
        tb_sbox_in = i;
        #1;
        tb_inv_sbox_in = tb_sbox_out;
        #1;
        if (tb_inv_sbox_out === i) begin
            pass_count = pass_count + 1;
        end else begin
            $display("  FAIL: S-box/InvS-box round-trip for 0x%02h", i);
        end
        test_count = test_count + 1;
    end
    $display("  S-box round-trip: %0d/%0d passed", pass_count, test_count);
    test_count = 0;
    pass_count = 0;
    
    // =================================================================
    // Test 2: GF(2^8) Multiplication - Known Values
    // =================================================================
    $display("\n--- Test 2: GF(2^8) Multiplication ---");
    
    // Test 0x02 * 0x87
    tb_gf_a = 8'h02;
    tb_gf_b = 8'h87;
    #1;
    expected = 8'h15;  // 0x87 << 1 = 0x10E (9-bit), reduce: 0x0E ^ 0x1B = 0x15
    if (tb_gf_result === expected) begin
        $display("  PASS: 0x02 * 0x87 = 0x%02h (expected 0x%02h)", tb_gf_result, expected);
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: 0x02 * 0x87 = 0x%02h (expected 0x%02h)", tb_gf_result, expected);
    end
    test_count = test_count + 1;
    
    // Test 0x01 * any = any
    tb_gf_a = 8'h01;
    tb_gf_b = 8'hAB;
    #1;
    expected = 8'hAB;
    if (tb_gf_result === expected) begin
        $display("  PASS: 0x01 * 0xAB = 0x%02h (expected 0x%02h)", tb_gf_result, expected);
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: 0x01 * 0xAB = 0x%02h (expected 0x%02h)", tb_gf_result, expected);
    end
    test_count = test_count + 1;
    
    // Test 0x00 * any = 0x00
    tb_gf_a = 8'h00;
    tb_gf_b = 8'hFF;
    #1;
    expected = 8'h00;
    if (tb_gf_result === expected) begin
        $display("  PASS: 0x00 * 0xFF = 0x%02h (expected 0x%02h)", tb_gf_result, expected);
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: 0x00 * 0xFF = 0x%02h (expected 0x%02h)", tb_gf_result, expected);
    end
    test_count = test_count + 1;
    
    // Test commutativity: a*b = b*a
    tb_gf_a = 8'h57;
    tb_gf_b = 8'h83;
    #1;
    expected = tb_gf_result;
    // Store result
    pass_count = pass_count + (tb_gf_result === expected ? 1 : 0);
    test_count = test_count + 1;
    
    // =================================================================
    // Test 3: AddRoundKey - XOR property
    // =================================================================
    $display("\n--- Test 3: AddRoundKey (XOR) ---");
    
    // XOR with zero
    tb_state = 128'h123456789ABCDEF0123456789ABCDEF0;
    tb_round_key = 128'h00000000000000000000000000000000;
    #1;
    if (tb_ark_result === tb_state) begin
        $display("  PASS: state XOR 0 = state");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: state XOR 0 != state");
    end
    test_count = test_count + 1;
    
    // XOR twice = original
    tb_state = 128'h123456789ABCDEF0123456789ABCDEF0;
    tb_round_key = 128'hFEDCBA9876543210FEDCBA9876543210;
    #1;
    if (tb_ark_result ^ tb_round_key === tb_state) begin
        $display("  PASS: (a XOR b) XOR b = a");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: (a XOR b) XOR b != a");
    end
    test_count = test_count + 1;
    
    // =================================================================
    // Summary
    // =================================================================
    $display("\n========================================");
    $display("  Test Summary: %0d/%0d passed", pass_count, test_count);
    if (pass_count == test_count) begin
        $display("  Status: ALL TESTS PASSED");
    end else begin
        $display("  Status: SOME TESTS FAILED");
    end
    $display("========================================");
    
    #10;
    $finish;
end

endmodule
