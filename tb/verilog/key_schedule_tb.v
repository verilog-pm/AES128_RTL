// =============================================================================
// Testbench for Key Schedule Module
// Uses FIPS-197 Appendix A test vector:
// Key: 2b7e1516 28aed2a6 abf71588 09cf4f3c
// Round keys should match FIPS-197 specification
// =============================================================================

`timescale 1ns / 1ps

module key_schedule_tb;

// =============================================================================
// Key Schedule instance
// =============================================================================
reg         tb_clk;
reg         tb_rst_n;
reg  [127:0] tb_key;
reg         tb_key_valid;
wire        tb_key_ready;
wire [10:0][127:0] tb_round_key_enc;
wire [10:0][127:0] tb_round_key_dec;

// Clock generation
initial begin
    tb_clk = 0;
    forever #5 tb_clk = ~tb_clk;  // 100MHz clock
end

key_schedule ks_inst (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .key_ready(tb_key_ready),
    .round_key_enc(tb_round_key_enc),
    .round_key_dec(tb_round_key_dec)
);

// =============================================================================
// Test Variables
// =============================================================================
reg [127:0] expected_enc_key0;
reg [127:0] expected_enc_key1;
integer test_count;
integer pass_count;
integer i;

// Expected round keys from FIPS-197
// These are the correct round keys for key = 2b7e1516 28aed2a6 abf71588 09cf4f3c
initial begin
    // Round key 0 (from original key)
    expected_enc_key0 = 128'h2b7e1516_28aed2a6_abf71588_09cf4f3c;
end

initial begin
    $display("========================================");
    $display("  AES-128 Key Schedule Testbench");
    $display("========================================");
    test_count = 0;
    pass_count = 0;
    
    // Initialize signals
    tb_rst_n = 0;
    tb_key = 128'h0;
    tb_key_valid = 0;
    
    #20;
    tb_rst_n = 1;
    #10;
    
    // =================================================================
    // Test 1: FIPS-197 Standard Test Vector
    // Key: 2b7e1516 28aed2a6 abf71588 09cf4f3c
    // =================================================================
    $display("\n--- Test 1: FIPS-197 Standard Test Vector ---");
    
    @(posedge tb_clk);
    tb_key <= 128'h2b7e1516_28aed2a6_abf71588_09cf4f3c;
    tb_key_valid <= 1;
    @(posedge tb_clk);
    tb_key_valid <= 0;
    
    // Wait for key_ready
    @(posedge tb_key_ready);
    #1;
    
    // Check encryption key[0] matches input
    test_count = test_count + 1;
    if (tb_round_key_enc[0] === 128'h2b7e1516_28aed2a6_abf71588_09cf4f3c) begin
        $display("  PASS: round_key_enc[0] matches input key");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: round_key_enc[0] mismatch");
        $display("    Expected: 0x%032x", 128'h2b7e1516_28aed2a6_abf71588_09cf4f3c);
        $display("    Got:      0x%032x", tb_round_key_enc[0]);
    end
    
    // Display all encryption round keys
    $display("\n  Encryption Round Keys:");
    for (i = 0; i < 11; i = i + 1) begin
        $display("    Key[%2d]: 0x%032x", i, tb_round_key_enc[i]);
    end
    
    // Display all decryption round keys
    $display("\n  Decryption Round Keys:");
    for (i = 0; i < 11; i = i + 1) begin
        $display("    Key[%2d]: 0x%032x", i, tb_round_key_dec[i]);
    end
    
    // =================================================================
    // Test 2: Decryption Key Properties
    // =================================================================
    $display("\n--- Test 2: Decryption Key Properties ---");
    
    // Check that dec_key[10] == enc_key[0]
    test_count = test_count + 1;
    if (tb_round_key_dec[10] === tb_round_key_enc[0]) begin
        $display("  PASS: dec_key[10] == enc_key[0]");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: dec_key[10] != enc_key[0]");
    end
    
    // Check that dec_key[0] == enc_key[10]
    test_count = test_count + 1;
    if (tb_round_key_dec[0] === tb_round_key_enc[10]) begin
        $display("  PASS: dec_key[0] == enc_key[10]");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: dec_key[0] != enc_key[10]");
    end
    
    // Check encryption round key[1] against FIPS-197 Appendix A
    test_count = test_count + 1;
    if (tb_round_key_enc[1] === 128'ha0fafe17_88542cb1_23a33939_2a6c7605) begin
        $display("  PASS: round_key_enc[1] matches FIPS-197");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: round_key_enc[1] mismatch");
        $display("    Expected: 0x%032x", 128'ha0fafe17_88542cb1_23a33939_2a6c7605);
        $display("    Got:      0x%032x", tb_round_key_enc[1]);
    end
    
    // Check encryption round key[10] against FIPS-197 Appendix A
    test_count = test_count + 1;
    if (tb_round_key_enc[10] === 128'hd014f9a8_c9ee2589_e13f0cc8_b6630ca6) begin
        $display("  PASS: round_key_enc[10] matches FIPS-197");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: round_key_enc[10] mismatch");
        $display("    Expected: 0x%032x", 128'hd014f9a8_c9ee2589_e13f0cc8_b6630ca6);
        $display("    Got:      0x%032x", tb_round_key_enc[10]);
    end
    
    // =================================================================
    // Test 3: Key Schedule Re-computation
    // =================================================================
    $display("\n--- Test 3: Key Re-computation ---");
    
    @(posedge tb_clk);
    tb_key <= 128'h00000000_00000000_00000000_00000000;
    tb_key_valid <= 1;
    @(posedge tb_clk);
    tb_key_valid <= 0;
    
    // Wait for key_ready
    @(posedge tb_key_ready);
    #1;
    
    test_count = test_count + 1;
    if (tb_round_key_enc[0] === 128'h00000000_00000000_00000000_00000000) begin
        $display("  PASS: Zero key expansion works");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: Zero key expansion failed");
    end
    
    // Note: an all-zero key does NOT produce all-zero round keys, because
    // the Rcon constants are XORed in starting at round 1. Instead, verify
    // internal consistency: dec_key[10] must equal enc_key[0] (both zero).
    test_count = test_count + 1;
    if (tb_round_key_dec[10] === 128'h00000000_00000000_00000000_00000000) begin
        $display("  PASS: Zero key dec_key[10] == enc_key[0] == 0");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: Zero key dec_key[10] mismatch");
    end
    
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
    
    #100;
    $finish;
end

// =============================================================================
// Timeout watchdog
// =============================================================================
initial begin
    #10000;
    $display("\nERROR: Simulation timeout!");
    $finish;
end

endmodule
