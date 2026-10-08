// =============================================================================
// Testbench for MixColumns and InvMixColumns
// Uses FIPS-197 Appendix C test vectors
// =============================================================================

`timescale 1ns / 1ps

module mix_columns_tb;

// =============================================================================
// MixColumns instance
// =============================================================================
reg [31:0] tb_mc_col_in;
wire [31:0] tb_mc_col_out;

mix_columns mc_inst (
    .col_in(tb_mc_col_in),
    .col_out(tb_mc_col_out)
);

// =============================================================================
// InvMixColumns instance
// =============================================================================
reg [31:0] tb_imc_col_in;
wire [31:0] tb_imc_col_out;

inv_mix_columns imc_inst (
    .col_in(tb_imc_col_in),
    .col_out(tb_imc_col_out)
);

// =============================================================================
// Test Variables
// =============================================================================
integer test_count;
integer pass_count;
reg [31:0] expected;
reg [31:0] temp_result;

initial begin
    $display("========================================");
    $display("  MixColumns Testbench");
    $display("========================================");
    test_count = 0;
    pass_count = 0;
    
    // =================================================================
    // Test: MixColumns using FIPS-197 Appendix C example
    // State before MixColumns (column 0):
    // From FIPS-197: state before MixColumns round 1
    // Input column: {d0, d1, d2, d3}
    // From test vector: state column is 87 F2 DB 30 (big-endian order)
    // In our format: col_in[31:24]=d0=87, col_in[23:16]=d1=F2,
    //                col_in[15:8]=d2=DB, col_in[7:0]=d3=30
    // Expected output: 47 40 A3 BE
    // =================================================================
    $display("\n--- Test 1: MixColumns Round-trip with InvMixColumns ---");
    
    // Test column 1 from FIPS-197 example
    // Input: 87 F2 DB 30
    tb_mc_col_in = 32'h87F2_DB30;
    #1;
    // InvMixColumns of MixColumns should give back original
    tb_imc_col_in = tb_mc_col_out;
    #1;
    if (tb_imc_col_out === 32'h87F2_DB30) begin
        $display("  PASS: Round-trip for column 0x87F2_DB30");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: Round-trip for column 0x87F2_DB30");
        $display("    Input:    0x%08h", 32'h87F2_DB30);
        $display("    MixOut:   0x%08h", tb_mc_col_out);
        $display("    InvMixOut: 0x%08h", tb_imc_col_out);
    end
    test_count = test_count + 1;
    
    // Test column 2 from FIPS-197 example
    // Input: E8 2E 44 5B
    tb_mc_col_in = 32'hE8_2E_44_5B;
    #1;
    tb_imc_col_in = tb_mc_col_out;
    #1;
    if (tb_imc_col_out === 32'hE8_2E_44_5B) begin
        $display("  PASS: Round-trip for column 0xE82E445B");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: Round-trip for column 0xE82E445B");
    end
    test_count = test_count + 1;
    
    // Test column 3 from FIPS-197 example
    // Input: B8 2F 6E 49
    tb_mc_col_in = 32'hB8_2F_6E_49;
    #1;
    tb_imc_col_in = tb_mc_col_out;
    #1;
    if (tb_imc_col_out === 32'hB8_2F_6E_49) begin
        $display("  PASS: Round-trip for column 0xB82F6E49");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: Round-trip for column 0xB82F6E49");
    end
    test_count = test_count + 1;
    
    // Test column 4 from FIPS-197 example
    // Input: 49 55 07 85
    tb_mc_col_in = 32'h49_55_07_85;
    #1;
    tb_imc_col_in = tb_mc_col_out;
    #1;
    if (tb_imc_col_out === 32'h49_55_07_85) begin
        $display("  PASS: Round-trip for column 0x49550785");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: Round-trip for column 0x49550785");
    end
    test_count = test_count + 1;
    
    // =================================================================
    // Test: All zeros -> all zeros
    // =================================================================
    $display("\n--- Test 2: Zero column ---");
    tb_mc_col_in = 32'h00000000;
    #1;
    if (tb_mc_col_out === 32'h00000000) begin
        $display("  PASS: MixColumns(0) = 0");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: MixColumns(0) != 0");
    end
    test_count = test_count + 1;
    
    // =================================================================
    // Test: Known MixColumns value
    // Input column: 87 F2 DB 30 -> expected F3 3E 88 DB
    // (computed via the standard MixColumns matrix multiplication in GF(2^8))
    // =================================================================
    $display("\n--- Test 3: Known MixColumns values ---");
    tb_mc_col_in = 32'h87F2_DB30;
    #1;
    expected = 32'hF3_3E_88_DB;
    if (tb_mc_col_out === expected) begin
        $display("  PASS: MixColumns(0x87F2_DB30) = 0xF3_3E_88_DB");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: MixColumns(0x87F2_DB30)");
        $display("    Expected: 0x%08h", expected);
        $display("    Got:      0x%08h", tb_mc_col_out);
    end
    test_count = test_count + 1;
    
    // =================================================================
    // Test: InvMixColumns on known values
    // =================================================================
    $display("\n--- Test 4: Known InvMixColumns values ---");
    // InvMixColumns(F3 3E 88 DB) = 87 F2 DB 30 (inverse of Test 3)
    tb_imc_col_in = 32'hF3_3E_88_DB;
    #1;
    expected = 32'h87F2_DB30;
    if (tb_imc_col_out === expected) begin
        $display("  PASS: InvMixColumns(0xF3_3E_88_DB) = 0x87_F2_DB_30");
        pass_count = pass_count + 1;
    end else begin
        $display("  FAIL: InvMixColumns(0xF3_3E_88_DB)");
        $display("    Expected: 0x%08h", expected);
        $display("    Got:      0x%08h", tb_imc_col_out);
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
