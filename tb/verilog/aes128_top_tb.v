// =============================================================================
// AES-128 Top Module Testbench
// Tests encryption and decryption using NIST FIPS-197 test vectors
// =============================================================================

`timescale 1ns / 1ps

module aes128_top_tb;

localparam TB_DW = 32;
localparam TB_KW = TB_DW / 8;
localparam TB_BEATS = 128 / TB_DW;

// =============================================================================
// Clock and reset
// =============================================================================
reg         tb_clk;
reg         tb_rst_n;

initial begin
    tb_clk = 0;
    forever #5 tb_clk = ~tb_clk;  // 100MHz clock
end

initial begin
    tb_rst_n = 0;
    #20;
    tb_rst_n = 1;
end

// =============================================================================
// DUT
// =============================================================================
reg  [127:0] tb_key;
reg          tb_key_valid;
reg          tb_mode;       // selects which parameterized core is observed
reg  [1:0]   tb_op_mode;    // 00=ECB, 01=CBC, 10=CTR (this testbench uses ECB)
reg  [127:0] tb_iv;
reg          tb_iv_valid;
reg  [TB_DW-1:0] tb_data_in;
reg          tb_data_in_valid;
reg          tb_data_in_last;
reg  [TB_KW-1:0] tb_data_in_keep;
wire         tb_data_in_ready;
wire [TB_DW-1:0] tb_data_out;
wire         tb_data_out_valid;
wire         tb_data_out_last;
wire [TB_KW-1:0] tb_data_out_keep;
reg          tb_data_out_ready;

wire         enc_ready, dec_ready;
wire         enc_out_valid, dec_out_valid;
wire         enc_last, dec_last;
wire [TB_DW-1:0] enc_out, dec_out;
wire [TB_KW-1:0] enc_keep, dec_keep;
// CTR (both directions) lives on the encrypt core.
wire         use_enc = (tb_mode == 1'b0) || (tb_op_mode == 2'b10);

aes128_top #(.mode(1'b0)) dut_enc (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .op_mode(tb_op_mode),
    .iv(tb_iv),
    .iv_valid(tb_iv_valid),
    .data_in(tb_data_in),
    .data_in_valid(tb_data_in_valid && use_enc),
    .data_in_last(tb_data_in_last && use_enc),
    .data_in_keep(tb_data_in_keep),
    .data_in_ready(enc_ready),
    .data_out(enc_out),
    .data_out_valid(enc_out_valid),
    .data_out_last(enc_last),
    .data_out_keep(enc_keep),
    .data_out_ready(tb_data_out_ready)
);

aes128_top #(.mode(1'b1)) dut_dec (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .op_mode(tb_op_mode),
    .iv(tb_iv),
    .iv_valid(tb_iv_valid),
    .data_in(tb_data_in),
    .data_in_valid(tb_data_in_valid && !use_enc),
    .data_in_last(tb_data_in_last && !use_enc),
    .data_in_keep(tb_data_in_keep),
    .data_in_ready(dec_ready),
    .data_out(dec_out),
    .data_out_valid(dec_out_valid),
    .data_out_last(dec_last),
    .data_out_keep(dec_keep),
    .data_out_ready(tb_data_out_ready)
);

assign tb_data_in_ready  = use_enc ? enc_ready : dec_ready;
assign tb_data_out       = use_enc ? enc_out : dec_out;
assign tb_data_out_valid = use_enc ? enc_out_valid : dec_out_valid;
assign tb_data_out_last  = use_enc ? enc_last : dec_last;
assign tb_data_out_keep  = use_enc ? enc_keep : dec_keep;

`include "aes_stream_tasks.vh"

// =============================================================================
// Test vectors from FIPS-197
// Test Case 1:
// Key:    2b7e1516 28aed2a6 abf71588 09cf4f3c
// Plaintext:  3243f6a8 885a308d 313198a2 e0370734
// Ciphertext: 3925841d 02dc09fb dc118597 196a0b32
// =============================================================================

// =============================================================================
// Test control
// =============================================================================
reg [127:0] test_key;
reg [127:0] test_plaintext;
reg [127:0] test_ciphertext;
reg [127:0] result;
reg         result_valid;

// =============================================================================
// Test sequence
// =============================================================================
integer test_count;
integer pass_count;

// =============================================================================
// Task: send one 128-bit block and capture the output data_out_valid pulse.
// data_out_valid is asserted for exactly one cycle per output word, so we
// must sample every cycle rather than waiting a fixed number of cycles.
// =============================================================================
task send_and_capture;
    input  [127:0] in_data;
    output [127:0] out_data;
    output         got_valid;
    reg            saw_last;
begin
    send_block(in_data, 1'b1);
    recv_block(out_data, saw_last);
    got_valid = saw_last && (out_data !== {128{1'bx}});
end
endtask

initial begin
    $display("========================================");
    $display("  AES-128 Top Module Testbench");
    $display("========================================");
    test_count = 0;
    pass_count = 0;
    result = 128'h0;
    result_valid = 1'b0;
    
    // Initialize control signals
    tb_key_valid = 0;
    tb_data_in_valid = 0;
    tb_data_in_last = 0;
    tb_data_in_keep = {TB_KW{1'b0}};
    tb_data_in = {TB_DW{1'b0}};
    tb_mode = 0;
    tb_op_mode = 2'b00;  // ECB
    tb_iv = 128'h0;
    tb_iv_valid = 1'b0;
    tb_key = 128'h0;
    tb_data_out_ready = 1'b1;
    
    // Wait for reset
    @(posedge tb_rst_n);
    #10;
    
    // =================================================================
    // Test 1: Load key and encrypt
    // =================================================================
    $display("\n--- Loading Key ---");
    test_key = 128'h2b7e1516_28aed2a6_abf71588_09cf4f3c;
    tb_key = test_key;
    tb_key_valid = 1;
    @(posedge tb_clk);
    #1;
    tb_key_valid = 0;
    
    // key_valid only latches the key. data_in_ready rises after the cipher
    // is idle and round-key expansion has finished.
    while (!tb_data_in_ready) @(posedge tb_clk);
    $display("  Key loaded successfully");
    repeat (2) @(posedge tb_clk);
    
    $display("\n--- Test 1: Encryption ---");
    tb_mode = 1'b0;
    test_plaintext = 128'h3243f6a8_885a308d_313198a2_e0370734;
    test_ciphertext = 128'h3925841d_02dc09fb_dc118597_196a0b32;
    
    send_and_capture(test_plaintext, result, result_valid);
    
    test_count = test_count + 1;
    if (result_valid) begin
        $display("  Input:    0x%032x", test_plaintext);
        $display("  Output:   0x%032x", result);
        $display("  Expected: 0x%032x", test_ciphertext);
        
        if (result === test_ciphertext) begin
            $display("  PASS: Encryption matches expected ciphertext");
            pass_count = pass_count + 1;
        end else begin
            $display("  FAIL: Encryption output mismatch");
        end
    end else begin
        $display("  FAIL: No valid output received");
    end
    
    // =================================================================
    // Test 2: Decrypt
    // =================================================================
    $display("\n--- Test 2: Decryption ---");
    tb_mode = 1'b1;
    
    send_and_capture(test_ciphertext, result, result_valid);
    
    test_count = test_count + 1;
    if (result_valid) begin
        $display("  Input:    0x%032x", test_ciphertext);
        $display("  Output:   0x%032x", result);
        $display("  Expected: 0x%032x", test_plaintext);
        
        if (result === test_plaintext) begin
            $display("  PASS: Decryption matches expected plaintext");
            pass_count = pass_count + 1;
        end else begin
            $display("  FAIL: Decryption output mismatch");
        end
    end else begin
        $display("  FAIL: No valid output received");
    end
    
    // =================================================================
    // Test 3: Encrypt-Decrypt Round Trip
    // =================================================================
    $display("\n--- Test 3: Encrypt-Decrypt Round Trip ---");
    tb_mode = 1'b0;
    test_plaintext = 128'h00112233_44556677_8899aabb_ccddeeff;
    
    send_and_capture(test_plaintext, result, result_valid);
    
    if (result_valid) begin
        $display("  Plaintext:  0x%032x", test_plaintext);
        $display("  Ciphertext: 0x%032x", result);
        
        tb_mode = 1'b1;
        send_and_capture(result, result, result_valid);
        
        test_count = test_count + 1;
        if (result_valid && result === test_plaintext) begin
            $display("  Decrypted:   0x%032x", result);
            $display("  PASS: Round trip successful");
            pass_count = pass_count + 1;
        end else begin
            $display("  FAIL: Round trip failed (result_valid=%b)", result_valid);
        end
    end else begin
        test_count = test_count + 1;
        $display("  FAIL: No valid output received for encryption step");
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
    #100000;
    $display("\nERROR: Simulation timeout!");
    $finish;
end

endmodule
