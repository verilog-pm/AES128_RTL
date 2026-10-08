// =============================================================================
// AES-128 Cross-check Testbench
// Reads randomly generated (key, plaintext, ciphertext) triples produced by
// gen_vectors.py (using pycryptodome as the golden reference) and checks that
// the RTL aes128_top module's encryption and decryption match.
// =============================================================================

`timescale 1ns / 1ps

module aes128_cross_check_tb;

// =============================================================================
// Parameters
// =============================================================================
parameter NUM_VECTORS = 10;
parameter VECTOR_FILE = "aes128_vectors.hex";

// =============================================================================
// Waveform dump
// =============================================================================
initial begin
    $dumpfile("aes128_cross_check_tb.vcd");
    $dumpvars(0, aes128_cross_check_tb);
end

// =============================================================================
// Clock and reset
// =============================================================================
reg tb_clk;
reg tb_rst_n;

initial begin
    tb_clk = 0;
    forever #5 tb_clk = ~tb_clk;
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
wire         tb_key_ready;
reg          tb_mode;
reg  [127:0] tb_data_in;
reg          tb_data_in_valid;
wire         tb_data_in_ready;
wire [127:0] tb_data_out;
wire         tb_data_out_valid;
reg          tb_data_out_ready;

aes128_top dut (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .key_ready(tb_key_ready),
    .mode(tb_mode),
    .op_mode(2'b00),      // ECB (this testbench only cross-checks ECB)
    .iv(128'h0),
    .iv_valid(1'b0),
    .iv_ready(),
    .data_in(tb_data_in),
    .data_in_valid(tb_data_in_valid),
    .data_in_ready(tb_data_in_ready),
    .data_out(tb_data_out),
    .data_out_valid(tb_data_out_valid),
    .data_out_ready(tb_data_out_ready)
);

// =============================================================================
// Vector storage: each row holds {key, plaintext, ciphertext}
// =============================================================================
reg [127:0] vec_key        [0:NUM_VECTORS-1];
reg [127:0] vec_plaintext  [0:NUM_VECTORS-1];
reg [127:0] vec_ciphertext [0:NUM_VECTORS-1];

integer fd, scan_ret, idx;

initial begin
    fd = $fopen(VECTOR_FILE, "r");
    if (fd == 0) begin
        $display("ERROR: could not open %s", VECTOR_FILE);
        $finish;
    end
    idx = 0;
    while (!$feof(fd) && idx < NUM_VECTORS) begin
        scan_ret = $fscanf(fd, "%h %h %h\n", vec_key[idx], vec_plaintext[idx], vec_ciphertext[idx]);
        if (scan_ret == 3) begin
            idx = idx + 1;
        end
    end
    $fclose(fd);
    $display("Loaded %0d vectors from %s", idx, VECTOR_FILE);
end

// =============================================================================
// Task: send one 128-bit block and capture the output data_out_valid pulse.
// =============================================================================
task send_and_capture;
    input  [127:0] in_data;
    output [127:0] out_data;
    output         got_valid;
    integer wait_cycles;
begin
    @(posedge tb_clk);
    tb_data_in = in_data;
    tb_data_in_valid = 1;
    @(posedge tb_clk);
    while (!tb_data_in_ready) @(posedge tb_clk);
    tb_data_in_valid = 0;

    got_valid = 0;
    out_data  = 128'h0;
    wait_cycles = 0;
    while (!got_valid && wait_cycles < 50) begin
        @(posedge tb_clk);
        wait_cycles = wait_cycles + 1;
        if (tb_data_out_valid) begin
            got_valid = 1;
            out_data  = tb_data_out;
        end
    end
end
endtask

// =============================================================================
// Test sequence
// =============================================================================
integer v;
integer enc_pass, enc_fail;
integer dec_pass, dec_fail;
reg [127:0] result;
reg         result_valid;
reg [127:0] last_key;

initial begin
    $display("========================================");
    $display("  AES-128 Cross-check vs pycryptodome");
    $display("========================================");

    enc_pass = 0; enc_fail = 0;
    dec_pass = 0; dec_fail = 0;
    result = 128'h0;
    result_valid = 1'b0;
    last_key = {128{1'b1}}; // force first key load

    tb_key_valid = 0;
    tb_data_in_valid = 0;
    tb_data_in = 128'h0;
    tb_mode = 0;
    tb_key = 128'h0;
    tb_data_out_ready = 1'b1;

    @(posedge tb_rst_n);
    #10;

    // Wait for the vector-loading initial block above to finish populating
    // the vector arrays before using them.
    #1;

    for (v = 0; v < NUM_VECTORS; v = v + 1) begin
        if (vec_key[v] !== last_key) begin
            tb_key = vec_key[v];
            tb_key_valid = 1;
            @(posedge tb_clk);
            tb_key_valid = 0;
            while (!tb_key_ready) @(posedge tb_clk);
            last_key = vec_key[v];
            #20;
        end

        // Encryption check
        tb_mode = 1'b0;
        send_and_capture(vec_plaintext[v], result, result_valid);
        if (result_valid && result === vec_ciphertext[v]) begin
            enc_pass = enc_pass + 1;
        end else begin
            enc_fail = enc_fail + 1;
            $display("  ENC FAIL [%0d]: key=%032x pt=%032x got=%032x exp=%032x valid=%b",
                      v, vec_key[v], vec_plaintext[v], result, vec_ciphertext[v], result_valid);
        end

        // Decryption check
        tb_mode = 1'b1;
        send_and_capture(vec_ciphertext[v], result, result_valid);
        if (result_valid && result === vec_plaintext[v]) begin
            dec_pass = dec_pass + 1;
        end else begin
            dec_fail = dec_fail + 1;
            $display("  DEC FAIL [%0d]: key=%032x ct=%032x got=%032x exp=%032x valid=%b",
                      v, vec_key[v], vec_ciphertext[v], result, vec_plaintext[v], result_valid);
        end
    end

    $display("\n========================================");
    $display("  Encryption: %0d/%0d passed", enc_pass, enc_pass + enc_fail);
    $display("  Decryption: %0d/%0d passed", dec_pass, dec_pass + dec_fail);
    if (enc_fail == 0 && dec_fail == 0) begin
        $display("  Status: ALL CROSS-CHECK TESTS PASSED");
    end else begin
        $display("  Status: SOME CROSS-CHECK TESTS FAILED");
    end
    $display("========================================");

    #100;
    $finish;
end

// =============================================================================
// Timeout watchdog
// =============================================================================
initial begin
    #2000000;
    $display("\nERROR: Simulation timeout!");
    $finish;
end

endmodule
