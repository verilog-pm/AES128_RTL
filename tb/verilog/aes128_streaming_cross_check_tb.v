// =============================================================================
// AES-128 Streaming Cross-check Testbench
// Combines the two verification ideas:
//   1) Golden-model cross-check against pycryptodome (like aes128_cross_check_tb)
//   2) Continuous/back-to-back pipelined data transfer with random idle gaps
//      of 0-4 cycles (like aes128_streaming_tb), instead of the strictly
//      blocking one-block-at-a-time handshake.
//
// A single fixed key is loaded once, then all plaintext blocks are streamed
// into the encryption pipeline (multiple blocks in flight at once thanks to
// the pipeline + output FIFO). Results are collected out-of-band and compared
// against the golden ciphertexts produced offline by gen_stream_vectors.py.
//
// After the encryption pass, the recorded ciphertexts are streamed back
// through the pipeline in decrypt mode and checked against the original
// plaintexts, exercising the same continuous-transfer path for decryption.
// =============================================================================

`timescale 1ns / 1ps

module aes128_streaming_cross_check_tb;

localparam TB_DW = 32;
localparam TB_KW = TB_DW / 8;
localparam TB_BEATS = 128 / TB_DW;

// =============================================================================
// Parameters
// =============================================================================
parameter NUM_VECTORS = 64;
parameter VECTOR_FILE  = "aes128_stream_vectors.hex";
parameter CLK_PERIOD   = 10;
parameter MAX_GAP      = 4;  // max idle cycles allowed between back-to-back blocks

// =============================================================================
// Waveform dump
// =============================================================================
initial begin
    $dumpfile("aes128_streaming_cross_check_tb.vcd");
    $dumpvars(0, aes128_streaming_cross_check_tb);
end


// =============================================================================
// Clock and reset
// =============================================================================
reg tb_clk;
reg tb_rst_n;

initial begin
    tb_clk = 0;
    forever #(CLK_PERIOD/2) tb_clk = ~tb_clk;
end

initial begin
    tb_rst_n = 0;
    #(CLK_PERIOD * 2);
    tb_rst_n = 1;
end

// =============================================================================
// DUT
// =============================================================================
reg  [127:0] tb_key;
reg          tb_key_valid;
reg          tb_mode;
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
wire         use_enc = (tb_mode == 1'b0);

aes128_top #(.mode(1'b0)) dut_enc (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .op_mode(2'b00),
    .iv(128'h0),
    .iv_valid(1'b0),
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
    .op_mode(2'b00),
    .iv(128'h0),
    .iv_valid(1'b0),
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
// Vector storage (golden model, from pycryptodome via gen_stream_vectors.py)
// =============================================================================
reg [127:0] vec_key        [0:NUM_VECTORS-1];
reg [127:0] vec_plaintext  [0:NUM_VECTORS-1];
reg [127:0] vec_ciphertext [0:NUM_VECTORS-1];

// Captured results from the streaming runs
reg [127:0] enc_result [0:NUM_VECTORS-1];
reg [127:0] dec_result [0:NUM_VECTORS-1];

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
    $display("Loaded %0d streaming vectors from %s", idx, VECTOR_FILE);
end

// =============================================================================
// Generic streaming driver task: pumps NUM_VECTORS blocks from `src` into the
// DUT back-to-back, inserting a random 0..MAX_GAP idle-cycle gap after each
// block (0 means fully continuous), while a parallel process collects results
// into `dst`. Blocks are correlated by arrival order, matching the DUT's
// in-order pipeline + FIFO behavior.
// =============================================================================
// use_ct selects the source and the result array. Unpacked-array task
// ports are rejected by Icarus Verilog, so the arrays stay at module scope.
task stream_blocks;
    input use_ct;
    integer sent;
    integer received;
    reg saw_last;
    reg [127:0] got;
begin
    sent = 0;
    received = 0;

    fork
        begin : send_proc
            while (sent < NUM_VECTORS) begin
                if (use_ct)
                    send_block(vec_ciphertext[sent], 1'b1);
                else
                    send_block(vec_plaintext[sent], 1'b1);
                sent = sent + 1;
            end
        end

        begin : recv_proc
            while (received < NUM_VECTORS) begin
                recv_block(got, saw_last);
                if (!saw_last)
                    got = {128{1'bx}};
                if (use_ct)
                    dec_result[received] = got;
                else
                    enc_result[received] = got;
                received = received + 1;
            end
        end
    join
end
endtask

// =============================================================================
// Test sequence
// =============================================================================
integer v;
integer enc_pass, enc_fail;
integer dec_pass, dec_fail;

initial begin
    $display("========================================");
    $display("  AES-128 Streaming Cross-check vs pycryptodome");
    $display("========================================");

    enc_pass = 0; enc_fail = 0;
    dec_pass = 0; dec_fail = 0;

    tb_key_valid = 0;
    tb_data_in_valid = 0;
    tb_data_in_last = 0;
    tb_data_in_keep = {TB_KW{1'b0}};
    tb_data_in = {TB_DW{1'b0}};
    tb_mode = 0;
    tb_key = 128'h0;
    tb_data_out_ready = 1'b1;

    @(posedge tb_rst_n);
    #1; // let the vector-loading initial block finish populating the arrays

    // All vectors share a single key (see gen_stream_vectors.py), load it once.
    tb_key = vec_key[0];
    tb_key_valid = 1;
    @(posedge tb_clk);
    #1;
    tb_key_valid = 0;
    while (!tb_data_in_ready) @(posedge tb_clk);
    repeat(3) @(posedge tb_clk);

    // ---------------------------------------------------------------
    // Continuous encryption pass: plaintext -> enc_result
    // ---------------------------------------------------------------
    $display("[%0t] Starting continuous ENCRYPTION stream (%0d blocks)...", $time, NUM_VECTORS);
    tb_mode = 1'b0;
    stream_blocks(1'b0);

    for (v = 0; v < NUM_VECTORS; v = v + 1) begin
        if (enc_result[v] === vec_ciphertext[v]) begin
            enc_pass = enc_pass + 1;
        end else begin
            enc_fail = enc_fail + 1;
            $display("  ENC FAIL [%0d]: pt=%032x got=%032x exp=%032x",
                      v, vec_plaintext[v], enc_result[v], vec_ciphertext[v]);
        end
    end

    // Drain / settle before switching mode
    repeat(20) @(posedge tb_clk);

    // ---------------------------------------------------------------
    // Continuous decryption pass: ciphertext -> dec_result
    // ---------------------------------------------------------------
    $display("[%0t] Starting continuous DECRYPTION stream (%0d blocks)...", $time, NUM_VECTORS);
    tb_mode = 1'b1;
    stream_blocks(1'b1);

    for (v = 0; v < NUM_VECTORS; v = v + 1) begin
        if (dec_result[v] === vec_plaintext[v]) begin
            dec_pass = dec_pass + 1;
        end else begin
            dec_fail = dec_fail + 1;
            $display("  DEC FAIL [%0d]: ct=%032x got=%032x exp=%032x",
                      v, vec_ciphertext[v], dec_result[v], vec_plaintext[v]);
        end
    end

    $display("\n========================================");
    $display("  Streaming Encryption: %0d/%0d passed", enc_pass, enc_pass + enc_fail);
    $display("  Streaming Decryption: %0d/%0d passed", dec_pass, dec_pass + dec_fail);
    if (enc_fail == 0 && dec_fail == 0) begin
        $display("  Status: ALL STREAMING CROSS-CHECK TESTS PASSED");
    end else begin
        $display("  Status: SOME STREAMING CROSS-CHECK TESTS FAILED");
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
