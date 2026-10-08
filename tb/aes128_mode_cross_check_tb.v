// =============================================================================
// AES-128 CBC / CTR Cross-check Testbench
// Reads golden (key, iv, plaintext, ciphertext) vectors produced offline by
// gen_mode_vectors.py (pycryptodome) and checks that aes128_top's CBC and
// CTR op_mode implementations match, for both encryption and decryption.
//
// Vectors are grouped into fixed-size messages (BLOCKS_PER_MESSAGE blocks
// each); a fresh IV is loaded before the first block of every message, and
// blocks within a message are streamed back-to-back (allowing idle gaps),
// matching how a real CBC/CTR session is expected to be driven: load IV once
// per message, then stream all blocks of that message before loading a new
// IV for the next message.
// =============================================================================

`timescale 1ns / 1ps

module aes128_mode_cross_check_tb;

// =============================================================================
// Parameters
// =============================================================================
parameter NUM_MESSAGES      = 8;
parameter BLOCKS_PER_MESSAGE = 16;
parameter NUM_VECTORS        = NUM_MESSAGES * BLOCKS_PER_MESSAGE;
parameter CBC_VECTOR_FILE   = "aes128_cbc_vectors.hex";
parameter CTR_VECTOR_FILE   = "aes128_ctr_vectors.hex";
parameter CLK_PERIOD        = 10;
parameter MAX_GAP           = 3;  // max idle cycles between back-to-back blocks

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
wire         tb_key_ready;
reg          tb_mode;      // 0=encrypt, 1=decrypt
reg  [1:0]   tb_op_mode;   // 01=CBC, 10=CTR
reg  [127:0] tb_iv;
reg          tb_iv_valid;
wire         tb_iv_ready;
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
    .op_mode(tb_op_mode),
    .iv(tb_iv),
    .iv_valid(tb_iv_valid),
    .iv_ready(tb_iv_ready),
    .data_in(tb_data_in),
    .data_in_valid(tb_data_in_valid),
    .data_in_ready(tb_data_in_ready),
    .data_out(tb_data_out),
    .data_out_valid(tb_data_out_valid),
    .data_out_ready(tb_data_out_ready)
);

// =============================================================================
// Vector storage (golden model, from pycryptodome via gen_mode_vectors.py)
// =============================================================================
reg [127:0] vec_key        [0:NUM_VECTORS-1];
reg [127:0] vec_iv         [0:NUM_VECTORS-1];
reg [127:0] vec_plaintext  [0:NUM_VECTORS-1];
reg [127:0] vec_ciphertext [0:NUM_VECTORS-1];

task load_vectors;
    input [8*64:1] fname;  // plain string arg (packed reg), matches $fscanf usage below
    integer fd, scan_ret, idx;
begin
    fd = $fopen(fname, "r");
    if (fd == 0) begin
        $display("ERROR: could not open %s", fname);
        $finish;
    end
    idx = 0;
    while (!$feof(fd) && idx < NUM_VECTORS) begin
        scan_ret = $fscanf(fd, "%h %h %h %h\n",
                            vec_key[idx], vec_iv[idx], vec_plaintext[idx], vec_ciphertext[idx]);
        if (scan_ret == 4) begin
            idx = idx + 1;
        end
    end
    $fclose(fd);
    $display("Loaded %0d vectors from %s", idx, fname);
end
endtask

// =============================================================================
// Task: stream one message (BLOCKS_PER_MESSAGE blocks starting at base_idx)
// into the DUT back-to-back with random 0..MAX_GAP idle-cycle gaps, while a
// parallel process collects the results in arrival order.
// =============================================================================
task stream_message;
    input integer   base_idx;
    input           use_ct_as_src;  // 0: source=plaintext, 1: source=ciphertext
    output [127:0]  dst [0:BLOCKS_PER_MESSAGE-1];
    integer sent, received, gap;
begin
    sent = 0;
    received = 0;

    fork
        begin : send_proc
            // Present each block and hold data_in_valid asserted until the
            // DUT actually asserts data_in_ready for it (handles CBC-encrypt
            // backpressure, where acceptance can be delayed by many cycles).
            while (sent < BLOCKS_PER_MESSAGE) begin
                tb_data_in = use_ct_as_src ? vec_ciphertext[base_idx + sent]
                                            : vec_plaintext[base_idx + sent];
                tb_data_in_valid = 1;
                // Wait for this exact block to be accepted.
                do begin
                    @(posedge tb_clk);
                end while (!tb_data_in_ready);
                sent = sent + 1;
`ifdef DEBUG_TRACE
                $display("[%0t] DEBUG send: sent=%0d data_in=%h", $time, sent, tb_data_in);
`endif

                if (sent < BLOCKS_PER_MESSAGE) begin
                    gap = $urandom_range(0, MAX_GAP);
                    if (gap > 0) begin
                        tb_data_in_valid = 0;
                        repeat (gap) @(posedge tb_clk);
                    end
                end
            end
            tb_data_in_valid = 0;
        end

        begin : recv_proc
            while (received < BLOCKS_PER_MESSAGE) begin
                @(posedge tb_clk);
                if (tb_data_out_valid && tb_data_out_ready) begin
                    dst[received] = tb_data_out;
                    received = received + 1;
`ifdef DEBUG_TRACE
                    $display("[%0t] DEBUG recv: received=%0d data_out=%h", $time, received, tb_data_out);
`endif
                end
            end
        end
    join
end
endtask

// =============================================================================
// Task: run one full test category (op_mode x direction) across all
// NUM_MESSAGES, loading a fresh key/IV per message as needed.
// =============================================================================
reg [127:0] last_key;

task run_test_category;
    input [1:0]     op_mode_sel;
    input           mode_bit;      // 0=encrypt, 1=decrypt
    input           use_ct_as_src; // 0: src=plaintext, 1: src=ciphertext
    input [8*8-1:0] label;         // short ASCII tag for failure messages
    output integer  pass_cnt;
    output integer  fail_cnt;
    integer m, b, base_idx;
    reg [127:0] msg_result [0:BLOCKS_PER_MESSAGE-1];
    reg [127:0] expected;
begin
    pass_cnt = 0;
    fail_cnt = 0;
    tb_mode    = mode_bit;
    tb_op_mode = op_mode_sel;

    for (m = 0; m < NUM_MESSAGES; m = m + 1) begin
        base_idx = m * BLOCKS_PER_MESSAGE;

        // Reload key only when it changes from the previous message.
        if (vec_key[base_idx] !== last_key) begin
            tb_key = vec_key[base_idx];
            tb_key_valid = 1;
            @(posedge tb_clk);
            tb_key_valid = 0;
            while (!tb_key_ready) @(posedge tb_clk);
            last_key = vec_key[base_idx];
        end

        // Load this message's IV / initial counter. Must wait for the
        // pipeline to be fully drained (iv_ready) before (re)seeding it.
        while (!tb_iv_ready) @(posedge tb_clk);
        tb_iv = vec_iv[base_idx];
        tb_iv_valid = 1;
        @(posedge tb_clk);
        tb_iv_valid = 0;
        repeat (2) @(posedge tb_clk);

        stream_message(base_idx, use_ct_as_src, msg_result);

        for (b = 0; b < BLOCKS_PER_MESSAGE; b = b + 1) begin
            expected = use_ct_as_src ? vec_plaintext[base_idx + b] : vec_ciphertext[base_idx + b];
            if (msg_result[b] === expected) begin
                pass_cnt = pass_cnt + 1;
            end else begin
                fail_cnt = fail_cnt + 1;
                $display("  %s FAIL [msg %0d blk %0d]: got=%032x exp=%032x",
                          label, m, b, msg_result[b], expected);
            end
        end

        // Let the pipeline fully drain before the next message's IV load.
        repeat (5) @(posedge tb_clk);
    end
end
endtask

// =============================================================================
// Test sequence
// =============================================================================
integer cbc_enc_pass, cbc_enc_fail, cbc_dec_pass, cbc_dec_fail;
integer ctr_enc_pass, ctr_enc_fail, ctr_dec_pass, ctr_dec_fail;

initial begin
    $display("========================================");
    $display("  AES-128 CBC/CTR Cross-check vs pycryptodome");
    $display("========================================");

    tb_key_valid = 0;
    tb_data_in_valid = 0;
    tb_data_in = 128'h0;
    tb_mode = 1'b0;
    tb_op_mode = 2'b00;
    tb_key = 128'h0;
    tb_iv = 128'h0;
    tb_iv_valid = 1'b0;
    tb_data_out_ready = 1'b1;
    last_key = {128{1'b1}};  // force first key load

    @(posedge tb_rst_n);
    repeat (3) @(posedge tb_clk);

    // --------------------------------------------------------------
    // CBC
    // --------------------------------------------------------------
    load_vectors(CBC_VECTOR_FILE);

    $display("[%0t] Running CBC ENCRYPT (%0d messages x %0d blocks)...",
              $time, NUM_MESSAGES, BLOCKS_PER_MESSAGE);
    run_test_category(2'b01, 1'b0, 1'b0, "CBC-ENC", cbc_enc_pass, cbc_enc_fail);

    $display("[%0t] Running CBC DECRYPT...", $time);
    run_test_category(2'b01, 1'b1, 1'b1, "CBC-DEC", cbc_dec_pass, cbc_dec_fail);

    // --------------------------------------------------------------
    // CTR
    // --------------------------------------------------------------
    load_vectors(CTR_VECTOR_FILE);

    $display("[%0t] Running CTR ENCRYPT (%0d messages x %0d blocks)...",
              $time, NUM_MESSAGES, BLOCKS_PER_MESSAGE);
    run_test_category(2'b10, 1'b0, 1'b0, "CTR-ENC", ctr_enc_pass, ctr_enc_fail);

    $display("[%0t] Running CTR DECRYPT...", $time);
    run_test_category(2'b10, 1'b1, 1'b1, "CTR-DEC", ctr_dec_pass, ctr_dec_fail);

    $display("\n========================================");
    $display("  CBC Encryption: %0d/%0d passed", cbc_enc_pass, cbc_enc_pass + cbc_enc_fail);
    $display("  CBC Decryption: %0d/%0d passed", cbc_dec_pass, cbc_dec_pass + cbc_dec_fail);
    $display("  CTR Encryption: %0d/%0d passed", ctr_enc_pass, ctr_enc_pass + ctr_enc_fail);
    $display("  CTR Decryption: %0d/%0d passed", ctr_dec_pass, ctr_dec_pass + ctr_dec_fail);
    if (cbc_enc_fail == 0 && cbc_dec_fail == 0 && ctr_enc_fail == 0 && ctr_dec_fail == 0) begin
        $display("  Status: ALL CBC/CTR CROSS-CHECK TESTS PASSED");
    end else begin
        $display("  Status: SOME CBC/CTR CROSS-CHECK TESTS FAILED");
    end
    $display("========================================");

    #100;
    $finish;
end

// =============================================================================
// Timeout watchdog
// =============================================================================
initial begin
    #4000000;
    $display("\nERROR: Simulation timeout!");
    $finish;
end

endmodule
