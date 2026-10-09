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

localparam TB_DW = 32;
localparam TB_KW = TB_DW / 8;
localparam TB_BEATS = 128 / TB_DW;

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
reg          tb_mode;      // 0=encrypt core, 1=decrypt core (CTR always uses encrypt)
reg  [1:0]   tb_op_mode;   // 01=CBC, 10=CTR
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
wire         use_enc = (tb_mode == 1'b0) || (tb_op_mode == 2'b10);

aes128_top #(.mode(1'b0)) dut_enc (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .op_mode(tb_op_mode),
    .iv(tb_iv),
    .iv_valid(tb_iv_valid && use_enc),
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
    .iv_valid(tb_iv_valid && !use_enc),
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

// Result beats for the message currently being streamed. Kept at module
// scope because Icarus Verilog rejects unpacked-array task ports.
reg [127:0] msg_result [0:BLOCKS_PER_MESSAGE-1];

// =============================================================================
// Task: stream one message (BLOCKS_PER_MESSAGE blocks starting at base_idx)
// into the DUT back-to-back with random 0..MAX_GAP idle-cycle gaps, while a
// parallel process collects the results in arrival order into msg_result.
// =============================================================================
task stream_message;
    input integer   base_idx;
    input           use_ct_as_src;  // 0: source=plaintext, 1: source=ciphertext
    integer sent, received, gap;
    reg saw_last;
    reg [127:0] got;
begin
    sent = 0;
    received = 0;

    fork
        begin : send_proc
            while (sent < BLOCKS_PER_MESSAGE) begin
                send_block(use_ct_as_src ? vec_ciphertext[base_idx + sent]
                                         : vec_plaintext[base_idx + sent], 1'b1);
                sent = sent + 1;
                if (sent < BLOCKS_PER_MESSAGE) begin
                    gap = $urandom_range(0, MAX_GAP);
                    if (gap > 0)
                        repeat (gap) @(posedge tb_clk);
                end
            end
        end

        begin : recv_proc
            while (received < BLOCKS_PER_MESSAGE) begin
                recv_block(got, saw_last);
                if (!saw_last)
                    got = {128{1'bx}};
                msg_result[received] = got;
                received = received + 1;
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
            #1;
            tb_key_valid = 0;
            while (!tb_data_in_ready) @(posedge tb_clk);
            last_key = vec_key[base_idx];
        end

        // Latch this message's IV. The core installs it once idle and holds
        // data_in_ready low until then.
        tb_iv = vec_iv[base_idx];
        tb_iv_valid = 1;
        @(posedge tb_clk);
        #1;
        tb_iv_valid = 0;
        repeat (2) @(posedge tb_clk);

        stream_message(base_idx, use_ct_as_src);

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
    tb_data_in_last = 0;
    tb_data_in_keep = {TB_KW{1'b0}};
    tb_data_in = {TB_DW{1'b0}};
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
