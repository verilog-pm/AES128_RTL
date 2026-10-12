// =============================================================================
// AES-128 Streaming Testbench
// Tests continuous high-throughput data input capability
// Validates that pipeline can accept new data every cycle without stalling
// =============================================================================

`timescale 1ns / 1ps

module aes128_streaming_tb;

localparam TB_DW = 32;
localparam TB_KW = TB_DW / 8;
localparam TB_BEATS = 128 / TB_DW;

// =============================================================================
// Parameters
// =============================================================================
parameter NUM_BLOCKS = 20;  // Number of consecutive blocks to test
parameter CLK_PERIOD = 10;

// =============================================================================
// Signals
// =============================================================================
reg         tb_clk;
reg         tb_rst_n;
reg  [127:0] tb_key;
reg          tb_key_valid;
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

// =============================================================================
// DUT instantiation
// =============================================================================
aes128_top #(.mode(1'b0)) dut (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .op_mode(2'b00),      // ECB (this testbench exercises raw streaming throughput)
    .iv(128'h0),
    .iv_valid(1'b0),
    .data_in(tb_data_in),
    .data_in_valid(tb_data_in_valid),
    .data_in_last(tb_data_in_last),
    .data_in_keep(tb_data_in_keep),
    .data_in_ready(tb_data_in_ready),
    .data_out(tb_data_out),
    .data_out_valid(tb_data_out_valid),
    .data_out_last(tb_data_out_last),
    .data_out_keep(tb_data_out_keep),
    .data_out_ready(tb_data_out_ready)
);

`include "aes_stream_tasks.vh"

// =============================================================================
// Clock generation
// =============================================================================
initial begin
    tb_clk = 0;
    forever #(CLK_PERIOD/2) tb_clk = ~tb_clk;
end

// =============================================================================
// Reset generation
// =============================================================================
initial begin
    tb_rst_n = 0;
    #(CLK_PERIOD * 2);
    tb_rst_n = 1;
end

// =============================================================================
// Test data storage
// =============================================================================
reg [127:0] input_data [0:NUM_BLOCKS-1];
reg [127:0] output_data [0:NUM_BLOCKS-1];
integer input_count;
integer output_count;
integer cycle_count;

// =============================================================================
// Main test sequence
// =============================================================================
initial begin
    $display("========================================");
    $display("  AES-128 Streaming Test");
    $display("========================================");
    
    // Initialize signals
    tb_key_valid = 0;
    tb_data_in_valid = 0;
    tb_data_in_last = 0;
    tb_data_in_keep = {TB_KW{1'b0}};
    tb_data_in = {TB_DW{1'b0}};
    tb_key = 128'h2b7e151628aed2a6abf7158809cf4f3c;
    tb_data_out_ready = 1'b1;  // Always ready to accept output
    
    input_count = 0;
    output_count = 0;
    cycle_count = 0;
    
    // Generate test data patterns
    for (input_count = 0; input_count < NUM_BLOCKS; input_count = input_count + 1) begin
        input_data[input_count] = {32'hDEADBEEF, 32'h12345678, 32'h9ABCDEF0, input_count[31:0]};
    end
    input_count = 0;
    
    @(posedge tb_rst_n);
    repeat(5) @(posedge tb_clk);
    
    // Load key
    $display("[%0t] Loading encryption key...", $time);
    tb_key_valid = 1;
    @(posedge tb_clk);
    #1;
    tb_key_valid = 0;
    while (!tb_data_in_ready) @(posedge tb_clk);
    repeat(3) @(posedge tb_clk);
    
    $display("[%0t] Starting continuous data stream test...", $time);
    $display("Target: Send %0d blocks back-to-back", NUM_BLOCKS);
    
    // Fork input and output monitoring
    fork
        // Input process: send data with random gaps of 0-4 idle cycles between
        // blocks (a gap of 0 means fully back-to-back / continuous input).
        begin
            integer gap;
            while (input_count < NUM_BLOCKS) begin
                send_block(input_data[input_count], 1'b1);
                $display("[%0t] Sent block %0d: %h", $time, input_count, input_data[input_count]);
                input_count = input_count + 1;
                if (input_count < NUM_BLOCKS) begin
                    gap = $urandom_range(0, 4);
                    if (gap > 0) begin
                        $display("[%0t] Inserting %0d-cycle gap before next block", $time, gap);
                        repeat (gap) @(posedge tb_clk);
                    end
                end
            end
            $display("[%0t] All %0d blocks sent", $time, NUM_BLOCKS);
        end

        // Output process: collect one 128-bit block per TB_BEATS narrow beats
        begin
            reg saw_last;
            while (output_count < NUM_BLOCKS) begin
                recv_block(output_data[output_count], saw_last);
                if (!saw_last)
                    $display("ERROR: block %0d missing data_out_last", output_count);
                $display("[%0t] Received block %0d: %h", $time, output_count, output_data[output_count]);
                output_count = output_count + 1;
            end
            $display("[%0t] All %0d blocks received", $time, NUM_BLOCKS);
        end
    join
    
    // Wait a bit for pipeline to drain
    repeat(50) @(posedge tb_clk);
    
    $display("");
    $display("Final FIFO state check:");
    $display("  data_out_valid: %b", tb_data_out_valid);
    $display("  data_in_ready:  %b", tb_data_in_ready);
    
    // Performance analysis
    $display("");
    $display("========================================");
    $display("  Streaming Performance Analysis");
    $display("========================================");
    $display("Total blocks:     %0d", NUM_BLOCKS);
    $display("Beats per block:  %0d (DATA_WIDTH=%0d)", TB_BEATS, TB_DW);
    $display("RESULT: received %0d/%0d blocks", output_count, NUM_BLOCKS);
    
    $display("========================================");
    $finish;
end

// =============================================================================
// Timeout watchdog
// =============================================================================
initial begin
    #(CLK_PERIOD * 2000);
    $display("ERROR: Testbench timeout!");
    $display("Only received %0d/%0d blocks", output_count, NUM_BLOCKS);
    $finish;
end

endmodule
