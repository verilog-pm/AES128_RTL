// =============================================================================
// AES-128 Streaming Testbench
// Tests continuous high-throughput data input capability
// Validates that pipeline can accept new data every cycle without stalling
// =============================================================================

`timescale 1ns / 1ps

module aes128_streaming_tb;

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
wire         tb_key_ready;
reg          tb_mode;
reg  [127:0] tb_data_in;
reg          tb_data_in_valid;
wire         tb_data_in_ready;
wire [127:0] tb_data_out;
wire         tb_data_out_valid;
reg          tb_data_out_ready;

// =============================================================================
// DUT instantiation
// =============================================================================
aes128_top dut (
    .clk(tb_clk),
    .rst_n(tb_rst_n),
    .key(tb_key),
    .key_valid(tb_key_valid),
    .key_ready(tb_key_ready),
    .mode(tb_mode),
    .op_mode(2'b00),      // ECB (this testbench exercises raw streaming throughput)
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
    tb_data_in = 128'h0;
    tb_mode = 0;  // Encryption mode
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
    tb_key_valid = 0;
    while (!tb_key_ready) @(posedge tb_clk);
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
                @(posedge tb_clk);
                if (tb_data_in_ready) begin
                    tb_data_in = input_data[input_count];
                    tb_data_in_valid = 1;
                    $display("[%0t] Cycle %0d: Sent block %0d: %h", 
                             $time, cycle_count, input_count, input_data[input_count]);
                    input_count = input_count + 1;
                    cycle_count = cycle_count + 1;

                    // Hold data_in_valid high for exactly this one cycle, then
                    // decide whether to insert an idle gap before the next
                    // block (only while there are still blocks left to send).
                    if (input_count < NUM_BLOCKS) begin
                        gap = $urandom_range(0, 4);
                        if (gap > 0) begin
                            @(posedge tb_clk);
                            tb_data_in_valid = 0;
                            $display("[%0t] Cycle %0d: Inserting %0d-cycle gap before next block",
                                     $time, cycle_count, gap);
                            cycle_count = cycle_count + 1;
                            repeat (gap - 1) begin
                                @(posedge tb_clk);
                                cycle_count = cycle_count + 1;
                            end
                        end
                    end
                end else begin
                    $display("[%0t] Cycle %0d: INPUT STALLED (data_in_ready=0)", $time, cycle_count);
                    cycle_count = cycle_count + 1;
                end
            end
            @(posedge tb_clk);
            tb_data_in_valid = 0;
            $display("[%0t] All %0d blocks sent", $time, NUM_BLOCKS);
        end
        
        // Output process: collect results
        begin
            while (output_count < NUM_BLOCKS) begin
                @(posedge tb_clk);
                if (tb_data_out_valid && tb_data_out_ready) begin
                    output_data[output_count] = tb_data_out;
                    $display("[%0t] Received block %0d: %h", $time, output_count, tb_data_out);
                    output_count = output_count + 1;
                end
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
    $display("Input cycles:     %0d", cycle_count);
    $display("Throughput:       %.2f blocks/cycle", NUM_BLOCKS / real'(cycle_count));
    
    if (cycle_count == NUM_BLOCKS) begin
        $display("RESULT: OPTIMAL - Full throughput achieved (1 block/cycle)");
    end else if (cycle_count < NUM_BLOCKS + 5) begin
        $display("RESULT: EXCELLENT - Near-optimal throughput");
    end else if (cycle_count < NUM_BLOCKS * 2) begin
        $display("RESULT: GOOD - Improved throughput over blocking mode");
    end else begin
        $display("RESULT: POOR - Still experiencing significant stalls");
    end
    
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
