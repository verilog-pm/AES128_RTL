// DATA_WIDTH 32 and 64, plus a short final beat (last + keep).
// NIST ECB checks both widths. CTR partial packets round-trip.
// A two-block ECB message checks that data_out_last is only on the last beat.

`timescale 1ns / 1ps

module aes_width_case #(parameter integer DATA_WIDTH = 32) (
    input  wire tb_clk,
    input  wire tb_rst_n,
    output reg  done,
    output integer errors
);
    localparam TB_DW = DATA_WIDTH;
    localparam TB_KW = TB_DW / 8;
    localparam TB_BEATS = 128 / TB_DW;

    reg  [127:0] tb_key;
    reg          tb_key_valid;
    reg  [1:0]   tb_op_mode;
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

    aes128_top #(.mode(1'b0), .DATA_WIDTH(DATA_WIDTH)) dut (
        .clk(tb_clk),
        .rst_n(tb_rst_n),
        .key(tb_key),
        .key_valid(tb_key_valid),
        .op_mode(tb_op_mode),
        .iv(tb_iv),
        .iv_valid(tb_iv_valid),
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

    task drive_beat;
        input [TB_DW-1:0] beat;
        input [TB_KW-1:0] keep;
        input             last;
        begin
            @(posedge tb_clk);
            #1;
            while (!tb_data_in_ready) begin
                @(posedge tb_clk);
                #1;
            end
            tb_data_in = beat;
            tb_data_in_keep = keep;
            tb_data_in_last = last;
            tb_data_in_valid = 1'b1;
            @(posedge tb_clk);
            #1;
            tb_data_in_valid = 1'b0;
            tb_data_in_last = 1'b0;
        end
    endtask

    task automatic capture_n;
        input integer nbeats;
        output [127:0] block;
        output [TB_BEATS-1:0] last_seen;
        output [TB_KW-1:0] last_keep;
        integer b;
        integer guard;
        reg [TB_DW-1:0] beat;
        begin
            block = 128'h0;
            last_seen = {TB_BEATS{1'b0}};
            last_keep = {TB_KW{1'b0}};
            for (b = 0; b < nbeats; b = b + 1) begin
                guard = 0;
                begin : wait_one
                    while (guard < 4000) begin
                        @(posedge tb_clk);
                        #1;
                        if (tb_data_out_valid && tb_data_out_ready) begin
                            beat = tb_data_out;
                            block[127 - b*TB_DW -: TB_DW] = beat;
                            last_seen[b] = tb_data_out_last;
                            last_keep = tb_data_out_keep;
                            disable wait_one;
                        end
                        guard = guard + 1;
                    end
                    $display("DW=%0d ERROR: timeout beat %0d", DATA_WIDTH, b);
                    errors = errors + 1;
                end
            end
            @(posedge tb_clk);
            #1;
            if (tb_data_out_valid) begin
                $display("DW=%0d ERROR: extra beat after %0d", DATA_WIDTH, nbeats);
                errors = errors + 1;
            end
        end
    endtask

    reg [127:0] got;
    reg [127:0] ct;
    reg saw_last;
    reg [TB_BEATS-1:0] lasts;
    reg [TB_KW-1:0] tail_keep;
    reg [127:0] nist_pt;
    reg [127:0] nist_ct;
    reg [127:0] partial;

    initial begin
        done = 1'b0;
        errors = 0;
        tb_key_valid = 1'b0;
        tb_iv_valid = 1'b0;
        tb_data_in_valid = 1'b0;
        tb_data_in_last = 1'b0;
        tb_data_in_keep = {TB_KW{1'b0}};
        tb_data_in = {TB_DW{1'b0}};
        tb_data_out_ready = 1'b1;
        tb_op_mode = 2'b00;
        tb_key = 128'h0;
        tb_iv = 128'h0;
        nist_pt = 128'h3243f6a8_885a308d_313198a2_e0370734;
        nist_ct = 128'h3925841d_02dc09fb_dc118597_196a0b32;

        @(posedge tb_rst_n);
        repeat (4) @(posedge tb_clk);

        tb_key = 128'h2b7e1516_28aed2a6_abf71588_09cf4f3c;
        tb_key_valid = 1'b1;
        @(posedge tb_clk);
        #1;
        tb_key_valid = 1'b0;
        while (!tb_data_in_ready) @(posedge tb_clk);

        send_block(nist_pt, 1'b1);
        recv_block(got, saw_last);
        if (got !== nist_ct || !saw_last) begin
            $display("DW=%0d FAIL NIST enc got=%h last=%b", DATA_WIDTH, got, saw_last);
            errors = errors + 1;
        end else begin
            $display("DW=%0d PASS NIST enc", DATA_WIDTH);
        end

        // Two full blocks: last only on the second block's final beat.
        send_block(nist_pt, 1'b0);
        send_block(nist_pt, 1'b1);
        recv_block(got, saw_last);
        if (got !== nist_ct || saw_last) begin
            $display("DW=%0d FAIL block0 got=%h last=%b", DATA_WIDTH, got, saw_last);
            errors = errors + 1;
        end
        recv_block(got, saw_last);
        if (got !== nist_ct || !saw_last) begin
            $display("DW=%0d FAIL block1 got=%h last=%b", DATA_WIDTH, got, saw_last);
            errors = errors + 1;
        end else begin
            $display("DW=%0d PASS multi-block last", DATA_WIDTH);
        end

        // CTR partial packet. 32-bit: 5 bytes. 64-bit: 3 bytes.
        tb_op_mode = 2'b10;
        tb_iv = 128'h00010203_04050607_08090a0b_0c0d0e0f;
        tb_iv_valid = 1'b1;
        @(posedge tb_clk);
        #1;
        tb_iv_valid = 1'b0;
        while (!tb_data_in_ready) @(posedge tb_clk);

        if (DATA_WIDTH == 32) begin
            partial = 128'hAABBCCDD_EE000000_00000000_00000000;
            drive_beat(32'hAABBCCDD, 4'b1111, 1'b0);
            drive_beat(32'hEE000000, 4'b1000, 1'b1);
            capture_n(2, ct, lasts, tail_keep);
            if (lasts !== 2'b10 || tail_keep !== 4'b1000 || ct[87:0] !== 88'h0) begin
                $display("DW=32 FAIL partial flags lasts=%b keep=%b ct=%h",
                         lasts, tail_keep, ct);
                errors = errors + 1;
            end
        end else begin
            partial = 128'hAABBCC00_00000000_00000000_00000000;
            drive_beat(64'hAABBCC00_00000000, 8'b1110_0000, 1'b1);
            capture_n(1, ct, lasts, tail_keep);
            if (lasts[0] !== 1'b1 || tail_keep !== 8'b1110_0000 || ct[103:0] !== 104'h0) begin
                $display("DW=64 FAIL partial flags last=%b keep=%b ct=%h",
                         lasts[0], tail_keep, ct);
                errors = errors + 1;
            end
        end

        tb_iv_valid = 1'b1;
        @(posedge tb_clk);
        #1;
        tb_iv_valid = 1'b0;
        while (!tb_data_in_ready) @(posedge tb_clk);

        if (DATA_WIDTH == 32) begin
            drive_beat(ct[127:96], 4'b1111, 1'b0);
            drive_beat(ct[95:64], 4'b1000, 1'b1);
            capture_n(2, got, lasts, tail_keep);
        end else begin
            drive_beat(ct[127:64], 8'b1110_0000, 1'b1);
            capture_n(1, got, lasts, tail_keep);
        end
        if (got !== partial) begin
            $display("DW=%0d FAIL CTR round-trip got=%h exp=%h", DATA_WIDTH, got, partial);
            errors = errors + 1;
        end else begin
            $display("DW=%0d PASS CTR partial round-trip", DATA_WIDTH);
        end

        done = 1'b1;
    end
endmodule

module aes128_width_tb;
    reg clk;
    reg rst_n;
    wire done32, done64;
    integer err32, err64;

    initial begin
        clk = 1'b0;
        forever #5 clk = ~clk;
    end

    initial begin
        rst_n = 1'b0;
        #20;
        rst_n = 1'b1;
    end

    aes_width_case #(.DATA_WIDTH(32)) c32 (
        .tb_clk(clk), .tb_rst_n(rst_n), .done(done32), .errors(err32)
    );
    aes_width_case #(.DATA_WIDTH(64)) c64 (
        .tb_clk(clk), .tb_rst_n(rst_n), .done(done64), .errors(err64)
    );

    initial begin
        wait (done32 && done64);
        if (err32 == 0 && err64 == 0)
            $display("WIDTH TESTS PASSED");
        else
            $display("WIDTH TESTS FAILED 32=%0d 64=%0d", err32, err64);
        $finish;
    end

    initial begin
        #200000;
        $display("ERROR: width tb timeout");
        $finish;
    end
endmodule
