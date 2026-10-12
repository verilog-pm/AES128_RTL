// Requires the including module to define:
//   tb_clk, tb_data_in[TB_DW-1:0], tb_data_in_valid, tb_data_in_last,
//   tb_data_in_keep[TB_KW-1:0], tb_data_in_ready,
//   tb_data_out[TB_DW-1:0], tb_data_out_valid, tb_data_out_last,
//   tb_data_out_keep[TB_KW-1:0], tb_data_out_ready
// and localparams TB_DW, TB_KW, TB_BEATS.
// Beats are MSB-first slices of the 128-bit block. keep[i] qualifies
// data[8*i +: 8]. Full blocks use keep=all-ones; packet_last is carried
// on the last beat only.

task send_block;
    input [127:0] block;
    input         packet_last;
    integer       b;
    reg [TB_DW-1:0] beat;
    reg           beat_last;
begin
    for (b = 0; b < TB_BEATS; b = b + 1) begin
        beat = block[127 - b*TB_DW -: TB_DW];
        beat_last = packet_last && (b == TB_BEATS-1);
        if (b == 0) begin
            @(posedge tb_clk);
            #1;
            while (!tb_data_in_ready) begin
                @(posedge tb_clk);
                #1;
            end
        end else if (!tb_data_in_ready) begin
            tb_data_in_valid = 1'b0;
            tb_data_in_last = 1'b0;
            while (!tb_data_in_ready) begin
                @(posedge tb_clk);
                #1;
            end
        end
        tb_data_in = beat;
        tb_data_in_keep = {TB_KW{1'b1}};
        tb_data_in_last = beat_last;
        tb_data_in_valid = 1'b1;
        @(posedge tb_clk);
        #1;
    end
    tb_data_in_valid = 1'b0;
    tb_data_in_last = 1'b0;
end
endtask

task recv_block;
    output [127:0] block;
    output         final_last;
    integer        b;
    integer        guard;
begin
    block = 128'h0;
    final_last = 1'b0;
    b = 0;
    while (b < TB_BEATS) begin
        guard = 0;
        begin : wait_beat
            while (guard < 4000) begin
                @(posedge tb_clk);
                #1;
                if (tb_data_out_valid && tb_data_out_ready) begin
                    block[127 - b*TB_DW -: TB_DW] = tb_data_out;
                    if (tb_data_out_keep !== {TB_KW{1'b1}}) begin
                        $display("ERROR: data_out_keep=%b at beat %0d t=%0t",
                                 tb_data_out_keep, b, $time);
                        block = {128{1'bx}};
                    end
                    if ((b != TB_BEATS-1) && tb_data_out_last) begin
                        $display("ERROR: early data_out_last at beat %0d t=%0t", b, $time);
                        block = {128{1'bx}};
                    end
                    final_last = tb_data_out_last;
                    disable wait_beat;
                end
                guard = guard + 1;
            end
            $display("ERROR: timeout receiving beat %0d at t=%0t", b, $time);
            block = {128{1'bx}};
            final_last = 1'b0;
        end
        b = b + 1;
    end
end
endtask
