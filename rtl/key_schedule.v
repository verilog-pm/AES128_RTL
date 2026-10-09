// =============================================================================
// AES-128 Key Schedule Module
// Generates 11 round keys (176 bytes total) from 128-bit initial key
// Also generates inverse round keys for decryption
// Based on FIPS-197 Section 5.2 and 5.3.5
// =============================================================================

// DECRYPT=0: encryption round keys only (encrypt core).
// DECRYPT=1: also derive the inverse round keys (decrypt core).
module key_schedule #(
    parameter DECRYPT = 1
) (
    input  wire         clk,
    input  wire         rst_n,
    input  wire [127:0] key,
    input  wire         key_valid,
    output reg          key_ready,
    output reg  [1407:0] round_key_enc,  // 11 keys × 128 bits = 1408 bits (flattened)
    output reg  [1407:0] round_key_dec   // 11 keys × 128 bits = 1408 bits (flattened)
);

// =============================================================================
// Constants
// =============================================================================
localparam NUM_ROUNDS = 4'd10;

// FSM states
localparam [2:0] KEY_IDLE       = 3'd0;
localparam [2:0] KEY_EXPAND     = 3'd1;
localparam [2:0] KEY_DEC_START  = 3'd2;
localparam [2:0] KEY_DEC_WAIT   = 3'd3;
localparam [2:0] KEY_DEC_LATCH  = 3'd4;
localparam [2:0] KEY_DONE       = 3'd5;

reg [2:0] state;
reg [3:0] round_cnt;
reg [2:0] word_idx;

// =============================================================================
// Internal storage for key words (44 words of 32 bits each)
// =============================================================================
reg [31:0] w [0:43];

// =============================================================================
// Rcon lookup function
// =============================================================================
function [7:0] get_rcon;
    input [3:0] r;
    case (r)
        4'd1:  get_rcon = 8'h01;
        4'd2:  get_rcon = 8'h02;
        4'd3:  get_rcon = 8'h04;
        4'd4:  get_rcon = 8'h08;
        4'd5:  get_rcon = 8'h10;
        4'd6:  get_rcon = 8'h20;
        4'd7:  get_rcon = 8'h40;
        4'd8:  get_rcon = 8'h80;
        4'd9:  get_rcon = 8'h1b;
        4'd10: get_rcon = 8'h36;
        default: get_rcon = 8'h00;
    endcase
endfunction

// =============================================================================
// S-box for SubWord
// SubWord: Apply S-box to each byte of a word
// RotWord: Rotate left by 1 byte (implemented in wiring)
// =============================================================================
wire [7:0] sbox_out_w0, sbox_out_w1, sbox_out_w2, sbox_out_w3;
wire [31:0] rotword_input;
wire [31:0] prev_word;

// Previous word w[N-1] where N = round_cnt*4 is the word currently being computed
assign prev_word = w[round_cnt * 4 - 1];

// RotWord: {w[23:16], w[15:8], w[7:0], w[31:24]}
assign rotword_input = {prev_word[23:16], prev_word[15:8], prev_word[7:0], prev_word[31:24]};

sbox sbox_ks0 (.in_data(rotword_input[31:24]), .out_data(sbox_out_w0));
sbox sbox_ks1 (.in_data(rotword_input[23:16]), .out_data(sbox_out_w1));
sbox sbox_ks2 (.in_data(rotword_input[15:8]),  .out_data(sbox_out_w2));
sbox sbox_ks3 (.in_data(rotword_input[7:0]),   .out_data(sbox_out_w3));

// SubWord = S-box applied to each byte
wire [31:0] subword;
assign subword = {sbox_out_w0, sbox_out_w1, sbox_out_w2, sbox_out_w3};

// New word = SubWord XOR Rcon[round] XOR w[N-4]
wire [31:0] new_word;
assign new_word = (subword ^ {get_rcon(round_cnt), 24'h000000}) ^ w[round_cnt * 4 - 4];

// =============================================================================
// InvMixColumns for decryption round keys
// Apply InvMixColumns to each 32-bit column of the encryption round key
// =============================================================================
reg  [31:0] imc_col_in;
wire [31:0] imc_col_out;
generate
if (DECRYPT != 0) begin : g_imc
    inv_mix_columns imc_inst (
        .col_in(imc_col_in),
        .col_out(imc_col_out)
    );
end else begin : g_no_imc
    assign imc_col_out = 32'h0;
end
endgenerate

// Decryption key generation working registers
reg [3:0] dec_round;       // Which decryption round key (1..9) is being built
reg [1:0] dec_word_stage;  // Which 32-bit word (0..3) within the round is being processed
reg [127:0] dec_src_key;   // Encryption round key being transformed
reg [127:0] dec_result;    // Assembled InvMixColumns result

// Track key_valid rising edge
reg key_valid_d1;
wire key_valid_pulse;
assign key_valid_pulse = key_valid && !key_valid_d1;

// =============================================================================
// Single unified state machine: key expansion + decryption key derivation
// =============================================================================
integer j;
always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
        state <= KEY_IDLE;
        round_cnt <= 4'd0;
        word_idx <= 3'd0;
        key_ready <= 1'b0;
        key_valid_d1 <= 1'b0;
        dec_round <= 4'd0;
        dec_word_stage <= 2'd0;
        dec_src_key <= 128'h0;
        dec_result <= 128'h0;
        imc_col_in <= 32'h0;

        for (j = 0; j < 44; j = j + 1) begin
            w[j] <= 32'h0;
        end
        for (j = 0; j < 11; j = j + 1) begin
            round_key_enc[j*128 +: 128] <= 128'h0;
            round_key_dec[j*128 +: 128] <= 128'h0;
        end
    end else begin
        key_valid_d1 <= key_valid;

        case (state)
            KEY_IDLE: begin
                if (key_valid_pulse) begin
                    // Load initial key
                    w[0] <= key[127:96];
                    w[1] <= key[95:64];
                    w[2] <= key[63:32];
                    w[3] <= key[31:0];
                    round_cnt <= 4'd1;
                    word_idx <= 3'd0;
                    state <= KEY_EXPAND;
                    key_ready <= 1'b0;
                end
            end

            KEY_EXPAND: begin
                // Compute 4 words per round
                case (word_idx)
                    3'd0: begin
                        w[round_cnt * 4] <= new_word;
                        word_idx <= 3'd1;
                    end
                    3'd1: begin
                        w[round_cnt * 4 + 1] <= w[round_cnt * 4 + 1 - 1] ^ w[round_cnt * 4 + 1 - 4];
                        word_idx <= 3'd2;
                    end
                    3'd2: begin
                        w[round_cnt * 4 + 2] <= w[round_cnt * 4 + 2 - 1] ^ w[round_cnt * 4 + 2 - 4];
                        word_idx <= 3'd3;
                    end
                    3'd3: begin
                        w[round_cnt * 4 + 3] <= w[round_cnt * 4 + 3 - 1] ^ w[round_cnt * 4 + 3 - 4];
                        word_idx <= 3'd0;
                        if (round_cnt == NUM_ROUNDS) begin
                            // Key expansion complete. Assemble encryption round keys.
                            // Note: w[] values used here are those computed by end of
                            // the previous cycle; the final word (round_cnt*4+3) just
                            // computed this cycle is not yet visible, so assembly is
                            // deferred one more cycle via KEY_DEC_START's use of w[].
                            state <= KEY_DEC_START;
                        end else begin
                            round_cnt <= round_cnt + 4'd1;
                        end
                    end
                endcase
            end

            KEY_DEC_START: begin
                // At this point all 44 words (w[0]..w[43]) are valid.
                for (j = 0; j < 11; j = j + 1) begin
                    round_key_enc[j*128 +: 128] <= {w[j*4], w[j*4+1], w[j*4+2], w[j*4+3]};
                end
                if (DECRYPT != 0) begin
                    // Decryption key[10] = Encryption key[0], key[0] = Encryption key[10]
                    round_key_dec[10*128 +: 128] <= {w[0], w[1], w[2], w[3]};
                    round_key_dec[0*128 +: 128]  <= {w[40], w[41], w[42], w[43]};

                    // Kick off InvMixColumns pipeline for decryption round key 1,
                    // derived from encryption round key 9 (words 36..39)
                    dec_round <= 4'd1;
                    dec_src_key <= {w[36], w[37], w[38], w[39]};
                    dec_word_stage <= 2'd0;
                    imc_col_in <= w[36];
                    state <= KEY_DEC_WAIT;
                end else begin
                    state <= KEY_DONE;
                    key_ready <= 1'b1;
                end
            end

            KEY_DEC_WAIT: begin
                // One-cycle wait state for InvMixColumns combinational result
                // to become valid before latching.
                state <= KEY_DEC_LATCH;
            end

            KEY_DEC_LATCH: begin
                case (dec_word_stage)
                    2'd0: begin
                        dec_result[127:96] <= imc_col_out;
                        imc_col_in <= dec_src_key[95:64];
                        dec_word_stage <= 2'd1;
                        state <= KEY_DEC_WAIT;
                    end
                    2'd1: begin
                        dec_result[95:64] <= imc_col_out;
                        imc_col_in <= dec_src_key[63:32];
                        dec_word_stage <= 2'd2;
                        state <= KEY_DEC_WAIT;
                    end
                    2'd2: begin
                        dec_result[63:32] <= imc_col_out;
                        imc_col_in <= dec_src_key[31:0];
                        dec_word_stage <= 2'd3;
                        state <= KEY_DEC_WAIT;
                    end
                    2'd3: begin
                        dec_result[31:0] <= imc_col_out;
                        round_key_dec[dec_round*128 +: 128] <= {dec_result[127:32], imc_col_out};
                        if (dec_round == 4'd9) begin
                            state <= KEY_DONE;
                            key_ready <= 1'b1;
                        end else begin
                            dec_round <= dec_round + 4'd1;
                            // Encryption key index for next decryption round:
                            // dec_round=1 -> enc key 9, dec_round=2 -> enc key 8, ...
                            // next dec_round = dec_round+1 -> enc key (10 - (dec_round+1)) = 9 - dec_round
                            dec_src_key <= round_key_enc[(9 - dec_round)*128 +: 128];
                            imc_col_in <= round_key_enc[(9 - dec_round)*128 + 96 +: 32];
                            dec_word_stage <= 2'd0;
                            state <= KEY_DEC_WAIT;
                        end
                    end
                endcase
            end

            KEY_DONE: begin
                key_ready <= 1'b1;
                if (key_valid_pulse) begin
                    // Reload key
                    w[0] <= key[127:96];
                    w[1] <= key[95:64];
                    w[2] <= key[63:32];
                    w[3] <= key[31:0];
                    round_cnt <= 4'd1;
                    word_idx <= 3'd0;
                    state <= KEY_EXPAND;
                    key_ready <= 1'b0;
                    dec_round <= 4'd0;
                end
            end
        endcase
    end
end

endmodule
