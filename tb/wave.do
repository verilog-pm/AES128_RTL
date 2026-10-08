# =============================================================================
# Waveform Configuration for ModelSim
# =============================================================================

onerror {resume}
quietly WaveActivateNextPane {} 0

# Add signals
add wave -noupdate -divider {Top Level Signals}
add wave -noupdate /aes128_top_tb/tb_clk
add wave -noupdate /aes128_top_tb/tb_rst_n
add wave -noupdate /aes128_top_tb/tb_mode
add wave -noupdate /aes128_top_tb/tb_key_valid
add wave -noupdate /aes128_top_tb/tb_key_ready
add wave -noupdate /aes128_top_tb/tb_data_in_valid
add wave -noupdate /aes128_top_tb/tb_data_in_ready
add wave -noupdate /aes128_top_tb/tb_data_out_valid
add wave -noupdate /aes128_top_tb/tb_data_out_ready

add wave -noupdate -radix hexadecimal /aes128_top_tb/tb_key
add wave -noupdate -radix hexadecimal /aes128_top_tb/tb_data_in
add wave -noupdate -radix hexadecimal /aes128_top_tb/tb_data_out

add wave -noupdate -divider {Key Schedule}
add wave -noupdate /aes128_top_tb/dut/key_sched/state
add wave -noupdate /aes128_top_tb/dut/key_sched/key_ready

add wave -noupdate -divider {Encryption Pipeline}
add wave -noupdate /aes128_top_tb/dut/enc_pipe/stall
add wave -noupdate /aes128_top_tb/dut/enc_pipe/pipe_en
add wave -noupdate /aes128_top_tb/dut/enc_pipe/data_in_ready
add wave -noupdate /aes128_top_tb/dut/enc_pipe/data_out_valid

add wave -noupdate -divider {Decryption Pipeline}
add wave -noupdate /aes128_top_tb/dut/dec_pipe/stall
add wave -noupdate /aes128_top_tb/dut/dec_pipe/pipe_en
add wave -noupdate /aes128_top_tb/dut/dec_pipe/data_in_ready
add wave -noupdate /aes128_top_tb/dut/dec_pipe/data_out_valid

# Configuration
TreeUpdate [SetDefaultTree]
WaveRestoreCursors {{Cursor 1} {0 ps} 0}
quietly wave cursor active 1
configure wave -namecolwidth 300
configure wave -valuecolwidth 100
configure wave -justifyvalue left
configure wave -signalnamewidth 0
configure wave -snapdistance 10
configure wave -datasetprefix 0
configure wave -rowmargin 4
configure wave -childrowmargin 2
configure wave -gridoffset 0
configure wave -gridperiod 1
configure wave -griddelta 40
configure wave -timeline 0
configure wave -timelineunits ns
update

# Run simulation
run -all
