# =============================================================================
# XDC for compiling aes128_top by itself on XC7Z100-FFG900
# =============================================================================
#
# These false paths keep unconstrained top-level ports from failing timing
# when the core is synthesized without a board. A design that instantiates
# aes128_top should replace this file with real input and output delays.
# Package pins are intentionally unset: key and IV alone are 256 ports.

# 100 MHz target for the standalone core.
create_clock -period 10.000 -name clk -waveform {0.000 5.000} [get_ports clk]

set_false_path -from [get_ports rst_n]
set_false_path -from [get_ports op_mode[*]]
set_false_path -from [get_ports key_valid]
set_false_path -from [get_ports key[*]]
set_false_path -from [get_ports iv_valid]
set_false_path -from [get_ports iv[*]]
set_false_path -from [get_ports data_in_valid]
set_false_path -from [get_ports data_in_last]
set_false_path -from [get_ports data_in_keep[*]]
set_false_path -from [get_ports data_in[*]]
set_false_path -from [get_ports data_out_ready]

set_false_path -to [get_ports data_in_ready]
set_false_path -to [get_ports data_out[*]]
set_false_path -to [get_ports data_out_valid]
set_false_path -to [get_ports data_out_last]
set_false_path -to [get_ports data_out_keep[*]]

set_property IOSTANDARD LVCMOS18 [get_ports clk]
set_property IOSTANDARD LVCMOS18 [get_ports rst_n]
set_property IOSTANDARD LVCMOS18 [get_ports op_mode[*]]
set_property IOSTANDARD LVCMOS18 [get_ports key_valid]
set_property IOSTANDARD LVCMOS18 [get_ports key[*]]
set_property IOSTANDARD LVCMOS18 [get_ports iv_valid]
set_property IOSTANDARD LVCMOS18 [get_ports iv[*]]
set_property IOSTANDARD LVCMOS18 [get_ports data_in_valid]
set_property IOSTANDARD LVCMOS18 [get_ports data_in_last]
set_property IOSTANDARD LVCMOS18 [get_ports data_in_keep[*]]
set_property IOSTANDARD LVCMOS18 [get_ports data_in[*]]
set_property IOSTANDARD LVCMOS18 [get_ports data_out_ready]
set_property IOSTANDARD LVCMOS18 [get_ports data_in_ready]
set_property IOSTANDARD LVCMOS18 [get_ports data_out[*]]
set_property IOSTANDARD LVCMOS18 [get_ports data_out_valid]
set_property IOSTANDARD LVCMOS18 [get_ports data_out_last]
set_property IOSTANDARD LVCMOS18 [get_ports data_out_keep[*]]

set_property DRIVE 8 [get_ports data_in_ready]
set_property DRIVE 8 [get_ports data_out_valid]
set_property DRIVE 8 [get_ports data_out_last]
set_property DRIVE 8 [get_ports data_out[*]]
set_property DRIVE 8 [get_ports data_out_keep[*]]
