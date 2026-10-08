# =============================================================================
# XDC Constraints for AES-128 on Xilinx Zynq-7000 (XC7Z100-FFG900)
# =============================================================================

# =============================================================================
# Clock Constraint
# =============================================================================
create_clock -period 8.000 -name clk -waveform {0.000 4.000} [get_ports clk]

# =============================================================================
# Input Constraints
# =============================================================================

# Reset signal
set_false_path -from [get_ports rst_n]

# Mode selection
set_false_path -from [get_ports mode]
set_false_path -from [get_ports op_mode[*]]

# Key signals
set_false_path -from [get_ports key_valid]
set_false_path -from [get_ports key[*]]

# IV / initial counter signals (CBC/CTR)
set_false_path -from [get_ports iv_valid]
set_false_path -from [get_ports iv[*]]

# Data input signals
set_false_path -from [get_ports data_in_valid]
set_false_path -from [get_ports data_in[*]]

# Output ready signal
set_false_path -from [get_ports data_out_ready]

# =============================================================================
# Output Constraints
# =============================================================================

# Key ready signal
set_false_path -to [get_ports key_ready]

# IV ready signal (CBC/CTR)
set_false_path -to [get_ports iv_ready]

# Data input ready signal
set_false_path -to [get_ports data_in_ready]

# Data output signals
set_false_path -to [get_ports data_out[*]]
set_false_path -to [get_ports data_out_valid]

# =============================================================================
# I/O Standard
# =============================================================================

# All ports use LVCMOS18 (1.8V) by default
# Adjust based on your board requirements
set_property IOSTANDARD LVCMOS18 [get_ports clk]
set_property IOSTANDARD LVCMOS18 [get_ports rst_n]
set_property IOSTANDARD LVCMOS18 [get_ports mode]
set_property IOSTANDARD LVCMOS18 [get_ports op_mode[*]]
set_property IOSTANDARD LVCMOS18 [get_ports key_valid]
set_property IOSTANDARD LVCMOS18 [get_ports key[*]]
set_property IOSTANDARD LVCMOS18 [get_ports iv_valid]
set_property IOSTANDARD LVCMOS18 [get_ports iv[*]]
set_property IOSTANDARD LVCMOS18 [get_ports data_in_valid]
set_property IOSTANDARD LVCMOS18 [get_ports data_in[*]]
set_property IOSTANDARD LVCMOS18 [get_ports data_out_ready]
set_property IOSTANDARD LVCMOS18 [get_ports key_ready]
set_property IOSTANDARD LVCMOS18 [get_ports iv_ready]
set_property IOSTANDARD LVCMOS18 [get_ports data_in_ready]
set_property IOSTANDARD LVCMOS18 [get_ports data_out[*]]
set_property IOSTANDARD LVCMOS18 [get_ports data_out_valid]

# =============================================================================
# Physical Constraints
# =============================================================================

# Clock pin location (adjust for your board)
# Example: Bank 34, pin E12 (common Zynq PS_CLK location)
# set_property PACKAGE_PIN E12 [get_ports clk]

# Optional: Drive strength
set_property DRIVE 8 [get_ports key_ready]
set_property DRIVE 8 [get_ports iv_ready]
set_property DRIVE 8 [get_ports data_in_ready]
set_property DRIVE 8 [get_ports data_out_valid]
set_property DRIVE 8 [get_ports data_out[*]]

# =============================================================================
# Timing Exceptions
# =============================================================================

# Note: Pipeline paths are already constrained by the main clock constraint
# No additional timing exceptions needed - removed redundant set_false_path constraint
