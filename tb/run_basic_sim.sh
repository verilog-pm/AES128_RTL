#!/bin/bash
# Icarus Verilog simulation script for AES basic operations testbench

set -e

echo "========================================"
echo "  Compiling AES Basic Operations Testbench"
echo "========================================"

# Compile Verilog files
iverilog -g2005-sv \
    -o basic_ops_tb \
    ../rtl/add_round_key.v \
    ../rtl/sbox.v \
    ../rtl/inv_sbox.v \
    ../rtl/gf_mult.v \
    basic_ops_tb.v

echo ""
echo "========================================"
echo "  Running Simulation"
echo "========================================"

# Run simulation with VCD output for waveform viewing
vvp basic_ops_tb

echo ""
echo "Simulation complete. Use GTKWave to view waveforms:"
echo "  gtkwave basic_ops_tb.vcd basic_ops_tb.gtkw &"
