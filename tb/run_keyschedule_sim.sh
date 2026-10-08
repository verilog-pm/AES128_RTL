#!/bin/bash
# Compile and run key schedule testbench

set -e

echo "========================================"
echo "  Compiling AES Key Schedule Testbench"
echo "========================================"

RTL_DIR="../rtl"
TB_DIR="."

# Compile all required files
iverilog -g2005-sv \
    -o key_schedule_tb \
    $RTL_DIR/sbox.v \
    $RTL_DIR/inv_sbox.v \
    $RTL_DIR/gf_mult.v \
    $RTL_DIR/inv_mix_columns.v \
    $RTL_DIR/key_schedule.v \
    key_schedule_tb.v

echo ""
echo "========================================"
echo "  Running Simulation"
echo "========================================"

vvp key_schedule_tb
