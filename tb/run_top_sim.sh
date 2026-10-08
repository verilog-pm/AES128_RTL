#!/bin/bash
# Compile and run AES-128 top-level testbench

set -e

echo "========================================"
echo "  Compiling AES-128 Top Testbench"
echo "========================================"

RTL_DIR="../rtl"
TB_DIR="."

# Compile all required files
iverilog -g2005-sv \
    -o aes128_sim \
    $RTL_DIR/add_round_key.v \
    $RTL_DIR/sbox.v \
    $RTL_DIR/inv_sbox.v \
    $RTL_DIR/gf_mult.v \
    $RTL_DIR/mix_columns.v \
    $RTL_DIR/inv_mix_columns.v \
    $RTL_DIR/key_schedule.v \
    $RTL_DIR/aes128_pipeline_enc.v \
    $RTL_DIR/aes128_pipeline_dec.v \
    $RTL_DIR/aes128_top.v \
    $TB_DIR/aes128_top_tb.v

echo ""
echo "========================================"
echo "  Running Simulation"
echo "========================================"

vvp aes128_sim

echo ""
echo "Simulation complete."
