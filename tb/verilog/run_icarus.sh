#!/bin/bash
# Compile and run every Verilog testbench with Icarus Verilog.
# Vector files are read from this directory. They are not regenerated.

set -euo pipefail
cd "$(dirname "$0")"

tests=(
    basic_ops_tb
    mix_columns_tb
    key_schedule_tb
    aes128_top_tb
    aes128_cross_check_tb
    aes128_streaming_tb
    aes128_streaming_cross_check_tb
    aes128_mode_cross_check_tb
    aes128_width_tb
)

for name in "${tests[@]}"; do
    echo "========================================"
    echo "  ${name}"
    echo "========================================"
    iverilog -g2005-sv -I. -o "${name}.vvp" ../../rtl/*.v "${name}.v"
    vvp "${name}.vvp"
    rm -f "${name}.vvp"
done

echo "All Icarus tests finished."
