#!/bin/bash
# =============================================================================
# ModelSim Simulation Script for AES-128 (Linux/macOS/WSL)
# =============================================================================

set -e

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TB_DIR="$(pwd)"

echo "========================================"
echo "  AES-128 ModelSim Simulation"
echo "========================================"
echo ""

# Detect ModelSim installation
MODELSIM_PATHS=(
    "/opt/modelsim/modeltech/bin"
    "/usr/modelsim/bin"
    "$HOME/modeltech/bin"
    "$HOME/intelFPGA_lite/18.1/modelsim_ase/linux"
    "$HOME/intelFPGA/18.1/modelsim_ae/linux"
    "$QUESTA_HOME/linux_x86_64"
)

VLOG=""
VSIM=""
for path in "${MODELSIM_PATHS[@]}"; do
    if [ -x "$path/vlog" ]; then
        VLOG="$path/vlog"
        VSIM="$path/vsim"
        echo "Found ModelSim at: $path"
        break
    fi
done

if [ -z "$VSIM" ]; then
    echo "ERROR: ModelSim not found!"
    echo "Please install ModelSim or update the search paths in this script."
    exit 1
fi

# Create work directory
echo ""
echo "Creating work library..."
rm -rf work
mkdir -p work

# Compile RTL files
echo ""
echo "========================================"
echo "  Compiling RTL Files"
echo "========================================"

RTL_FILES=(
    "$PROJECT_DIR/rtl/add_round_key.v"
    "$PROJECT_DIR/rtl/sbox.v"
    "$PROJECT_DIR/rtl/inv_sbox.v"
    "$PROJECT_DIR/rtl/gf_mult.v"
    "$PROJECT_DIR/rtl/mix_columns.v"
    "$PROJECT_DIR/rtl/inv_mix_columns.v"
    "$PROJECT_DIR/rtl/key_schedule.v"
    "$PROJECT_DIR/rtl/aes128_pipeline_enc.v"
    "$PROJECT_DIR/rtl/aes128_pipeline_dec.v"
    "$PROJECT_DIR/rtl/aes128_top.v"
)

for file in "${RTL_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  Compiling: $(basename $file)"
        $VLOG -work work "$file"
    else
        echo "  WARNING: File not found: $file"
    fi
done

# Compile testbench files
echo ""
echo "========================================"
echo "  Compiling Testbench Files"
echo "========================================"

TB_FILES=(
    "basic_ops_tb.v"
    "mix_columns_tb.v"
    "key_schedule_tb.v"
    "aes128_top_tb.v"
)

for file in "${TB_FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "  Compiling: $file"
        $VLOG -work work "$file"
    else
        echo "  WARNING: File not found: $file"
    fi
done

echo ""
echo "========================================"
echo "  Compilation Complete"
echo "========================================"
echo ""
echo "To run a testbench, use:"
echo ""
echo "  $VSIM -do 'run -all; quit -f' work.basic_ops_tb"
echo "  $VSIM -do 'run -all; quit -f' work.mix_columns_tb"
echo "  $VSIM -do 'run -all; quit -f' work.key_schedule_tb"
echo "  $VSIM -do 'run -all; quit -f' work.aes128_top_tb"
echo ""
echo "Or run all tests in GUI mode:"
echo ""
echo "  $VSIM work.aes128_top_tb"
echo ""
echo "Or run in batch mode with wave:"
echo ""
echo "  $VSIM -do 'do wave.do; run -all; quit -f' work.aes128_top_tb"
