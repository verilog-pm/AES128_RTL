# =============================================================================
# ModelSim Do File for AES-128 Simulation
# =============================================================================

# Set resolution
vsim -t 1ps

# Create work library if not exists
if {![file exists work]} {
    vlib work
}

# =============================================================================
# Step 1: Compile RTL files
# =============================================================================
puts ""
puts "========================================"
puts "  Step 1: Compiling RTL Files"
puts "========================================"

set rtl_files {
    ../rtl/add_round_key.v
    ../rtl/sbox.v
    ../rtl/inv_sbox.v
    ../rtl/gf_mult.v
    ../rtl/mix_columns.v
    ../rtl/inv_mix_columns.v
    ../rtl/key_schedule.v
    ../rtl/aes128_pipeline_enc.v
    ../rtl/aes128_pipeline_dec.v
    ../rtl/aes128_top.v
}

foreach file $rtl_files {
    if {[file exists $file]} {
        puts "Compiling: $file"
        vlog -work work $file
    } else {
        puts "ERROR: File not found: $file"
    }
}

# =============================================================================
# Step 2: Compile testbench files
# =============================================================================
puts ""
puts "========================================"
puts "  Step 2: Compiling Testbench Files"
puts "========================================"

set tb_files {
    basic_ops_tb.v
    mix_columns_tb.v
    key_schedule_tb.v
    aes128_top_tb.v
}

foreach file $tb_files {
    if {[file exists $file]} {
        puts "Compiling: $file"
        vlog -work work $file
    } else {
        puts "ERROR: File not found: $file"
    }
}

puts ""
puts "========================================"
puts "  Compilation Complete"
puts "========================================"
puts ""
puts "Available testbenches:"
puts "  - work.basic_ops_tb"
puts "  - work.mix_columns_tb"
puts "  - work.key_schedule_tb"
puts "  - work.aes128_top_tb"
puts ""
puts "To run a testbench, use:"
puts "  vsim -do \"run -all; quit -f\" work.<testbench_name>"
