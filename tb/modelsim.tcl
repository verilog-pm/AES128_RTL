# =============================================================================
# ModelSim Project File for AES-128
# =============================================================================

# Project directory
set PROJECT_DIR "C:/workspace/temp/CursorGen/code/aes128"

# Work library
set WORK_DIR "$PROJECT_DIR/tb/work"

# Source files
set RTL_FILES {
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
}

set TB_FILES {
    "$PROJECT_DIR/tb/basic_ops_tb.v"
    "$PROJECT_DIR/tb/mix_columns_tb.v"
    "$PROJECT_DIR/tb/key_schedule_tb.v"
    "$PROJECT_DIR/tb/aes128_top_tb.v"
}

# Create work directory
file mkdir "$PROJECT_DIR/tb/work"

# Quit function
proc quit_sim {} {
    if {[catch {quit -force} err]} {
        puts "Note: $err"
    }
}

# Compile all files
proc compile_all {} {
    global PROJECT_DIR RTL_FILES TB_FILES WORK_DIR
    
    puts "========================================"
    puts "  Compiling AES-128 RTL Files"
    puts "========================================"
    
    foreach file $RTL_FILES {
        if {[file exists $file]} {
            puts "Compiling: $file"
            vlog -work work "$file"
        } else {
            puts "WARNING: File not found: $file"
        }
    }
    
    puts ""
    puts "========================================"
    puts "  Compiling Testbench Files"
    puts "========================================"
    
    foreach file $TB_FILES {
        if {[file exists $file]} {
            puts "Compiling: $file"
            vlog -work work "$file"
        } else {
            puts "WARNING: File not found: $file"
        }
    }
    
    puts ""
    puts "Compilation complete."
}

# Run basic operations testbench
proc run_basic_test {} {
    puts ""
    puts "========================================"
    puts "  Running Basic Operations Testbench"
    puts "========================================"
    vsim -t 1ps -L work -do "run -all; quit -force" work.basic_ops_tb
}

# Run mix columns testbench
proc run_mix_test {} {
    puts ""
    puts "========================================"
    puts "  Running MixColumns Testbench"
    puts "========================================"
    vsim -t 1ps -L work -do "run -all; quit -force" work.mix_columns_tb
}

# Run key schedule testbench
proc run_ks_test {} {
    puts ""
    puts "========================================"
    puts "  Running Key Schedule Testbench"
    puts "========================================"
    vsim -t 1ps -L work -do "run -all; quit -force" work.key_schedule_tb
}

# Run top-level testbench
proc run_top_test {} {
    puts ""
    puts "========================================"
    puts "  Running AES-128 Top Testbench"
    puts "========================================"
    vsim -t 1ps -L work -do "run -all; quit -force" work.aes128_top_tb
}

# Run all tests
proc run_all {} {
    compile_all
    run_basic_test
    run_mix_test
    run_ks_test
    run_top_test
}

puts "ModelSim project loaded."
puts "Available commands:"
puts "  compile_all    - Compile all RTL and testbench files"
puts "  run_basic_test - Run basic operations testbench"
puts "  run_mix_test   - Run MixColumns testbench"
puts "  run_ks_test    - Run key schedule testbench"
puts "  run_top_test   - Run top-level testbench"
puts "  run_all        - Run all tests"
