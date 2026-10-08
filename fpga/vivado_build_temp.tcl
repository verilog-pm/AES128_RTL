# =============================================================================
# Vivado Build Script for AES-128 (Temporary - different project name)
# Target: Xilinx Zynq-7000 (XC7Z100)
# =============================================================================

# Create project with different name to avoid lock
create_project aes128_prj_fixed ./vivado_prj_fixed -part xc7z100ffg900-2 -force

# Set target language
set_property target_language Verilog [current_project]

# Add source files
add_files [glob ../rtl/*.v]

# Add constraints file
add_files -fileset constrs_1 aes128_xdc.xdc

# Set file properties for synthesis
set_property used_in_synthesis true [get_files *.v]

# Set top module
set_property top aes128_top [current_fileset]

# Update to set top and compile order
update_compile_order -fileset sources_1

# Run synthesis
launch_runs synth_1 -jobs 4
wait_on_run synth_1

# Check synthesis status
if {[get_property PROGRESS [get_runs synth_1]] != "100%"} {
    puts "ERROR: Synthesis failed"
    exit 1
}

# Open synthesized design for timing analysis
open_run synth_1 -name synth_1

# Generate timing and utilization reports
report_timing_summary -file ./timing_synth.txt
report_utilization -file ./utilization_synth.txt

puts "Synthesis completed successfully"
exit 0
