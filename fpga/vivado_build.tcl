# =============================================================================
# Vivado Build Script for AES-128
# Target: Xilinx Zynq-7000 (XC7Z100)
# =============================================================================

# Create project
create_project aes128_prj ./vivado_prj -part xc7z100ffg900-2 -force

# Set target language
set_property target_language Verilog [current_project]

# Add source files
add_files [glob ../rtl/*.v]

# Add constraints file
add_files -fileset constrs_1 aes128_xdc.xdc

# Set file properties for synthesis
set_property used_in_synthesis true [get_files *.v]

# =============================================================================
# Synthesis Settings
# =============================================================================
set_property strategy Flow_PerfOptimized_high [get_runs synth_1]

# Set synthesis properties
set_property STEPS.SYNTH_DESIGN.ARGS.FANOUT_LIMIT 10000 [get_runs synth_1]
set_property STEPS.SYNTH_DESIGN.ARGS.RETIMING true [get_runs synth_1]
# set_property STEPS.SYNTH_DESIGN.ARGS.OBUF_DRIVE_IF_NEG75 false [get_runs synth_1]  # Not supported in Vivado 2018.3

# =============================================================================
# Implementation Settings
# =============================================================================
set_property strategy Performance_ExplorePostRoutePhysOpt [get_runs impl_1]

# Enable physical optimization
# set_property STEPS.POST_ROUTE_PHYS_OPT_DESIGN.ARGS.INSERT_ECO false [get_runs impl_1]  # Not supported in Vivado 2018.3

# =============================================================================
# Run Synthesis
# =============================================================================
puts "Running synthesis..."
launch_runs synth_1 -jobs 4
wait_on_run synth_1

if {[get_property PROGRESS [get_runs synth_1]] != "100%"} {
    puts "ERROR: Synthesis failed"
    exit 1
}

open_run synth_1 -name synth_1

# Report timing
report_timing_summary -file ./timing_synth.txt
report_utilization -file ./utilization_synth.txt
report_resources -file ./resources_synth.txt

# =============================================================================
# Run Implementation
# =============================================================================
puts "Running implementation..."
launch_runs impl_1 -jobs 4
wait_on_run impl_1

if {[get_property PROGRESS [get_runs impl_1]] != "100%"} {
    puts "ERROR: Implementation failed"
    exit 1
}

open_run impl_1 -name impl_1

# Report timing and utilization
report_timing_summary -file ./timing_impl.txt
report_utilization -file ./utilization_impl.txt
report_drc -file ./drc.txt
report_power -file ./power.txt

# =============================================================================
# Generate Bitstream
# =============================================================================
puts "Generating bitstream..."
launch_runs impl_1 -to_step write_bitstream -jobs 4
wait_on_run impl_1

if {[get_property PROGRESS [get_runs impl_1]] != "100%"} {
    puts "ERROR: Bitstream generation failed"
    exit 1
}

puts "Build complete!"
puts "Bitstream: ./vivado_prj/[project].runs/impl_1/*.bit"
puts "Reports:"
puts "  - timing_synth.txt: Synthesis timing report"
puts "  - timing_impl.txt: Implementation timing report"
puts "  - utilization_synth.txt: Synthesis resource utilization"
puts "  - utilization_impl.txt: Implementation resource utilization"
