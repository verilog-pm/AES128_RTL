# =============================================================================
# Standalone synthesis for aes128_top
# Target: Xilinx Zynq-7000 (XC7Z100-FFG900-2)
#
# Run from fpga/:
#   vivado -mode batch -source vivado_synth.tcl
#   vivado -mode batch -source vivado_synth.tcl -tclargs ./vivado_prj
#
# Stops after synthesis and writes reports under ./reports. This core has no
# PACKAGE_PIN constraints, so the script does not place, route, or write a
# bitstream. aes128_top defaults are mode=0 (encrypt) and DATA_WIDTH=32.
# =============================================================================

set proj_dir "./vivado_prj"
if {[llength $argv] > 0} {
    set proj_dir [lindex $argv 0]
}

create_project aes128_prj $proj_dir -part xc7z100ffg900-2 -force
set_property target_language Verilog [current_project]
add_files [glob ../rtl/*.v]
add_files -fileset constrs_1 aes128_xdc.xdc
set_property top aes128_top [current_fileset]
update_compile_order -fileset sources_1

set_property strategy Flow_PerfOptimized_high [get_runs synth_1]
set_property STEPS.SYNTH_DESIGN.ARGS.FANOUT_LIMIT 10000 [get_runs synth_1]
set_property STEPS.SYNTH_DESIGN.ARGS.RETIMING true [get_runs synth_1]

puts "Running synthesis..."
launch_runs synth_1 -jobs 4
wait_on_run synth_1

if {[get_property PROGRESS [get_runs synth_1]] != "100%"} {
    puts "ERROR: Synthesis failed"
    exit 1
}

open_run synth_1 -name synth_1
file mkdir ./reports
report_timing_summary -file ./reports/timing_synth.rpt
report_utilization -file ./reports/utilization_synth.rpt

puts "Synthesis complete."
puts "Reports:"
puts "  ./reports/timing_synth.rpt"
puts "  ./reports/utilization_synth.rpt"
exit 0
