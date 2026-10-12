# NIST top-level smoke test. From this directory:
#   vsim -c -do run_test.tcl

set script_dir [file dirname [file normalize [info script]]]
set rtl_dir [file normalize [file join $script_dir .. .. rtl]]
set tb_dir [file normalize [file join $script_dir .. verilog]]

cd $tb_dir
if {![file exists work]} {
    vlib work
}
vlog -sv +incdir+$tb_dir {*}[glob -directory $rtl_dir *.v] [file join $tb_dir aes128_top_tb.v]
vsim -t 1ps -voptargs=+acc work.aes128_top_tb -do "run -all; quit -f"
