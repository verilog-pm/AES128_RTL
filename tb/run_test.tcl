vlib work
vlog -sv ../rtl/*.v ./aes128_top_tb.v
vsim -t 1ps -voptargs="+acc" work.aes128_top_tb -do "run -all; quit -f"
