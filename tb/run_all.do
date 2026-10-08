# =============================================================================
# Run All Tests Do File
# =============================================================================

puts ""
puts "========================================"
puts "  Running All AES-128 Tests"
puts "========================================"

# =============================================================================
# Test 1: Basic Operations
# =============================================================================
puts ""
puts "--- Test 1: Basic Operations ---"
vsim -t 1ps -voptargs="+acc" -L work work.basic_ops_tb
run -all
quit -force

# =============================================================================
# Test 2: MixColumns
# =============================================================================
puts ""
puts "--- Test 2: MixColumns ---"
vsim -t 1ps -voptargs="+acc" -L work work.mix_columns_tb
run -all
quit -force

# =============================================================================
# Test 3: Key Schedule
# =============================================================================
puts ""
puts "--- Test 3: Key Schedule ---"
vsim -t 1ps -voptargs="+acc" -L work work.key_schedule_tb
run -all
quit -force

# =============================================================================
# Test 4: AES-128 Top (Encryption/Decryption)
# =============================================================================
puts ""
puts "--- Test 4: AES-128 Top Module ---"
vsim -t 1ps -voptargs="+acc" -L work work.aes128_top_tb
run -all
quit -force

puts ""
puts "========================================"
puts "  All Tests Complete"
puts "========================================"
