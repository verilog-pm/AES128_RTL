# AES-128 Verilog Implementation for Xilinx 7z100

## Project Structure

```
aes128/
├── rtl/
│   ├── aes128_top.v           # Top-level module
│   ├── aes128_pipeline_enc.v  # Encryption pipeline
│   ├── aes128_pipeline_dec.v  # Decryption pipeline
│   ├── key_schedule.v         # Key expansion
│   ├── sbox.v                 # S-box lookup
│   ├── inv_sbox.v             # Inverse S-box
│   ├── mix_columns.v           # MixColumns transformation
│   ├── inv_mix_columns.v       # Inverse MixColumns
│   ├── gf_mult.v               # GF(2^8) multiplier
│   └── add_round_key.v         # AddRoundKey (XOR)
├── tb/
│   ├── aes128_top_tb.v        # Top-level testbench
│   ├── basic_ops_tb.v         # Basic operations testbench
│   ├── mix_columns_tb.v       # MixColumns testbench
│   ├── key_schedule_tb.v       # Key schedule testbench
│   └── run_*.sh               # Simulation scripts
├── fpga/
│   ├── vivado_build.tcl        # Vivado build script
│   └── aes128_xdc.xdc          # Constraints file
└── docs/
    └── (architecture documentation)
```

## Building

### RTL Simulation (Icarus Verilog)

```bash
cd aes128/tb
iverilog -g2005-sv -o aes128_sim \
    ../rtl/*.v \
    aes128_top_tb.v
vvp aes128_sim
```

### Vivado FPGA Build

```bash
cd aes128/fpga
source /path/to/vivado/settings64.sh
vivado -mode batch -source vivado_build.tcl
```

## Interface

### Inputs
- `clk`: System clock (100 MHz recommended)
- `rst_n`: Active-low asynchronous reset
- `key[127:0]`: 128-bit AES key
- `key_valid`: Pulsed high to trigger key expansion
- `mode`: 0 = encrypt, 1 = decrypt (ignored in CTR mode)
- `op_mode[1:0]`: Block cipher mode select — 00=ECB, 01=CBC, 10=CTR
- `iv[127:0]`: Initial IV (CBC) / initial counter value (CTR); ignored in ECB
- `iv_valid`: Pulsed high to load `iv`; only sampled when `iv_ready` is high
- `data_in[127:0]`: Input data (plaintext or ciphertext)
- `data_in_valid`: Input data valid signal
- `data_out_ready`: Downstream ready to receive

### Outputs
- `key_ready`: High when round keys are ready
- `iv_ready`: High when the pipeline is fully drained and a new `iv` can be loaded
- `data_in_ready`: High when module can accept new data
- `data_out[127:0]`: Output data
- `data_out_valid`: High when output data is valid

## Performance

- **Throughput**: 1 block per cycle for ECB, CTR, and CBC-decrypt (128 bits/cycle).
  CBC-encrypt is inherently serial (each block depends on the previous
  block's ciphertext) and only reaches ~1 block per pipeline latency (11
  cycles).
- **Latency**: 11 clock cycles per block
- **Target Frequency**: 100 MHz
- **Estimated Resources**:
  - LUT: ~15,000-20,000
  - FF: ~2,500-3,500
  - BRAM: 0 (using distributed ROM for S-boxes)
