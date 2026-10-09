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
- `key_valid`: High to latch `key`. The core installs that key once the cipher is idle; there is no `key_ready` pin.
- `op_mode[1:0]`: Block cipher mode select — 00=ECB, 01=CBC, 10=CTR
- parameter `mode`: 0 = encrypt instance (also used for CTR decrypt), 1 = decrypt instance. Only one pipeline is instantiated.
- `iv[127:0]`: Initial IV (CBC) / initial counter value (CTR); ignored in ECB
- `iv_valid`: High to latch `iv`. The core writes it into the chain register once idle; there is no `iv_ready` pin.
- `data_in[DATA_WIDTH-1:0]`: Input data. `DATA_WIDTH` is 32 (default) or 64
- `data_in_valid`: Input data valid
- `data_in_last`: Last beat of this AES block (may end the block early)
- `data_in_keep[DATA_WIDTH/8-1:0]`: Byte enable, `keep[i]` qualifies `data_in[8*i +: 8]`
- `data_out_ready`: Downstream ready to receive

### Outputs
- `data_in_ready`: High when module can accept new data
- `data_out[DATA_WIDTH-1:0]`: Output data
- `data_out_valid`: High when output data is valid
- `data_out_last`: Last beat corresponding to `data_in_last`
- `data_out_keep[DATA_WIDTH/8-1:0]`: Byte enable of the output beat

## Performance

- **Throughput**: external bus is `DATA_WIDTH` bits/cycle (default 32). The internal pipeline is still 1 AES block/cycle for ECB, CTR, and CBC-decrypt once a block is packed.
  CBC-encrypt is inherently serial (each block depends on the previous
  block's ciphertext) and only reaches ~1 block per pipeline latency (11
  cycles).
- **Latency**: 11 clock cycles per block
- **Target Frequency**: 100 MHz
- **Estimated Resources**:
  - LUT: ~15,000-20,000
  - FF: ~2,500-3,500
  - BRAM: 0 (using distributed ROM for S-boxes)
