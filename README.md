# AES-128 Verilog Implementation

基于 FIPS-197 标准的 AES-128 加密/解密流水线实现，支持连续数据流处理。

## 架构特性

- **流水线架构**: 10 级全展开流水线，稳态吞吐 1 block/cycle (ECB / CTR / CBC 解密)
- **加密/解密模式**: 通过 mode 信号切换，支持独立加解密
- **工作模式 (op_mode)**: 支持 ECB、CBC、CTR 三种 NIST SP 800-38A 分组密码工作模式
- **接口协议**: valid/ready 握手流式接口
- **密钥扩展**: 芯片内一次性完成 11 组轮密钥扩展并缓存
- **目标平台**: Xilinx Zynq-7000 (7z100) FPGA

## 目录结构

```
aes128/
├── rtl/                      # RTL 源码
│   ├── aes128_top.v          # 顶层模块
│   ├── aes128_pipeline_enc.v # 加密流水线
│   ├── aes128_pipeline_dec.v # 解密流水线
│   ├── key_schedule.v        # 密钥扩展
│   ├── sbox.v                # S-box 查找表
│   ├── inv_sbox.v            # 逆 S-box 查找表
│   ├── mix_columns.v          # MixColumns 变换
│   ├── inv_mix_columns.v      # 逆 MixColumns 变换
│   ├── gf_mult.v              # GF(2^8) 乘法器
│   └── add_round_key.v        # AddRoundKey (XOR)
├── tb/                       # 测试台
│   ├── aes128_top_tb.v       # 顶层测试台
│   ├── basic_ops_tb.v        # 基础运算测试
│   ├── mix_columns_tb.v      # MixColumns 测试
│   ├── key_schedule_tb.v     # 密钥扩展测试
│   └── run_*.sh              # 仿真脚本
├── fpga/                     # FPGA 相关
│   ├── vivado_build.tcl      # Vivado 综合脚本
│   ├── aes128_xdc.xdc        # 约束文件
│   └── README.md              # FPGA 构建说明
└── README.md                  # 本文件
```

## 模块说明

### 顶层模块 (aes128_top)

```
                ┌─────────────────────────────────────┐
                │            aes128_top                │
                │                                     │
key ──────────►│ key_valid              key_ready ──►│
key[127:0]───►│ key[127:0]                        │
                │                                     │
                │  ┌──────────────────────────────┐  │
                │  │      key_schedule             │  │
                │  │  key ──► 11 enc keys         │  │
                │  │  key ──► 11 dec keys         │  │
                │  └──────────────────────────────┘  │
                │           │            │            │
                │           ▼            ▼            │
                │  ┌────────────┐  ┌────────────┐    │
                │  │enc_pipeline│  │dec_pipeline│    │
mode────────────│  │   (10级)   │  │   (10级)   │    │
op_mode[1:0]───►│  └────────────┘  └────────────┘    │
iv[127:0] ─────►│  chain_reg (CBC 上一密文/CTR 计数器)│
iv_valid───────►│                     iv_ready ──────►│
data_in ───────►│ data_in_valid   data_out_valid ──►│
data_in[127:0]─►│                      data_out ────►│
                │ data_in_ready ◄──                  │
                │         data_out_ready ────────────│
                └─────────────────────────────────────┘
```

### 接口时序

```
Clock   │    │    │    │    │    │    │    │    │    │    │    │
        ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼    ▼
        ┌────┐
key     │ Valid
        └────┘
                           ┌────┐
key_ready                   │Ready
                           └────┘

                               ┌────┐
data_in_valid                │ 1  │
                              └────┘
data_in  ──────────────────────────► Input Block
                               ┌────┐
data_in_ready               │ 1  │
                              └────┘
                                    ┌────┐
data_out_valid                          │ 1  │
                                          └────┘
data_out ──────────────────────────────────────► Output Block
                                          ┌────┐
data_out_ready                        │ 1  │
                                          └────┘

Latency: 11 cycles from input to output
```

## 使用方法

### RTL 仿真 (Icarus Verilog)

```bash
cd aes128/tb
iverilog -g2005-sv -o aes128_sim ../rtl/*.v aes128_top_tb.v
vvp aes128_sim
```

### Vivado FPGA 综合

```bash
cd aes128/fpga
source /path/to/vivado/settings64.sh
vivado -mode batch -source vivado_build.tcl
```

## 接口信号

| 信号 | 方向 | 描述 |
|------|------|------|
| clk | 输入 | 系统时钟 |
| rst_n | 输入 | 异步低有效复位 |
| key[127:0] | 输入 | 128-bit AES 密钥 |
| key_valid | 输入 | 密钥有效信号 (脉冲) |
| mode | 输入 | 0=加密, 1=解密 (CTR 模式下忽略，始终走加密流水线) |
| op_mode[1:0] | 输入 | 分组密码工作模式：00=ECB, 01=CBC, 10=CTR (11 保留，行为等同 ECB) |
| iv[127:0] | 输入 | CBC 的初始向量 / CTR 的初始计数器值。ECB 模式下忽略 |
| iv_valid | 输入 | iv 有效信号 (脉冲)，需在 iv_ready 为高时拉高才会被采样 |
| iv_ready | 输出 | 流水线已排空，可以安全加载新的 iv/counter (开始新一条消息前必须等待此信号) |
| data_in[127:0] | 输入 | 输入数据 |
| data_in_valid | 输入 | 输入数据有效 |
| data_in_ready | 输出 | 模块准备好接收数据 |
| data_out[127:0] | 输出 | 输出数据 |
| data_out_valid | 输出 | 输出数据有效 |
| data_out_ready | 输入 | 下游准备好接收 |
| key_ready | 输出 | 轮密钥已准备好 |

### 工作模式说明 (op_mode)

- **ECB** (`op_mode=00`)：每个数据块独立加解密，与原先版本行为完全一致，全流水线，稳态 1 block/cycle。
- **CBC** (`op_mode=01`)：
  - 加密：`C_i = E(P_i XOR C_{i-1})`，`C_0` 取自 `iv`。由于下一块的输入依赖上一块的输出，CBC 加密**不能**全流水线，同一时刻只允许一个数据块在流水线中（吞吐降为约 1 block / 11 cycle）。
  - 解密：`P_i = D(C_i) XOR C_{i-1}`，异或量是刚进入的密文块本身（提前已知），因此 CBC 解密仍可全流水线，吞吐 1 block/cycle。
- **CTR** (`op_mode=10`)：`keystream_i = E(counter_i)`，`C_i = P_i XOR keystream_i` (加解密对称，运算相同)。始终使用加密流水线生成 keystream，计数器每接受一个块自增 1，全流水线，吞吐 1 block/cycle。

使用 CBC/CTR 时，每条新消息开始前需：
1. 等待 `iv_ready` 为高 (代表流水线和输出 FIFO 已完全排空，没有历史消息的残留数据块)。
2. 用一个周期的脉冲拉高 `iv_valid` 并给出 `iv`，加载 IV / 初始计数器。
3. 再开始给 `data_in`/`data_in_valid` 送入该消息的数据块。

`mode`、`op_mode` 同样只应在流水线空闲（`iv_ready`=1 且没有块在途）时切换。

## 性能指标

| 指标 | 值 |
|------|-----|
| 吞吐量 | 128 bits/cycle |
| 延迟 | 11 cycles |
| 目标频率 | 100 MHz |
| 预估 LUT | 15,000-20,000 |
| 预估 FF | 2,500-3,500 |

## 验证

- 基础运算模块单元测试 (S-box, GF乘法, XOR)
- MixColumns 往返测试
- 密钥扩展 FIPS-197 标准向量验证
- 顶层加解密测试 (NIST 标准测试向量)
- 加解密往返测试
- ECB 模式流式吞吐 / pycryptodome 交叉验证 (`aes128_streaming_cross_check_tb.v`)
- CBC / CTR 模式 pycryptodome 交叉验证，覆盖加密与解密两个方向 (`aes128_mode_cross_check_tb.v` + `gen_mode_vectors.py`)
