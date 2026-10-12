# AES-128 Verilog Implementation

基于 FIPS-197 的 AES-128 加密/解密流水线，支持 NIST SP 800-38A 的 ECB、CBC、CTR。一个实例由参数 `mode` 固定为加密或解密，对外是 32/64 bit 的 valid/ready 流。

## 目录

```
aes128/
├── rtl/                      # 可综合 Verilog
├── tb/
│   ├── verilog/              # Verilog 测试台、冻结向量、向量生成器
│   ├── modelsim/             # ModelSim 批处理和波形
│   └── cocotb/               # pycryptodome 交叉验证
├── ref/aes128_rounds.py      # 逐轮对照，不作为回归黄金模型
└── fpga/
    ├── aes128_xdc.xdc        # 单独综合用约束，100 MHz
    └── vivado_synth.tcl      # 综合并写报告，不出比特流
```

`rtl/` 只放可综合源码。仿真顶层 `aes128_cocotb_harness` 在 `tb/cocotb/`。

## 行为

- `mode=0` 只例化加密流水线，用于 ECB、CBC 加密和 CTR。CTR 加解密都用这一例。
- `mode=1` 只例化解密流水线，用于 ECB 和 CBC 解密。`op_mode=CTR` 在解密实例上按 ECB 解密处理。
- ECB、CTR、CBC 解密在块进入流水线后可以每周期一块。CBC 加密下一块依赖上一块密文，同一时刻只允许一个块在途，吞吐约 1 block / 11 cycle。
- 流水线延迟 11 拍，外面还要加上组包和拆包。
- `key_valid`、`iv_valid` 只锁存。新密钥或新 IV 在核空闲后装入，装入前 `data_in_ready` 为低。没有 `key_ready` 或 `iv_ready`。
- `op_mode` 只在没有数据块在途时切换。`00`=ECB，`01`=CBC，`10`=CTR，`11` 按 ECB 处理。
- `DATA_WIDTH` 为 32（默认）或 64。高位拍在前。`data_in_last` 可以提前结束一块；`keep=0` 的字节在块内补 0。密码核仍处理完整的 128 bit，输出只吐出实际收到的拍。非整块的 ECB/CBC 不能往返，CTR 可以，因为两边都丢掉未使用的密钥流字节。

## 例化

加密实例覆盖 ECB、CBC 加密和 CTR。解密实例单独再例化一份，不要和加密实例共用同一套 data 信号。

```verilog
localparam AES_DATA_WIDTH = 32;

aes128_top #(
    .mode       (1'b0),
    .DATA_WIDTH (32)
) u_aes128_enc (
    .clk            (clk),
    .rst_n          (rst_n),
    .key            (aes_key),
    .key_valid      (aes_key_valid),
    .op_mode        (aes_op_mode),
    .iv             (aes_iv),
    .iv_valid       (aes_iv_valid),
    .data_in        (aes_data_in),
    .data_in_valid  (aes_data_in_valid),
    .data_in_last   (aes_data_in_last),
    .data_in_keep   (aes_data_in_keep),
    .data_in_ready  (aes_data_in_ready),
    .data_out       (aes_data_out),
    .data_out_valid (aes_data_out_valid),
    .data_out_last  (aes_data_out_last),
    .data_out_keep  (aes_data_out_keep),
    .data_out_ready (aes_data_out_ready)
);
```

解密实例把 `mode` 改成 `1'b1`。

## 接口

| 信号 | 方向 | 描述 |
|------|------|------|
| clk | 输入 | 系统时钟。单独综合约束为 100 MHz |
| rst_n | 输入 | 异步低有效复位 |
| key[127:0] | 输入 | 128-bit AES 密钥 |
| key_valid | 输入 | 为高时锁存 `key`，空闲后才更新内部密钥 |
| op_mode[1:0] | 输入 | 00=ECB，01=CBC，10=CTR |
| iv[127:0] | 输入 | CBC 初始向量或 CTR 初始计数器。ECB 下忽略 |
| iv_valid | 输入 | 为高时锁存 `iv`，空闲后写入链寄存器。再次拉高会重新装载 |
| data_in[DATA_WIDTH-1:0] | 输入 | 输入数据 |
| data_in_valid | 输入 | 输入有效 |
| data_in_last | 输入 | 本拍是当前块的最后一拍，可以在块未满时结束 |
| data_in_keep[DATA_WIDTH/8-1:0] | 输入 | `keep[i]` 对应 `data_in[8*i +: 8]`。非最后一拍应为全 1 |
| data_in_ready | 输出 | 可以接收数据 |
| data_out[DATA_WIDTH-1:0] | 输出 | 输出数据 |
| data_out_valid | 输出 | 输出有效 |
| data_out_last | 输出 | 与输入包尾对应的最后一拍 |
| data_out_keep[DATA_WIDTH/8-1:0] | 输出 | 与输入相同的字节有效标记 |
| data_out_ready | 输入 | 下游可以接收 |

## 仿真

依赖：Icarus Verilog，或 ModelSim（`MODELSIM_HOME` 指向含 `vsim.exe` 的目录，默认 `C:\modeltech64_2020.4\win64`）。cocotb 还需要 `tb/cocotb/requirements.txt` 里的 cocotb 和 pycryptodome。

```bash
# ECB / CBC / CTR，RTL 与 pycryptodome 双向交叉验证
cd tb/cocotb
python run_sim.py

# 全部 Verilog 测试台，读 tb/verilog 里已提交的向量
bash tb/verilog/run_icarus.sh

# ModelSim 跑同一组测试台。REGEN=1 时才按默认种子重写向量
tb\modelsim\run_modelsim.bat

# 只跑 NIST 顶层向量
cd tb/modelsim
vsim -c -do run_test.tcl
```

波形配置在 `tb/modelsim/wave.do`，层次对应 `aes128_top_tb`。

向量由 `tb/verilog/gen_*.py` 生成，默认种子 `0xA35128`，可用环境变量 `AES_VECTOR_SEED` 覆盖。直接运行这三个脚本会把冻结文件写回 `tb/verilog/`：

```bash
python tb/verilog/gen_vectors.py
python tb/verilog/gen_stream_vectors.py
python tb/verilog/gen_mode_vectors.py cbc
python tb/verilog/gen_mode_vectors.py ctr
```

`ref/aes128_rounds.py` 打印一条固定明文的每一轮状态，并在安装了 pycryptodome 时与它对一下最终密文。

已覆盖的范围：

- 单元测试：S-box、GF 乘法、MixColumns、密钥扩展
- NIST 顶层加解密向量
- 冻结向量上的 ECB 流式交叉验证，以及 CBC/CTR 双向交叉验证
- `DATA_WIDTH` 32 和 64，以及 CTR 短尾往返（`aes128_width_tb`）
- cocotb 随机消息的 ECB/CBC/CTR 双向交叉验证。该测试把 `data_out_ready` 保持为 1

输出反压还没有签收用例。

## FPGA

在 `fpga/` 下执行：

```bash
vivado -mode batch -source vivado_synth.tcl
```

目标器件 XC7Z100-FFG900-2。脚本只做综合，报告写到 `fpga/reports/`（不入库）。约束周期是 10 ns。端口上的 false path 只用于这个没有板级延迟的单独综合；集成到系统里时换成真实的 input/output delay。没有分配 `PACKAGE_PIN`，这个脚本不实现、也不生成比特流。

当前仓库不附带综合数字。先前那份同时例化加解密两条流水线、数据口为 128 bit 的报告已经从树里移除。
