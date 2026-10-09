// =============================================================================
// aes128_top 实例化模板
// 把下面注释里的代码复制到上层模块。本文件只有注释，加入 rtl/*.v 编译列表
// 时不会生成额外逻辑。
//
// mode       : 0 = 加密（ECB / CBC 加密 / CTR），1 = 解密（ECB / CBC 解密）
//              CTR 加解密都用 mode=0。mode=1 遇到 op_mode=CTR 时按 ECB 解密处理。
// DATA_WIDTH : 32 或 64，默认 32。一块 AES 分别是 4 拍或 2 拍，高位拍在前。
//
// key_valid、iv_valid 只负责锁存，没有对应的 ready。新密钥或新 IV 未装入前
// data_in_ready 为低。CTR 的计数器由模块内部累加，iv 只给初值。
// op_mode：00 = ECB，01 = CBC，10 = CTR。只在没有数据块在途时切换。
// =============================================================================

// -----------------------------------------------------------------------------
// 信号声明（DATA_WIDTH 与例化参数保持一致）
// -----------------------------------------------------------------------------
/*
localparam AES_DATA_WIDTH = 32;

reg  [127:0]              aes_key;
reg                       aes_key_valid;
reg  [1:0]                aes_op_mode;
reg  [127:0]              aes_iv;
reg                       aes_iv_valid;

reg  [AES_DATA_WIDTH-1:0]   aes_data_in;
reg                         aes_data_in_valid;
reg                         aes_data_in_last;
reg  [AES_DATA_WIDTH/8-1:0] aes_data_in_keep;
wire                        aes_data_in_ready;

wire [AES_DATA_WIDTH-1:0]   aes_data_out;
wire                        aes_data_out_valid;
wire                        aes_data_out_last;
wire [AES_DATA_WIDTH/8-1:0] aes_data_out_keep;
reg                         aes_data_out_ready;
*/

// -----------------------------------------------------------------------------
// 加密实例。ECB、CBC 加密、CTR 加解密都用这一例。
// -----------------------------------------------------------------------------
/*
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
*/

// -----------------------------------------------------------------------------
// 解密实例。用于 ECB / CBC 解密。需要两个方向时再复制这一例，不要和上面共用同一套 data 信号。
// -----------------------------------------------------------------------------
/*
aes128_top #(
    .mode       (1'b1),
    .DATA_WIDTH (32)
) u_aes128_dec (
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
*/
