# =============================================================================
# AES-128 加密 - 纯 Python 实现（逐轮打印中间状态）
# 用于对照单条向量的中间轮，不是回归用的黄金模型。
# 回归签收使用 pycryptodome（tb/cocotb 与 tb/verilog/gen_*.py）。
# 示例向量: pt=0123456789abcdeffedcba8776543210
#           key=11112222333344445555666677778888
# =============================================================================

# ---------- S 盒 ----------
SBOX = [
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
]

# ---------- 轮常量 ----------
RCON = [0x00,
        0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36,
        0x6C,0xD8,0xAB,0x4D]  # 用到 10 即可

# ---------- 基础工具 ----------
def xtime(a):
    """GF(2^8) 乘 2"""
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF

def gf_mul(a, b):
    """GF(2^8) 通用乘法（用于 MixColumns / InvMixColumns）"""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        b >>= 1
        a = xtime(a)
    return p

# ---------- 状态矩阵工具（列主序） ----------
def bytes_to_state(bs):
    """16 字节 → 4x4 状态，s[r][c] = bs[r + 4c]"""
    return [[bs[r + 4*c] for c in range(4)] for r in range(4)]

def state_to_bytes(s):
    """4x4 状态 → 16 字节（列主序）"""
    return bytes(s[r][c] for c in range(4) for r in range(4))

def state_to_hex(s):
    """状态转十六进制字符串（列主序，便于对照 Verilog）"""
    return ''.join(f'{s[r][c]:02x}' for c in range(4) for r in range(4))

# ---------- 四个核心变换 ----------
def add_round_key(state, rk):
    """state ^= rk（rk 为 16 字节，列主序）"""
    for c in range(4):
        for r in range(4):
            state[r][c] ^= rk[r + 4*c]

def sub_bytes(state):
    for r in range(4):
        for c in range(4):
            state[r][c] = SBOX[state[r][c]]

def shift_rows(state):
    # 行 r 左移 r
    for r in range(1, 4):
        state[r] = state[r][r:] + state[r][:r]

def mix_columns(state):
    for c in range(4):
        a = [state[r][c] for r in range(4)]
        state[0][c] = gf_mul(a[0],2) ^ gf_mul(a[1],3) ^ a[2]      ^ a[3]
        state[1][c] = a[0]           ^ gf_mul(a[1],2) ^ gf_mul(a[2],3) ^ a[3]
        state[2][c] = a[0]           ^ a[1]           ^ gf_mul(a[2],2) ^ gf_mul(a[3],3)
        state[3][c] = gf_mul(a[0],3) ^ a[1]           ^ a[2]           ^ gf_mul(a[3],2)

# ---------- 密钥扩展 ----------
def key_expansion(key):
    """返回 11 组轮密钥，每组 16 字节（列主序）"""
    w = [list(key[4*i:4*i+4]) for i in range(4)]  # 4 个字
    for i in range(4, 44):
        temp = w[i-1][:]
        if i % 4 == 0:
            temp = temp[1:] + temp[:1]             # RotWord
            temp = [SBOX[b] for b in temp]         # SubWord
            temp[0] ^= RCON[i // 4]                # Rcon
        w.append([w[i-4][j] ^ temp[j] for j in range(4)])
    # 每 4 个字拼成 16 字节轮密钥（列主序：w[4r+c][r]）
    round_keys = []
    for r in range(11):
        rk = bytearray(16)
        for c in range(4):
            for row in range(4):
                rk[row + 4*c] = w[4*r + c][row]
        round_keys.append(bytes(rk))
    return round_keys

# ---------- 主加密函数 ----------
def aes128_encrypt(pt, key, verbose=True):
    assert len(pt) == 16 and len(key) == 16

    rks = key_expansion(key)

    if verbose:
        print("=" * 72)
        print("AES-128 加密")
        print(f"明文: {pt.hex()}")
        print(f"密钥: {key.hex()}")
        print("=" * 72)

    state = bytes_to_state(pt)

    # 初始 AddRoundKey
    add_round_key(state, rks[0])
    if verbose:
        print(f"\n[初始 AddRoundKey] {state_to_hex(state)}")

    # 9 轮完整
    for rnd in range(1, 10):
        sub_bytes(state)
        if verbose:
            print(f"\n[Round {rnd}]")
            print(f"  SubBytes    : {state_to_hex(state)}")
        shift_rows(state)
        if verbose:
            print(f"  ShiftRows   : {state_to_hex(state)}")
        mix_columns(state)
        if verbose:
            print(f"  MixColumns  : {state_to_hex(state)}")
        add_round_key(state, rks[rnd])
        if verbose:
            print(f"  AddRoundKey : {state_to_hex(state)}  (rk{rnd}={rks[rnd].hex()})")

    # 第 10 轮（无 MixColumns）
    sub_bytes(state)
    if verbose:
        print(f"\n[Round 10 - 最终轮]")
        print(f"  SubBytes    : {state_to_hex(state)}")
    shift_rows(state)
    if verbose:
        print(f"  ShiftRows   : {state_to_hex(state)}")
    add_round_key(state, rks[10])
    if verbose:
        print(f"  AddRoundKey : {state_to_hex(state)}  (rk10={rks[10].hex()})")

    ct = state_to_bytes(state)
    if verbose:
        print("\n" + "=" * 72)
        print(f"密文: {ct.hex()}")
        print("=" * 72)
    return ct

# ---------- 验证 ----------
if __name__ == "__main__":
    pt  = bytes.fromhex('0123456789abcdeffedcba8776543210')
    key = bytes.fromhex('11112222333344445555666677778888')

    ct = aes128_encrypt(pt, key, verbose=True)

    # 与 PyCryptodome 对比（若已安装）
    try:
        from Crypto.Cipher import AES
        ref = AES.new(key, AES.MODE_ECB).encrypt(pt)
        print(f"\nPyCryptodome 参考: {ref.hex()}")
        print(f"结果一致: {ct == ref}")
    except ImportError:
        print("\n(未安装 PyCryptodome，跳过交叉验证)")