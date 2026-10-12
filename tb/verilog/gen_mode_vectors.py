#!/usr/bin/env python3
"""Generate AES-128 CBC and CTR vectors for aes128_mode_cross_check_tb.v.

Messages are a flat table. Every row repeats its message key and IV, and the
testbench slices the table with the same BLOCKS_PER_MESSAGE this script used:

    <key_hex> <iv_hex> <plaintext_hex> <ciphertext_hex>

The checked-in files are 8 messages of 16 blocks from AES_VECTOR_SEED
(default 0xA35128).

Usage:
    python gen_mode_vectors.py <cbc|ctr> [num_messages] [blocks_per_message] [output_file]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from Crypto.Cipher import AES
from Crypto.Util import Counter
from vector_seed import make_rng, randbytes

HERE = Path(__file__).resolve().parent


def gen_cbc_message(rng, num_blocks):
    key = randbytes(rng, 16)
    iv = randbytes(rng, 16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    blocks = [randbytes(rng, 16) for _ in range(num_blocks)]
    ciphertext = cipher.encrypt(b"".join(blocks))
    return key, iv, blocks, [ciphertext[i * 16:(i + 1) * 16] for i in range(num_blocks)]


def gen_ctr_message(rng, num_blocks):
    key = randbytes(rng, 16)
    iv = randbytes(rng, 16)
    ctr = Counter.new(128, initial_value=int.from_bytes(iv, "big"))
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    blocks = [randbytes(rng, 16) for _ in range(num_blocks)]
    ciphertext = cipher.encrypt(b"".join(blocks))
    return key, iv, blocks, [ciphertext[i * 16:(i + 1) * 16] for i in range(num_blocks)]


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("cbc", "ctr"):
        print("Usage: python gen_mode_vectors.py <cbc|ctr> "
              "[num_messages] [blocks_per_message] [output_file]")
        sys.exit(1)

    op_mode = sys.argv[1]
    num_messages = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    blocks_per_message = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    out_path = (Path(sys.argv[4]) if len(sys.argv) > 4
                else HERE / f"aes128_{op_mode}_vectors.hex")
    rng, seed = make_rng()
    gen_fn = gen_cbc_message if op_mode == "cbc" else gen_ctr_message

    lines = []
    for _ in range(num_messages):
        key, iv, plaintext_blocks, ciphertext_blocks = gen_fn(rng, blocks_per_message)
        for pt, ct in zip(plaintext_blocks, ciphertext_blocks):
            lines.append(f"{key.hex()} {iv.hex()} {pt.hex()} {ct.hex()}")

    out_path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"Generated {num_messages} {op_mode.upper()} messages "
          f"({blocks_per_message} blocks each, {len(lines)} lines) "
          f"seed=0x{seed:X} -> {out_path}")


if __name__ == "__main__":
    main()
