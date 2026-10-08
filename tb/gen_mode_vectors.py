#!/usr/bin/env python3
"""
Generate AES-128 CBC and CTR golden vectors using pycryptodome, for
cross-checking the aes128_top RTL's CBC/CTR op_mode support.

Unlike gen_vectors.py/gen_stream_vectors.py (ECB), CBC and CTR need an IV / initial counter in addition to the key, and the
blocks within one message are chained together. To keep the Verilog reader
simple (a flat $fscanf loop, no blank-line handling), messages are NOT
blank-line separated; instead every row repeats its message's key/iv, and
the testbench slices the flat table into fixed-size messages using the same
BLOCKS_PER_MESSAGE constant passed to this script:

    <key_hex> <iv_hex> <plaintext_hex> <ciphertext_hex>

All hex fields are 32 hex digits (128 bits), space separated, one block per
line, num_messages * blocks_per_message lines total.

Usage:
    python gen_mode_vectors.py <ecb|cbc|ctr> [num_messages] [blocks_per_message] [output_file]
"""
import os
import sys

from Crypto.Cipher import AES
from Crypto.Util import Counter

MODE_MAP = {
    "cbc": AES.MODE_CBC,
    "ctr": None,  # handled specially (needs Counter object)
}


def gen_cbc_message(num_blocks):
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    blocks = [os.urandom(16) for _ in range(num_blocks)]
    plaintext = b"".join(blocks)
    ciphertext = cipher.encrypt(plaintext)
    return key, iv, blocks, [ciphertext[i * 16:(i + 1) * 16] for i in range(num_blocks)]


def gen_ctr_message(num_blocks):
    key = os.urandom(16)
    iv = os.urandom(16)  # used directly as the 128-bit initial counter value
    initial_value = int.from_bytes(iv, "big")
    ctr = Counter.new(128, initial_value=initial_value)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    blocks = [os.urandom(16) for _ in range(num_blocks)]
    plaintext = b"".join(blocks)
    ciphertext = cipher.encrypt(plaintext)
    return key, iv, blocks, [ciphertext[i * 16:(i + 1) * 16] for i in range(num_blocks)]


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in ("cbc", "ctr"):
        print("Usage: python gen_mode_vectors.py <cbc|ctr> [num_messages] [blocks_per_message] [output_file]")
        sys.exit(1)

    op_mode = sys.argv[1]
    num_messages = int(sys.argv[2]) if len(sys.argv) > 2 else 8
    blocks_per_message = int(sys.argv[3]) if len(sys.argv) > 3 else 16
    out_path = sys.argv[4] if len(sys.argv) > 4 else f"aes128_{op_mode}_vectors.hex"

    gen_fn = gen_cbc_message if op_mode == "cbc" else gen_ctr_message

    lines = []
    for _ in range(num_messages):
        key, iv, plaintext_blocks, ciphertext_blocks = gen_fn(blocks_per_message)
        for pt, ct in zip(plaintext_blocks, ciphertext_blocks):
            lines.append(f"{key.hex()} {iv.hex()} {pt.hex()} {ct.hex()}")

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {num_messages} {op_mode.upper()} messages "
          f"({blocks_per_message} blocks each, {len(lines)} total blocks) -> {out_path}")


if __name__ == "__main__":
    main()
