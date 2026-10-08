#!/usr/bin/env python3
"""
Generate AES-128-ECB streaming cross-check vectors using pycryptodome.

Unlike gen_vectors.py (which pairs each plaintext with a fresh random key),
this script uses a SINGLE fixed key for the whole batch. That matches how
aes128_streaming_cross_check_tb.v exercises the DUT: load the key once, then
pump many plaintext blocks through the pipeline back-to-back (with small
random gaps), relying on the pipeline/FIFO to keep multiple in-flight blocks
correctly ordered.

Each output line has the format:
    <key_hex> <plaintext_hex> <ciphertext_hex>
all as 32-hex-digit (128-bit) values, space separated, one block per line.
The key is repeated on every line purely so the Verilog $fscanf-based reader
(shared style with aes128_cross_check_tb.v) can stay simple.

Usage:
    python gen_stream_vectors.py [num_blocks] [output_file] [key_hex]
"""
import os
import sys

from Crypto.Cipher import AES

NUM_BLOCKS_DEFAULT = 64
OUTPUT_FILE_DEFAULT = "aes128_stream_vectors.hex"


def main():
    num_blocks = int(sys.argv[1]) if len(sys.argv) > 1 else NUM_BLOCKS_DEFAULT
    out_path = sys.argv[2] if len(sys.argv) > 2 else OUTPUT_FILE_DEFAULT
    key_hex = sys.argv[3] if len(sys.argv) > 3 else None

    key = bytes.fromhex(key_hex) if key_hex else os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)

    lines = []
    for _ in range(num_blocks):
        plaintext = os.urandom(16)
        ciphertext = cipher.encrypt(plaintext)
        lines.append(f"{key.hex()} {plaintext.hex()} {ciphertext.hex()}")

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {num_blocks} blocks with key={key.hex()} -> {out_path}")


if __name__ == "__main__":
    main()
