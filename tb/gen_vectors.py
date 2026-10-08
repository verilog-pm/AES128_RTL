#!/usr/bin/env python3
"""
Generate random AES-128-ECB test vectors using pycryptodome and dump them to
a hex file that the Verilog testbench reads via $readmemh.

Each line of the output file has the format:
    <key_hex> <plaintext_hex> <ciphertext_hex>
all as 32-hex-digit (128-bit) values, space separated, one test case per line.

Usage:
    python gen_vectors.py [num_vectors] [output_file]
"""
import os
import sys

from Crypto.Cipher import AES

NUM_VECTORS_DEFAULT = 200
OUTPUT_FILE_DEFAULT = "aes128_vectors.hex"


def gen_vector():
    key = os.urandom(16)
    plaintext = os.urandom(16)
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    return key, plaintext, ciphertext


def main():
    num_vectors = int(sys.argv[1]) if len(sys.argv) > 1 else NUM_VECTORS_DEFAULT
    out_path = sys.argv[2] if len(sys.argv) > 2 else OUTPUT_FILE_DEFAULT

    lines = []
    for _ in range(num_vectors):
        key, pt, ct = gen_vector()
        lines.append(
            f"{key.hex()} {pt.hex()} {ct.hex()}"
        )

    with open(out_path, "w") as f:
        f.write("\n".join(lines) + "\n")

    print(f"Generated {num_vectors} vectors -> {out_path}")


if __name__ == "__main__":
    main()
