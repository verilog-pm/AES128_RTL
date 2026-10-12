#!/usr/bin/env python3
"""Generate AES-128-ECB vectors for aes128_cross_check_tb.v.

Each line is ``<key> <plaintext> <ciphertext>``, 32 hex digits each.
The testbench reads the first NUM_VECTORS lines (currently 10).

Bytes come from AES_VECTOR_SEED (default 0xA35128). Running this script
with no extra arguments rewrites the checked-in file.

Usage:
    python gen_vectors.py [num_vectors] [output_file]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from Crypto.Cipher import AES
from vector_seed import make_rng, randbytes

HERE = Path(__file__).resolve().parent
NUM_VECTORS_DEFAULT = 10
OUTPUT_FILE_DEFAULT = HERE / "aes128_vectors.hex"


def main():
    num_vectors = int(sys.argv[1]) if len(sys.argv) > 1 else NUM_VECTORS_DEFAULT
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else OUTPUT_FILE_DEFAULT
    rng, seed = make_rng()

    lines = []
    for _ in range(num_vectors):
        key = randbytes(rng, 16)
        plaintext = randbytes(rng, 16)
        ciphertext = AES.new(key, AES.MODE_ECB).encrypt(plaintext)
        lines.append(f"{key.hex()} {plaintext.hex()} {ciphertext.hex()}")

    out_path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"Generated {num_vectors} vectors seed=0x{seed:X} -> {out_path}")


if __name__ == "__main__":
    main()
