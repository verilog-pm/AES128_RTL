#!/usr/bin/env python3
"""Generate AES-128-ECB streaming vectors for aes128_streaming_cross_check_tb.v.

One key is used for the whole file. Each line repeats that key:

    <key_hex> <plaintext_hex> <ciphertext_hex>

The checked-in file is 64 blocks from AES_VECTOR_SEED (default 0xA35128),
with the key drawn from that same stream. Pass key_hex only for a one-off
file; that file will not match the frozen vectors.

Usage:
    python gen_stream_vectors.py [num_blocks] [output_file] [key_hex]
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from Crypto.Cipher import AES
from vector_seed import make_rng, randbytes

HERE = Path(__file__).resolve().parent
NUM_BLOCKS_DEFAULT = 64
OUTPUT_FILE_DEFAULT = HERE / "aes128_stream_vectors.hex"


def main():
    num_blocks = int(sys.argv[1]) if len(sys.argv) > 1 else NUM_BLOCKS_DEFAULT
    out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else OUTPUT_FILE_DEFAULT
    key_hex = sys.argv[3] if len(sys.argv) > 3 else None
    rng, seed = make_rng()

    key = bytes.fromhex(key_hex) if key_hex else randbytes(rng, 16)
    cipher = AES.new(key, AES.MODE_ECB)

    lines = []
    for _ in range(num_blocks):
        plaintext = randbytes(rng, 16)
        ciphertext = cipher.encrypt(plaintext)
        lines.append(f"{key.hex()} {plaintext.hex()} {ciphertext.hex()}")

    out_path.write_text("\n".join(lines) + "\n", encoding="ascii", newline="\n")
    print(f"Generated {num_blocks} blocks seed=0x{seed:X} key={key.hex()} -> {out_path}")


if __name__ == "__main__":
    main()
