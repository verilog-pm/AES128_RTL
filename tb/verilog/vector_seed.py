"""Fixed-seed byte source for the Verilog vector files.

AES_VECTOR_SEED overrides the default. The same seed rewrites the files
checked in beside the generators.
"""
import os
import random

DEFAULT_SEED = 0xA35128


def make_rng():
    raw = os.environ.get("AES_VECTOR_SEED", str(DEFAULT_SEED))
    seed = int(raw, 0)
    return random.Random(seed), seed


def randbytes(rng, n):
    return rng.randbytes(n)
