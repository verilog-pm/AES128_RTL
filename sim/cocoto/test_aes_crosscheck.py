# =============================================================================
# cocotb cross-check testbench for aes128_top
#
# Cross-validates the RTL against pycryptodome (golden reference) for the
# three operating modes (ECB / CBC / CTR), in both directions:
#
#   Path A: random plaintext -> RTL encrypt -> Python decrypt
#          -> must equal the original plaintext.
#   Path B: random plaintext -> Python encrypt -> RTL decrypt
#          -> must equal the original plaintext.
#
# Byte order: 128-bit bus <-> bytes conversions are big-endian, matching
# tb/gen_vectors.py and tb/gen_mode_vectors.py.
#
# Driver notes:
#   The DUT is aes128_cocotb_harness, which muxes two aes128_top instances
#   (mode parameter 0 and 1). aes128_top itself no longer has a mode port.
#   * key_valid / iv_valid are single-cycle pulses. Each only latches its
#     value; the core applies it once the cipher is idle. data_in_ready stays
#     low until the new key or IV is installed. There is no key_ready or
#     iv_ready pin.
#   * The harness `mode` pin selects the encrypt or decrypt core. CTR always
#     uses the encrypt core. op_mode changes only while that core is idle.
#   * Data blocks go through the valid/ready handshake. Random gaps are
#     inserted on the input (data_in_valid low). data_out_ready stays 1:
#     the pipeline pops on the edge that raises data_out_valid, while
#     in_flight_count consumes one edge later, so a ready-low bubble
#     between those edges loses or double-counts the in-flight block.
#     CBC-encrypt's serial pacing is enforced by data_in_ready.
#
# Run from this directory:  python run_sim.py
# Reproducibility: set AES_TEST_SEED (e.g. 0x1234) to re-run a fixed sequence.
# =============================================================================
import os
import random
from pathlib import Path

import cocotb
from cocotb.clock import Clock
from cocotb.triggers import ReadOnly, RisingEdge, Timer

try:
    from cocotb.handle import Immediate  # cocotb >= 2.0
except ImportError:  # cocotb 1.x deposits are not deferred the same way
    Immediate = None

from Crypto.Cipher import AES
from Crypto.Util import Counter


def _drive(sig, value):
    """Drive a DUT input so the next posedge observes it.

    cocotb 2 ``sig.value = x`` is an inertial Deposit, applied at the next
    ReadWrite. On Icarus that ReadWrite runs after the following posedge has
    already sampled the old value, so a ready/valid change issued from a
    RisingEdge callback misses the edge it was meant to affect. Immediate
    updates the net before the simulator continues.
    """
    if Immediate is None:
        sig.value = value
    else:
        sig.value = Immediate(value)

# ---------------------------------------------------------------------------
# Parameters
# ---------------------------------------------------------------------------
OP_ECB = 0b00
OP_CBC = 0b01
OP_CTR = 0b10
MODE_NAMES = {OP_ECB: "ECB", OP_CBC: "CBC", OP_CTR: "CTR"}

CLK_PERIOD_NS = 10

NUM_MESSAGES = 4                 # random messages per mode
BLOCK_COUNTS = (1, 4, 8, 16)     # blocks per message (single + multi block)

# Cycle budgets: key expansion is ~115 cycles; CBC-encrypt 16 blocks takes
# ~16 * 13 cycles; random gaps add a few more.
KEY_TIMEOUT_CYCLES = 500
IDLE_TIMEOUT_CYCLES = 2000
HANDSHAKE_TIMEOUT_CYCLES = 2000
RECV_TIMEOUT_CYCLES = 4000

IN_GAP_PROBABILITY = 0.25        # chance to deassert data_in_valid between blocks
IN_GAP_MAX_CYCLES = 2

_seed_env = os.environ.get("AES_TEST_SEED")
RNG_SEED = int(_seed_env, 0) if _seed_env else 0xAE5128C0DE
rng = random.Random(RNG_SEED)


# ---------------------------------------------------------------------------
# Byte-order helpers (big-endian, as in tb/gen_vectors.py)
# ---------------------------------------------------------------------------
def bytes_to_block(b):
    return int.from_bytes(b, "big")


def block_to_bytes(v):
    return v.to_bytes(16, "big")


def _block_hex(block):
    """16-byte block or 128-bit int as 32 lowercase hex digits."""
    if isinstance(block, int):
        return f"{block:032x}"
    return block.hex()


_DATA_LOG = Path(__file__).resolve().parent / "sim_data.log"
_data_log_started = False


def _log_vectors(mode_name, mi, path_name, key, iv,
                 before_enc, after_enc, before_dec, after_dec):
    """Append one message's encrypt/decrypt bytes for sim.log."""
    global _data_log_started
    if not _data_log_started:
        _DATA_LOG.write_text(
            "AES-128 加解密数据（每个 128-bit 块一行，大端 hex）\n"
            "加密前 = 送入加密的明文；加密后 = 加密得到的密文；\n"
            "解密前 = 送入解密的密文；解密后 = 解密得到的明文。\n\n",
            encoding="utf-8",
        )
        _data_log_started = True

    def _lines(blocks):
        if not blocks:
            return "    (无数据)"
        return "\n".join(
            f"    [{i:02d}] {_block_hex(b)}" for i, b in enumerate(blocks)
        )

    iv_line = f"  iv:  {iv.hex()}\n" if iv is not None else ""
    text = (
        f"[{mode_name}] message {mi}  {path_name}\n"
        f"  key: {key.hex()}\n"
        f"{iv_line}"
        f"  加密前:\n{_lines(before_enc)}\n"
        f"  加密后:\n{_lines(after_enc)}\n"
        f"  解密前:\n{_lines(before_dec)}\n"
        f"  解密后:\n{_lines(after_dec)}\n"
        "\n"
    )
    with _DATA_LOG.open("a", encoding="utf-8") as handle:
        handle.write(text)


# ---------------------------------------------------------------------------
# pycryptodome golden model
# ---------------------------------------------------------------------------
def py_cipher(op, key, iv, blocks, encrypt):
    """Encrypt/decrypt a list of 16-byte blocks with pycryptodome."""
    data = b"".join(blocks)
    if op == OP_ECB:
        cipher = AES.new(key, AES.MODE_ECB)
    elif op == OP_CBC:
        cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    elif op == OP_CTR:
        # 128-bit big-endian counter, initial value = iv (matches RTL chain_reg)
        cipher = AES.new(
            key, AES.MODE_CTR,
            counter=Counter.new(128, initial_value=bytes_to_block(iv)),
        )
    else:
        raise ValueError(f"unsupported op_mode {op}")
    out = cipher.encrypt(data) if encrypt else cipher.decrypt(data)
    return [out[i * 16:(i + 1) * 16] for i in range(len(blocks))]


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------
class AesDriver:
    """Drives aes128_top: reset, key load, IV load, valid/ready streaming."""

    def __init__(self, dut):
        self.dut = dut

    async def reset(self):
        dut = self.dut
        await Timer(1, unit="ns")  # advance past t=0 so writes are legal
        dut.rst_n.value = 0
        dut.key.value = 0
        dut.key_valid.value = 0
        dut.iv.value = 0
        dut.iv_valid.value = 0
        dut.data_in.value = 0
        dut.data_in_valid.value = 0
        dut.data_in_last.value = 0
        dut.data_in_keep.value = 0
        dut.data_out_ready.value = 1
        dut.mode.value = 0
        dut.op_mode.value = OP_ECB
        for _ in range(5):
            await RisingEdge(dut.clk)
        dut.rst_n.value = 1
        for _ in range(2):
            await RisingEdge(dut.clk)

    async def wait_idle(self):
        """Wait until no input is offered and no output appears for a while.

        Pipeline latency is about 12 cycles, so a quiet stretch longer than
        that means nothing is left in flight. iv_ready is no longer a port.
        """
        dut = self.dut
        quiet = 0
        for _ in range(IDLE_TIMEOUT_CYCLES):
            await RisingEdge(dut.clk)
            await ReadOnly()
            if int(dut.data_out_valid.value) or int(dut.data_in_valid.value):
                quiet = 0
            else:
                quiet += 1
                if quiet >= 20:
                    await Timer(1, unit="ns")  # leave ReadOnly before the caller drives
                    return
        raise TimeoutError(
            "pipeline did not drain "
            f"(out_valid={int(dut.data_out_valid.value)} "
            f"out_ready={int(dut.data_out_ready.value)} "
            f"in_ready={int(dut.data_in_ready.value)})"
        )

    async def load_key(self, key_int):
        """Single-cycle key_valid pulse, then wait until the new key is in use.

        The top latches the key while key_valid is high and expands it only
        once the cipher is idle. data_in_ready stays low across that update.
        """
        dut = self.dut
        await RisingEdge(dut.clk)
        dut.key.value = key_int
        dut.key_valid.value = 1
        await RisingEdge(dut.clk)
        dut.key_valid.value = 0
        for _ in range(KEY_TIMEOUT_CYCLES):
            await RisingEdge(dut.clk)
            if dut.data_in_ready.value:
                return
        raise TimeoutError("data_in_ready never asserted after key_valid pulse")

    async def configure(self, op, encrypt):
        """Select op_mode and which parameterized core the harness uses.

        CTR decrypt stays on the encrypt core. Change these only while idle.
        """
        dut = self.dut
        dut.op_mode.value = op
        dut.mode.value = 0 if encrypt else 1
        await RisingEdge(dut.clk)

    async def load_iv(self, iv_int):
        """Single-cycle iv_valid pulse. The core latches iv and installs it when idle."""
        dut = self.dut
        await RisingEdge(dut.clk)
        dut.iv.value = iv_int
        dut.iv_valid.value = 1
        await RisingEdge(dut.clk)
        dut.iv_valid.value = 0

    def _geom(self):
        width = int(self.dut.DATA_WIDTH.value)
        beats = 128 // width
        full_keep = (1 << (width // 8)) - 1
        return width, beats, full_keep

    @staticmethod
    def _split_block(block, width, beats):
        mask = (1 << width) - 1
        return [((block >> (128 - (b + 1) * width)) & mask) for b in range(beats)]

    @staticmethod
    def _join_beats(beats, width):
        mask = (1 << width) - 1
        value = 0
        for b, beat in enumerate(beats):
            value |= (beat & mask) << (128 - (b + 1) * width)
        return value

    async def _send_beat(self, beat, keep, last):
        dut = self.dut
        _drive(dut.data_in, beat)
        _drive(dut.data_in_keep, keep)
        _drive(dut.data_in_last, 1 if last else 0)
        _drive(dut.data_in_valid, 1)
        for _ in range(HANDSHAKE_TIMEOUT_CYCLES):
            await ReadOnly()
            if dut.data_in_ready.value:
                break
            await RisingEdge(dut.clk)
        else:
            _drive(dut.data_in_valid, 0)
            _drive(dut.data_in_last, 0)
            raise TimeoutError("data_in_ready never asserted")
        await RisingEdge(dut.clk)

    async def send_blocks(self, blocks):
        """Stream each 128-bit block as DATA_WIDTH beats. last marks the
        final beat of the message. Gaps are inserted between blocks."""
        dut = self.dut
        width, nbeats, full_keep = self._geom()
        for idx, blk in enumerate(blocks):
            beats = self._split_block(blk, width, nbeats)
            for b, beat in enumerate(beats):
                last = (idx == len(blocks) - 1) and (b == nbeats - 1)
                await self._send_beat(beat, full_keep, last)
            if idx < len(blocks) - 1 and rng.random() < IN_GAP_PROBABILITY:
                _drive(dut.data_in_valid, 0)
                _drive(dut.data_in_last, 0)
                for _ in range(rng.randint(1, IN_GAP_MAX_CYCLES)):
                    await RisingEdge(dut.clk)
        _drive(dut.data_in_valid, 0)
        _drive(dut.data_in_last, 0)

    async def recv_blocks(self, count):
        """Collect `count` output blocks, reassembled from narrow beats.

        data_out_ready stays 1. Each accepted beat is visible for one cycle.
        data_out_last is high only on the last beat of the message, and every
        beat of these full blocks carries keep=all-ones.
        """
        dut = self.dut
        width, nbeats, full_keep = self._geom()
        need = count * nbeats
        beats = []
        lasts = []
        keeps = []
        budget = RECV_TIMEOUT_CYCLES
        _drive(dut.data_out_ready, 1)
        while len(beats) < need:
            await RisingEdge(dut.clk)
            budget -= 1
            if budget < 0:
                raise TimeoutError(
                    f"received only {len(beats)}/{need} output beats "
                    f"({len(beats) // nbeats} blocks)")
            await ReadOnly()
            if int(dut.data_out_valid.value):
                beats.append(int(dut.data_out.value))
                lasts.append(int(dut.data_out_last.value))
                keeps.append(int(dut.data_out_keep.value))
        await Timer(1, unit="ns")
        for i, (last, keep) in enumerate(zip(lasts, keeps)):
            if bool(last) != (i == need - 1):
                raise AssertionError(
                    f"data_out_last={last} on beat {i}, "
                    f"expected {int(i == need - 1)}")
            if keep != full_keep:
                raise AssertionError(
                    f"data_out_keep={keep:#x} on beat {i}, expected {full_keep:#x}")
        return [self._join_beats(beats[i * nbeats:(i + 1) * nbeats], width)
                for i in range(count)]

    async def stream(self, blocks):
        """Send blocks and concurrently collect len(blocks) output blocks."""
        recv_task = cocotb.start_soon(self.recv_blocks(len(blocks)))
        await self.send_blocks(blocks)
        return await recv_task


# ---------------------------------------------------------------------------
# Checks and per-message flow
# ---------------------------------------------------------------------------
def _check_blocks(mode, direction, mi, exp, got, key, iv, counterpart):
    """Assert got == exp; on mismatch print mode, direction, message #,
    block #, and the data on both ends."""
    if len(exp) != len(got):
        raise AssertionError(
            f"[{mode}] {direction} message #{mi}: block count mismatch "
            f"(expected {len(exp)}, got {len(got)})")
    for i, (e, g) in enumerate(zip(exp, got)):
        if e != g:
            raise AssertionError(
                f"[{mode}] {direction} mismatch at message #{mi}, block #{i}\n"
                f"  key:      {key.hex()}\n"
                + (f"  iv:       {iv.hex()}\n" if iv is not None else "")
                + f"  expected: {e.hex()}\n"
                f"  got:      {g.hex()}\n"
                f"  counterpart data: {counterpart}")


async def run_message(drv, mode_name, op, mi, key, iv, pt_blocks):
    nb = len(pt_blocks)
    key_int = bytes_to_block(key)
    iv_int = bytes_to_block(iv) if iv is not None else 0
    pt_ints = [bytes_to_block(p) for p in pt_blocks]

    # -------- Path A: RTL encrypt -> Python decrypt -------------------------
    await drv.wait_idle()
    await drv.load_key(key_int)
    await drv.configure(op, encrypt=True)
    if op != OP_ECB:
        await drv.load_iv(iv_int)
    rtl_ct = await drv.stream(pt_ints)
    rtl_ct_bytes = [block_to_bytes(v) for v in rtl_ct]
    py_pt = py_cipher(op, key, iv, rtl_ct_bytes, encrypt=False)
    _log_vectors(mode_name, mi, "RTL加密 -> Python解密", key, iv,
                 pt_blocks, rtl_ct_bytes, rtl_ct_bytes, py_pt)
    rtl_ct_hex = " ".join(b.hex() for b in rtl_ct_bytes)
    _check_blocks(mode_name, "RTL-enc->PY-dec", mi, pt_blocks, py_pt,
                  key, iv, f"rtl_ct: {rtl_ct_hex}")

    # -------- Path B: Python encrypt -> RTL decrypt -------------------------
    py_ct = py_cipher(op, key, iv, pt_blocks, encrypt=True)
    await drv.wait_idle()
    await drv.configure(op, encrypt=False)
    if op != OP_ECB:
        await drv.load_iv(iv_int)
    rtl_pt = await drv.stream([bytes_to_block(c) for c in py_ct])
    rtl_pt_bytes = [block_to_bytes(v) for v in rtl_pt]
    _log_vectors(mode_name, mi, "Python加密 -> RTL解密", key, iv,
                 pt_blocks, py_ct, py_ct, rtl_pt_bytes)
    py_ct_hex = " ".join(c.hex() for c in py_ct)
    _check_blocks(mode_name, "PY-enc->RTL-dec", mi, pt_blocks, rtl_pt_bytes,
                  key, iv, f"py_ct: {py_ct_hex}")


async def run_mode_crosscheck(dut, op):
    """Generate NUM_MESSAGES random messages (block counts from BLOCK_COUNTS)
    and cross-check both directions for the given operating mode."""
    mode_name = MODE_NAMES[op]
    cocotb.log.info(f"[{mode_name}] RNG seed {RNG_SEED:#x}")

    drv = AesDriver(dut)
    await drv.reset()

    for mi in range(NUM_MESSAGES):
        nb = BLOCK_COUNTS[mi % len(BLOCK_COUNTS)]
        key = rng.randbytes(16)
        iv = rng.randbytes(16) if op != OP_ECB else None
        pt_blocks = [rng.randbytes(16) for _ in range(nb)]
        cocotb.log.info(f"[{mode_name}] message {mi}: {nb} block(s)")
        await run_message(drv, mode_name, op, mi, key, iv, pt_blocks)

    cocotb.log.info(
        f"[{mode_name}] all {NUM_MESSAGES} messages passed both directions")


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
_clock_task = None


async def _ensure_clock(dut):
    """Start the clock for this test.

    cocotb cancels every task the test started when the test returns, which
    stops the clock and lets Icarus run out of events. The next test must
    start a new clock or its first RisingEdge never comes and the simulator
    exits.
    """
    global _clock_task
    if _clock_task is None or _clock_task.done():
        _clock_task = Clock(dut.clk, CLK_PERIOD_NS, unit="ns").start()
        await Timer(1, unit="ns")


@cocotb.test()
async def test_ecb_crosscheck(dut):
    """ECB: RTL-enc->PY-dec and PY-enc->RTL-dec over 4 random messages."""
    await _ensure_clock(dut)
    await run_mode_crosscheck(dut, OP_ECB)


@cocotb.test()
async def test_cbc_crosscheck(dut):
    """CBC: RTL-enc->PY-dec and PY-enc->RTL-dec over 4 random messages."""
    await _ensure_clock(dut)
    await run_mode_crosscheck(dut, OP_CBC)


@cocotb.test()
async def test_ctr_crosscheck(dut):
    """CTR: RTL-enc->PY-dec and PY-enc->RTL-dec over 4 random messages."""
    await _ensure_clock(dut)
    await run_mode_crosscheck(dut, OP_CTR)