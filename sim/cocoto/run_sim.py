#!/usr/bin/env python3
"""
Build and run the cocotb AES-128 cross-check simulation.

Compiles all of ../../rtl with the cocotb runner (top module aes128_top,
timescale 1ns/1ps) and runs test_aes_crosscheck.py, which cross-validates
ECB / CBC / CTR in both directions against pycryptodome:

  * RTL encrypt  -> Python decrypt -> must equal original plaintext
  * Python encrypt -> RTL decrypt  -> must equal original plaintext

Simulator selection: Icarus Verilog (`iverilog` on PATH) is preferred;
if it is missing, fall back to the existing ModelSim installation at
C:\\modeltech64_2020.4\\win64.

The runner import is compatible with cocotb 1.x (cocotb.runner) and
2.x (cocotb_tools.runner).

Usage:
    python run_sim.py            (from this directory)

The full build and test transcript is written to sim.log in this directory.
Icarus also writes a VCD waveform to aes128_top.vcd in this directory.
The console only prints the log path, the VCD path, and the pass/fail summary.

Exit code 0 iff every test passed.
"""
import os
import shutil
import sys
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
RTL_DIR = (HERE / ".." / ".." / "rtl").resolve()
BUILD_DIR = HERE / "sim_build"
BUILD_LOG = BUILD_DIR / "build.log"
TEST_LOG = BUILD_DIR / "test.log"
RUN_LOG = HERE / "sim.log"
VCD_PATH = HERE / "aes128_top.vcd"
TOP_MODULE = "aes128_top"
TEST_MODULE = "test_aes_crosscheck"
MODELSIM_BIN = r"C:\modeltech64_2020.4\win64"


def _get_runner_factory():
    """cocotb 2.x moved the runner from cocotb.runner to cocotb_tools.runner."""
    try:
        from cocotb_tools.runner import get_runner  # cocotb >= 2.0
    except ImportError:
        from cocotb.runner import get_runner  # cocotb 1.x
    return get_runner


try:
    from cocotb_tools.runner import Icarus as _Icarus
except ImportError:  # cocotb 1.x has no separate Icarus class to subclass
    _Icarus = None


if _Icarus is not None:

    class IcarusVcd(_Icarus):
        """Icarus runner that dumps a VCD file.

        Stock cocotb enables FST via vvp's ``-fst`` flag and, with waves off,
        passes ``-none``, which disables ``$dumpvars`` entirely.
        """

        def _create_iverilog_dump_file(self) -> None:
            vcd = VCD_PATH.as_posix()
            with open(self.iverilog_dump_file, "w") as handle:
                handle.write("module cocotb_iverilog_dump();\n")
                handle.write("initial begin\n")
                handle.write(f'    $dumpfile("{vcd}");\n')
                handle.write(f"    $dumpvars(0, {self.hdl_toplevel});\n")
                handle.write("end\n")
                handle.write("endmodule\n")

        def _waves_file(self):
            return str(VCD_PATH)

        def _test_command(self):
            commands = super()._test_command()
            for command in commands:
                while "-fst" in command:
                    command.remove("-fst")
            return commands


def _make_runner(sim):
    if sim == "icarus" and _Icarus is not None:
        return IcarusVcd()
    return _get_runner_factory()(sim)


def _try_attempts(fn, attempts):
    """Call fn(**kw) for each attempt dict until one does not raise TypeError."""
    last_exc = None
    for kwargs in attempts:
        try:
            fn(**kwargs)
            return
        except TypeError as exc:  # kwarg-name mismatch between cocotb versions
            last_exc = exc
    raise last_exc


def _build(runner, sources):
    """Version-tolerant runner.build() (hdl_toplevel in 2.x, top_module in 1.x;
    `sources` in 2.x, `verilog_sources` in 1.x; timescale is supported by
    Icarus but not every simulator)."""
    # always=True: an existing sim.vvp built without the dump module is not
    # newer than the RTL, so Icarus would otherwise skip the compile.
    base = dict(build_dir=str(BUILD_DIR), log_file=str(BUILD_LOG),
                waves=True, always=True)
    src_paths = [str(p) for p in sources]
    _try_attempts(
        runner.build,
        [
            dict(hdl_toplevel=TOP_MODULE, timescale=("1ns", "1ps"),
                 sources=src_paths, **base),                      # cocotb 2.x
            dict(hdl_toplevel=TOP_MODULE, timescale=("1ns", "1ps"),
                 verilog_sources=src_paths, **base),              # cocotb 2.x (old kwarg)
            dict(top_module=TOP_MODULE, timescale=("1ns", "1ps"),
                 verilog_sources=src_paths, **base),              # cocotb 1.x
            dict(hdl_toplevel=TOP_MODULE, sources=src_paths, **base),
            dict(top_module=TOP_MODULE, verilog_sources=src_paths, **base),
            dict(hdl_toplevel=TOP_MODULE, timescale=("1ns", "1ps"),
                 sources=src_paths, build_dir=str(BUILD_DIR),
                 waves=True, always=True),                        # no log_file
            dict(top_module=TOP_MODULE, verilog_sources=src_paths,
                 build_dir=str(BUILD_DIR), waves=True, always=True),
        ],
    )


def _run_tests(runner):
    """Version-tolerant runner.test(). Real failures raise SystemExit/Error
    and are NOT retried; only kwarg mismatches (TypeError) fall through."""
    base = dict(test_module=TEST_MODULE, build_dir=str(BUILD_DIR),
                test_dir=str(BUILD_DIR), log_file=str(TEST_LOG), waves=True)
    plain = dict(test_module=TEST_MODULE, build_dir=str(BUILD_DIR),
                 test_dir=str(BUILD_DIR), waves=True)
    _try_attempts(
        runner.test,
        [
            dict(hdl_toplevel=TOP_MODULE, **base),
            dict(top_module=TOP_MODULE, **base),
            dict(**base),
            dict(hdl_toplevel=TOP_MODULE, **plain),               # no log_file
            dict(top_module=TOP_MODULE, **plain),
            dict(**plain),
        ],
    )


def _report_results():
    """Parse cocotb's results.xml. Return (failed_count, summary lines)."""
    xml_path = BUILD_DIR / "results.xml"
    if not xml_path.exists():
        lines = [f"ERROR: {xml_path} not found; the simulation died before "
                 f"producing results."]
        return 1, lines
    tree = ET.parse(xml_path)
    lines = []
    total = failed = 0
    for testcase in tree.getroot().iter("testcase"):
        total += 1
        failure = testcase.find("failure")
        error = testcase.find("error")
        if failure is None and error is None:
            lines.append(f"  PASS: {testcase.get('name')}")
            continue
        failed += 1
        node = failure if failure is not None else error
        message = (node.get("message") or node.get("error_msg") or "").strip()
        lines.append(f"  FAIL: {testcase.get('name')}")
        if message:
            lines.append(f"        {message}")
    lines.append(f"cocotb results: {total - failed}/{total} tests passed")
    return failed, lines


def _read_log(path):
    if not path.exists():
        return "(no output)"
    return path.read_text(encoding="utf-8", errors="replace").rstrip() or "(empty)"


def _write_run_log(simulator, sources, summary_lines):
    """Combine the build transcript, the test transcript, and the summary."""
    body = [
        "AES-128 cocotb cross-check",
        f"time: {datetime.now():%Y-%m-%d %H:%M:%S}",
        f"simulator: {simulator}",
        f"rtl: {', '.join(src.name for src in sources)}",
        f"vcd: {VCD_PATH}",
        "",
        "-------- build --------",
        _read_log(BUILD_LOG).replace(
            "(empty)",
            "iverilog produced no console output",
        ),
        "",
        "-------- test --------",
        _read_log(TEST_LOG),
        "",
        "-------- summary --------",
        *summary_lines,
        "",
    ]
    RUN_LOG.write_text("\n".join(body), encoding="utf-8")
    return RUN_LOG


def main():
    sources = sorted(RTL_DIR.glob("*.v"))
    if not sources:
        sys.exit(f"ERROR: no Verilog sources found in {RTL_DIR}")
    if not (RTL_DIR / f"{TOP_MODULE}.v").exists():
        sys.exit(f"ERROR: {TOP_MODULE}.v not found in {RTL_DIR}")

    sim = "icarus" if shutil.which("iverilog") else "modelsim"
    if sim == "modelsim":
        if not Path(MODELSIM_BIN, "vsim.exe").exists():
            sys.exit(f"ERROR: neither iverilog on PATH nor ModelSim at {MODELSIM_BIN}")
        os.environ["PATH"] = MODELSIM_BIN + os.pathsep + os.environ.get("PATH", "")

    BUILD_DIR.mkdir(exist_ok=True)

    print(f"Simulator: {sim}")
    print(f"Log: {RUN_LOG}")
    print(f"VCD: {VCD_PATH}")

    runner = _make_runner(sim)

    rc = 0
    failed = 1
    summary = []
    try:
        print("Building...")
        _build(runner, sources)

        print("Running cocotb tests...")
        try:
            _run_tests(runner)
        except SystemExit as exc:  # cocotb may raise SystemExit on failed tests
            rc = exc.code if isinstance(exc.code, int) else 1
        failed, summary = _report_results()
        if failed == 0 and rc == 0:
            summary.append("ALL CROSS-CHECK TESTS PASSED")
        if VCD_PATH.exists() and VCD_PATH.stat().st_size > 0:
            summary.append(f"VCD: {VCD_PATH} ({VCD_PATH.stat().st_size} bytes)")
        else:
            summary.append(f"VCD: {VCD_PATH} was not written")
    finally:
        _write_run_log(sim, sources, summary)

    for line in summary:
        print(line)
    print(f"Log: {RUN_LOG}")
    print(f"VCD: {VCD_PATH}")
    sys.exit(rc or (1 if failed else 0))


if __name__ == "__main__":
    main()