# =============================================================================
# ModelSim Build Script for AES-128 (PowerShell)
# =============================================================================

param(
    [string]$TestBench = "all",
    [switch]$Clean
)

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "========================================"
Write-Host "  AES-128 ModelSim Build Script"
Write-Host "========================================"
Write-Host ""

# Detect ModelSim installation
$ModelSimPaths = @(
    "C:\modeltech\win32",
    "C:\modeltech\win64",
    "C:\intelFPGA_lite\18.1\modelsim_ase\win32aloem",
    "C:\intelFPGA\18.1\modelsim_ae\win32aloem",
    "${env:QUESTA_HOME}\win64",
    "${env:MODELSIM_PATH}\win32"
)

$VsimPath = $null
foreach ($Path in $ModelSimPaths) {
    $TestPath = Join-Path $Path "vsim.exe"
    if (Test-Path $TestPath) {
        $VsimPath = (Split-Path $Path)
        $VlogPath = Join-Path $Path "vlog.exe"
        $VlibPath = Join-Path $Path "vlib.exe"
        Write-Host "Found ModelSim at: $VsimPath"
        break
    }
}

if (-not $VsimPath) {
    Write-Host "ERROR: ModelSim not found. Please install ModelSim or update this script."
    Write-Host ""
    Write-Host "Searched paths:"
    foreach ($Path in $ModelSimPaths) {
        Write-Host "  - $Path"
    }
    exit 1
}

# Set working directory
Set-Location $ProjectDir

# Clean work library if requested
if ($Clean -and (Test-Path "work")) {
    Write-Host "Cleaning work library..."
    Remove-Item -Recurse -Force "work"
}

# Create work library
Write-Host ""
Write-Host "Creating work library..."
& $VlibPath work

# =============================================================================
# Compile RTL files
# =============================================================================
Write-Host ""
Write-Host "========================================"
Write-Host "  Compiling RTL Files"
Write-Host "========================================"

$RtlFiles = @(
    "..\rtl\add_round_key.v",
    "..\rtl\sbox.v",
    "..\rtl\inv_sbox.v",
    "..\rtl\gf_mult.v",
    "..\rtl\mix_columns.v",
    "..\rtl\inv_mix_columns.v",
    "..\rtl\key_schedule.v",
    "..\rtl\aes128_pipeline_enc.v",
    "..\rtl\aes128_pipeline_dec.v",
    "..\rtl\aes128_top.v"
)

foreach ($File in $RtlFiles) {
    if (Test-Path $File) {
        Write-Host "  Compiling: $File"
        & $VlogPath -work work $File
    } else {
        Write-Host "  WARNING: File not found: $File"
    }
}

# =============================================================================
# Compile testbench files
# =============================================================================
Write-Host ""
Write-Host "========================================"
Write-Host "  Compiling Testbench Files"
Write-Host "========================================"

$TbFiles = @(
    "basic_ops_tb.v",
    "mix_columns_tb.v",
    "key_schedule_tb.v",
    "aes128_top_tb.v"
)

foreach ($File in $TbFiles) {
    if (Test-Path $File) {
        Write-Host "  Compiling: $File"
        & $VlogPath -work work $File
    } else {
        Write-Host "  WARNING: File not found: $File"
    }
}

Write-Host ""
Write-Host "========================================"
Write-Host "  Compilation Complete"
Write-Host "========================================"
Write-Host ""

# =============================================================================
# Run tests
# =============================================================================
$TestBenches = @{
    "basic" = "work.basic_ops_tb"
    "mix"   = "work.mix_columns_tb"
    "ks"    = "work.key_schedule_tb"
    "top"   = "work.aes128_top_tb"
}

$TestNames = @{
    "basic" = "Basic Operations"
    "mix"   = "MixColumns"
    "ks"    = "Key Schedule"
    "top"   = "AES-128 Top Module"
}

if ($TestBench -eq "all") {
    # Run all tests
    $TestsToRun = @("basic", "mix", "ks", "top")
} else {
    $TestsToRun = @($TestBench.ToLower())
}

foreach ($Test in $TestsToRun) {
    if ($TestBenches.ContainsKey($Test)) {
        $TbName = $TestBenches[$Test]
        $DisplayName = $TestNames[$Test]
        
        Write-Host ""
        Write-Host "========================================"
        Write-Host "  Running: $DisplayName"
        Write-Host "========================================"
        
        # Run simulation
        & $VsimPath\vsim -t 1ps -voptargs="+acc" -L work -do "run -all; quit -force" $TbName
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "WARNING: Test may have failed (exit code: $LASTEXITCODE)"
        }
    } else {
        Write-Host "ERROR: Unknown testbench: $Test"
        Write-Host "Available tests: basic, mix, ks, top, all"
    }
}

Write-Host ""
Write-Host "========================================"
Write-Host "  Simulation Complete"
Write-Host "========================================"
