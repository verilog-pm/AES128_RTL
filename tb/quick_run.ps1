# =============================================================================
# ModelSim Quick Run Script for AES-128 (PowerShell)
# =============================================================================

$ErrorActionPreference = "Stop"
$ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Detect ModelSim installation
$ModelSimPaths = @(
    "C:\modeltech\win32",
    "C:\modeltech\win64",
    "C:\intelFPGA_lite\18.1\modelsim_ase\win32aloem",
    "C:\intelFPGA\18.1\modelsim_ae\win32aloem",
    "${env:QUESTA_HOME}\win64"
)

$VsimPath = $null
$VlogPath = $null

foreach ($Path in $ModelSimPaths) {
    $TestPath = Join-Path $Path "vsim.exe"
    if (Test-Path $TestPath) {
        $VsimPath = $Path
        $VlogPath = $Path
        break
    }
}

if (-not $VsimPath) {
    Write-Host "ERROR: ModelSim not found!"
    exit 1
}

Set-Location $ProjectDir

# Quick compile and run
Write-Host "Compiling AES-128..."

# Compile all files
& "$VlogPath\vlog" -work work ..\rtl\*.v 2>$null
& "$VlogPath\vlog" -work work *.v 2>$null

# Run simulation
Write-Host "Running simulation..."
& "$VsimPath\vsim" -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.aes128_top_tb

Write-Host "Done."
