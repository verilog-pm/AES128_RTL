@echo off
REM =============================================================================
REM ModelSim Simulation Script for AES-128
REM =============================================================================

echo ========================================
echo   AES-128 ModelSim Simulation
echo ========================================
echo.

REM Set paths
set MODELSIM_PATH=C:\modeltech\win32
set PROJECT_DIR=%~dp0

REM Check if ModelSim is installed
if exist "%MODELSIM_PATH%\vsim.exe" (
    echo Using ModelSim from: %MODELSIM_PATH%
) else (
    echo ERROR: ModelSim not found at %MODELSIM_PATH%
    echo Please install ModelSim or update the MODELSIM_PATH variable
    pause
    exit /b 1
)

REM Change to testbench directory
cd /d "%PROJECT_DIR%"

REM Create work library
echo.
echo Creating work library...
if exist work rmdir /s /q work
mkdir work

REM Compile RTL files
echo.
echo ========================================
echo   Compiling RTL Files
echo ========================================
%MODELSIM_PATH%\vlog -work work ..\rtl\add_round_key.v
%MODELSIM_PATH%\vlog -work work ..\rtl\sbox.v
%MODELSIM_PATH%\vlog -work work ..\rtl\inv_sbox.v
%MODELSIM_PATH%\vlog -work work ..\rtl\gf_mult.v
%MODELSIM_PATH%\vlog -work work ..\rtl\mix_columns.v
%MODELSIM_PATH%\vlog -work work ..\rtl\inv_mix_columns.v
%MODELSIM_PATH%\vlog -work work ..\rtl\key_schedule.v
%MODELSIM_PATH%\vlog -work work ..\rtl\aes128_pipeline_enc.v
%MODELSIM_PATH%\vlog -work work ..\rtl\aes128_pipeline_dec.v
%MODELSIM_PATH%\vlog -work work ..\rtl\aes128_top.v

REM Compile testbench files
echo.
echo ========================================
echo   Compiling Testbench Files
echo ========================================
%MODELSIM_PATH%\vlog -work work basic_ops_tb.v
%MODELSIM_PATH%\vlog -work work mix_columns_tb.v
%MODELSIM_PATH%\vlog -work work key_schedule_tb.v
%MODELSIM_PATH%\vlog -work work aes128_top_tb.v

echo.
echo ========================================
echo   Compilation Complete
echo ========================================
echo.
echo To run a testbench, use one of these commands:
echo.
echo   vsim -do "run -all; quit -f" work.basic_ops_tb
echo   vsim -do "run -all; quit -f" work.mix_columns_tb
echo   vsim -do "run -all; quit -f" work.key_schedule_tb
echo   vsim -do "run -all; quit -f" work.aes128_top_tb
echo.
echo Or run all tests:
echo.
echo   vsim -do run_all.do
echo.

pause
