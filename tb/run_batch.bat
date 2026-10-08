@echo off
REM =============================================================================
REM ModelSim Simulation Script for AES-128 (Batch Mode)
REM =============================================================================

set MODELSIM_HOME=C:\modeltech64_2020.4\win64
set TB_DIR=C:\workspace\temp\CursorGen\code\aes128\aes128\tb
set RTL_DIR=C:\workspace\temp\CursorGen\code\aes128\aes128\rtl

echo ========================================
echo   AES-128 ModelSim Simulation (Batch)
echo ========================================
echo.

REM Change to testbench directory
cd /d "%TB_DIR%"

REM Create work library
echo Creating work library...
if exist work rmdir /s /q work
mkdir work

REM Compile RTL files
echo.
echo ========================================
echo   Compiling RTL Files
echo ========================================

%MODELSIM_HOME%\vlog -work work %RTL_DIR%\add_round_key.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\sbox.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\inv_sbox.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\gf_mult.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\mix_columns.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\inv_mix_columns.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\key_schedule.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\aes128_pipeline_enc.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\aes128_pipeline_dec.v
%MODELSIM_HOME%\vlog -work work %RTL_DIR%\aes128_top.v

REM Compile testbench files
echo.
echo ========================================
echo   Compiling Testbench Files
echo ========================================

%MODELSIM_HOME%\vlog -work work %TB_DIR%\basic_ops_tb.v
%MODELSIM_HOME%\vlog -work work %TB_DIR%\mix_columns_tb.v
%MODELSIM_HOME%\vlog -work work %TB_DIR%\key_schedule_tb.v
%MODELSIM_HOME%\vlog -work work %TB_DIR%\aes128_top_tb.v
%MODELSIM_HOME%\vlog -work work %TB_DIR%\aes128_cross_check_tb.v
%MODELSIM_HOME%\vlog -work work %TB_DIR%\aes128_streaming_tb.v
%MODELSIM_HOME%\vlog -sv -work work %TB_DIR%\aes128_streaming_cross_check_tb.v
%MODELSIM_HOME%\vlog -sv -work work %TB_DIR%\aes128_mode_cross_check_tb.v

REM Generate fresh random cross-check vectors using pycryptodome (golden model)
echo.
echo ========================================
echo   Generating Python (pycryptodome) Cross-check Vectors
echo ========================================
python "%TB_DIR%\gen_vectors.py" 500 "%TB_DIR%\aes128_vectors.hex"
python "%TB_DIR%\gen_stream_vectors.py" 64 "%TB_DIR%\aes128_stream_vectors.hex"
python "%TB_DIR%\gen_mode_vectors.py" cbc 8 16 "%TB_DIR%\aes128_cbc_vectors.hex"
python "%TB_DIR%\gen_mode_vectors.py" ctr 8 16 "%TB_DIR%\aes128_ctr_vectors.hex"

echo.
echo ========================================
echo   Running Simulations
echo ========================================

REM Run all tests in batch mode
echo.
echo --- Running Basic Operations Test ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.basic_ops_tb

echo.
echo --- Running MixColumns Test ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.mix_columns_tb

echo.
echo --- Running Key Schedule Test ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.key_schedule_tb

echo.
echo --- Running AES-128 Top Test ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.aes128_top_tb

echo.
echo --- Running AES-128 Python Cross-check Test (10 random vectors, waveform enabled) ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.aes128_cross_check_tb

echo.
echo --- Running AES-128 Streaming Throughput Test (synthetic data, random gaps) ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.aes128_streaming_tb

echo.
echo --- Running AES-128 Streaming Cross-check Test (pycryptodome vectors, continuous pipeline transfer) ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.aes128_streaming_cross_check_tb

echo.
echo --- Running AES-128 CBC/CTR Cross-check Test (pycryptodome vectors, op_mode select) ---
%MODELSIM_HOME%\vsim -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.aes128_mode_cross_check_tb

echo.
echo ========================================
echo   Simulation Complete
echo ========================================
pause
