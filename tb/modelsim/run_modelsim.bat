@echo off
setlocal EnableExtensions
cd /d "%~dp0"

if "%MODELSIM_HOME%"=="" set "MODELSIM_HOME=C:\modeltech64_2020.4\win64"
set "VLOG=%MODELSIM_HOME%\vlog.exe"
set "VLIB=%MODELSIM_HOME%\vlib.exe"
set "VSIM=%MODELSIM_HOME%\vsim.exe"
set "RTL_DIR=%~dp0..\..\rtl"
set "TB_DIR=%~dp0..\verilog"

if not exist "%VLOG%" (
    echo ERROR: vlog.exe not found under MODELSIM_HOME=%MODELSIM_HOME%
    exit /b 1
)

if /I "%REGEN%"=="1" (
    python "%TB_DIR%\gen_vectors.py" || exit /b 1
    python "%TB_DIR%\gen_stream_vectors.py" || exit /b 1
    python "%TB_DIR%\gen_mode_vectors.py" cbc || exit /b 1
    python "%TB_DIR%\gen_mode_vectors.py" ctr || exit /b 1
)

cd /d "%TB_DIR%"
if exist work rmdir /s /q work
"%VLIB%" work
if errorlevel 1 exit /b 1

for %%F in ("%RTL_DIR%\*.v") do (
    echo Compiling %%~nxF
    "%VLOG%" -work work "%%F"
    if errorlevel 1 exit /b 1
)

"%VLOG%" -sv -work work +incdir+. basic_ops_tb.v mix_columns_tb.v key_schedule_tb.v aes128_top_tb.v aes128_cross_check_tb.v aes128_streaming_tb.v aes128_streaming_cross_check_tb.v aes128_mode_cross_check_tb.v aes128_width_tb.v
if errorlevel 1 exit /b 1

for %%T in (basic_ops_tb mix_columns_tb key_schedule_tb aes128_top_tb aes128_cross_check_tb aes128_streaming_tb aes128_streaming_cross_check_tb aes128_mode_cross_check_tb aes128_width_tb) do (
    echo.
    echo ===== %%T =====
    "%VSIM%" -c -t 1ps -voptargs="+acc" -L work -do "run -all; quit -f" work.%%T
    if errorlevel 1 exit /b 1
)

echo.
echo All ModelSim tests finished.
exit /b 0
