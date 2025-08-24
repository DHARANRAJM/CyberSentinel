@echo off
setlocal

:: Set Python executable (use python3 if available, otherwise python)
where python >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    set PYTHON=python
) else (
    set PYTHON=python3
)

echo Starting CyberSentinel Scan...
echo Target: %*

:: Run the scan with the provided arguments
%PYTHON% -m src.main %*

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Error occurred during scan.
    echo Common issues:
    echo 1. Make sure you're in the CyberSentinel root directory
    echo 2. Run 'pip install -r requirements.txt' to install dependencies
    echo 3. Try running as administrator if you get permission errors
)

endlocal
