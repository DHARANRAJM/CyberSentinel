@echo off
setlocal

:: Set default values
set TARGET=%~1
set OUTPUT_DIR=Result_file

:: Check if target is provided
if "%TARGET%"=="" (
    echo Usage: %~nx0 [target]
    echo Example: %~nx0 example.com
    exit /b 1
)

:: Create reports directory if it doesn't exist
if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
    echo Created directory: %CD%\%OUTPUT_DIR%
)

echo Starting CyberSentinel scan for %TARGET%
echo Reports will be saved to: %CD%\%OUTPUT_DIR%
echo.

:: Run the scan with HTML output by default
python -m src.main --target %TARGET% --output html --output-dir "%OUTPUT_DIR%"

if %ERRORLEVEL% EQU 0 (
    echo.
    echo Scan completed successfully!
    echo Reports are available in: %CD%\%OUTPUT_DIR%
    start "" "%CD%\%OUTPUT_DIR%"
) else (
    echo.
    echo Scan completed with errors. Check the console output for details.
)

endlocal
