@echo off
REM Speed Test for Deadbolt with Admin Privileges
echo ===============================================
echo    Deadbolt Speed Test - Admin Mode
echo    Testing Aggressive Detection Settings
echo ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✅] Running with Administrator privileges
    echo [⚡] Ultra-fast process termination enabled
    echo.
) else (
    echo [❌] Not running as Administrator
    echo [⚠️] Process termination will be slower without admin privileges
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

REM Change to project directory
cd /d "%~dp0.."

echo [🚀] Starting speed test...
echo [📂] Project directory: %CD%
echo.

REM Run the speed test
python speed_test.py

echo.
echo [📊] Speed test complete
echo.
pause