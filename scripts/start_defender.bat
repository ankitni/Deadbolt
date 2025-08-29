@echo off
REM Deadbolt Ransomware Defender - Admin Start Script
REM Simplified script that ensures admin privileges and starts Deadbolt

echo ===============================================
echo    Deadbolt 5 Ransomware Defender
echo    Starting with Administrator Privileges
echo ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✅] Running with Administrator privileges
    echo [🛡️] Full process termination capabilities enabled
    echo.
) else (
    echo [❌] Not running as Administrator
    echo [⚠️] Process termination will fail without admin privileges
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

REM Change to project directory
cd /d "%~dp0.."

echo [🚀] Starting Deadbolt Defender...
echo [📂] Project directory: %CD%
echo [⏰] Start time: %DATE% %TIME%
echo.

REM Start Deadbolt in daemon mode
python deadbolt.py --daemon

echo.
echo [📊] Deadbolt Defender has stopped
echo [⏰] Stop time: %DATE% %TIME%
echo.
pause