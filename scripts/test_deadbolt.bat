@echo off
REM Simple test script to verify Deadbolt can detect and kill good.py
REM Must be run as Administrator

echo ===============================================
echo    Testing Deadbolt vs good.py
echo    This will test if Deadbolt can kill good.py
echo ===============================================
echo.

REM Check admin privileges
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo [X] Not running as Administrator
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

echo [✓] Running with Administrator privileges
echo.

REM Change to project directory
cd /d "%~dp0.."

REM Clean up any existing test files
if exist "C:\Users\MADHURIMA\Documents\testtxt" (
    echo [🧹] Cleaning existing test files...
    rmdir /s /q "C:\Users\MADHURIMA\Documents\testtxt" >nul 2>&1
)

echo [🛡️] Starting Deadbolt in background...
start /min "Deadbolt Test" python deadbolt.py --daemon

echo [⏳] Waiting 5 seconds for Deadbolt to initialize...
timeout /t 5 /nobreak >nul

echo [🦠] Running good.py (ransomware simulation)...
echo     This should be detected and killed by Deadbolt
echo.

REM Run good.py and capture its process
start "Ransomware Test" python good.py

echo [👀] Monitor the console for:
echo     - Windows notifications from Deadbolt
echo     - good.py process termination
echo.
echo [📝] Check logs\detector.log for detection evidence
echo [📝] Check logs\responder.log for termination evidence
echo.
echo Press any key to stop the test...
pause >nul

REM Stop Deadbolt
taskkill /f /im python.exe /fi "windowtitle eq Deadbolt Test" >nul 2>&1

echo.
echo [✓] Test completed
echo Check the logs folder for detailed results
pause