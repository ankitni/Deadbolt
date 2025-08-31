@echo off
REM Deadbolt 5 - Website Launcher
echo ===============================================
echo    🛡️  DEADBOLT 5 CYBERSECURITY WEBSITE
echo    🚀 Interactive 3D Ransomware Defense Demo
echo ===============================================
echo.

REM Change to website directory
cd /d "%~dp0"

echo [🌐] Starting Deadbolt website server...
echo [📂] Website directory: %CD%
echo [⏰] Start time: %DATE% %TIME%
echo.

REM Start the website server
python server.py

echo.
echo [📊] Website server stopped
echo [⏰] Stop time: %DATE% %TIME%
echo.
pause