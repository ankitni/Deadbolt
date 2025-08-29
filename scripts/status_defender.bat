@echo off
REM Deadbolt Ransomware Defender - Status Check Script
REM This script checks the status of the defender

echo Checking Deadbolt Ransomware Defender Status...

REM Set up environment
cd /d "%~dp0"

REM Check if Python is available
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    pause
    exit /b 1
)

echo.
echo ================================================================
echo  DEADBOLT RANSOMWARE DEFENDER STATUS
echo ================================================================
echo.

REM Check if defender process is running
set "defender_running=false"
for /f "tokens=2" %%i in ('tasklist /fi "imagename eq python.exe" /fo table /nh ^| findstr /c:"python.exe"') do (
    wmic process where "ProcessId=%%i" get commandline | findstr /i "main.py" >nul
    if !errorlevel! == 0 (
        set "defender_running=true"
        echo Status: RUNNING (PID: %%i)
        goto :status_check
    )
)

if "%defender_running%"=="false" (
    echo Status: NOT RUNNING
    echo.
    echo The Deadbolt Defender is not currently running.
    echo To start protection, run: start_defender.bat
    echo.
    goto :end
)

:status_check
echo.
echo Getting detailed status...
python main.py --status 2>nul
if %errorLevel% neq 0 (
    echo Could not retrieve detailed status.
    echo The defender may be starting up or experiencing issues.
)

echo.
echo Recent log entries:
echo ------------------
if exist "logs\main.log" (
    powershell -Command "Get-Content 'logs\main.log' -Tail 5" 2>nul
) else (
    echo No main log file found.
)

echo.
echo Threat log entries:
echo ------------------
if exist "logs\threats.json" (
    powershell -Command "if (Test-Path 'logs\threats.json') { $content = Get-Content 'logs\threats.json' -Tail 3; if ($content) { $content } else { 'No threats detected yet.' } } else { 'No threat log found.' }" 2>nul
) else (
    echo No threats detected yet.
)

echo.
echo Response log entries:
echo --------------------
if exist "logs\responses.json" (
    powershell -Command "if (Test-Path 'logs\responses.json') { $content = Get-Content 'logs\responses.json' -Tail 3; if ($content) { $content } else { 'No responses triggered yet.' } } else { 'No response log found.' }" 2>nul
) else (
    echo No responses triggered yet.
)

:end
echo.
echo ================================================================
echo.
pause