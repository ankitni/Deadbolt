@echo off
REM Deadbolt Ransomware Defender - Stop Script
REM This script stops the defender

echo Stopping Deadbolt Ransomware Defender...

REM Set up environment
cd /d "%~dp0"

REM Find and kill Python processes running main.py
echo Looking for Deadbolt Defender processes...

for /f "tokens=2" %%i in ('tasklist /fi "imagename eq python.exe" /fo table /nh ^| findstr /c:"python.exe"') do (
    REM Check if this python process is running our main.py
    wmic process where "ProcessId=%%i" get commandline | findstr /i "main.py" >nul
    if !errorlevel! == 0 (
        echo Terminating Deadbolt Defender process (PID: %%i)
        taskkill /f /pid %%i >nul 2>&1
    )
)

REM Alternative method using PowerShell for more precision
powershell -Command "Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like '*main.py*' } | ForEach-Object { Write-Host 'Stopping process:' $_.ProcessName 'PID:' $_.Id; Stop-Process -Id $_.Id -Force }" 2>nul

REM Also kill any processes named "Deadbolt Defender"
tasklist /fi "windowtitle eq Deadbolt Defender*" /fo csv | find /i "python.exe" >nul
if %errorLevel% == 0 (
    echo Terminating Deadbolt Defender window processes...
    taskkill /f /fi "windowtitle eq Deadbolt Defender*" >nul 2>&1
)

echo.
echo ================================================================
echo  DEADBOLT RANSOMWARE DEFENDER STOPPED
echo ================================================================
echo.
echo The defender has been stopped.
echo Your system is no longer being monitored for ransomware.
echo.
echo To restart protection, run: start_defender.bat
echo.
pause