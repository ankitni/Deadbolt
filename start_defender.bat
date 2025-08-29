@echo off
REM Deadbolt Ransomware Defender - Start Script
REM This script starts the defender with administrative privileges

echo Starting Deadbolt Ransomware Defender...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges - Good!
) else (
    echo This script requires administrator privileges for optimal protection.
    echo Attempting to restart with administrator privileges...
    powershell -Command "Start-Process cmd -ArgumentList '/c cd /d %~dp0 && start_defender.bat' -Verb RunAs"
    exit /b
)

REM Set up environment
cd /d "%~dp0"

REM Check if Python is available
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo Error: Python is not installed or not in PATH
    echo Please install Python 3.7 or later
    pause
    exit /b 1
)

REM Check for required Python packages
echo Checking Python dependencies...
python -c "import watchdog, psutil, win10toast" >nul 2>&1
if %errorLevel% neq 0 (
    echo Installing required Python packages...
    pip install watchdog psutil win10toast python-dotenv
    if %errorLevel% neq 0 (
        echo Error: Failed to install required packages
        echo Please run: pip install watchdog psutil win10toast python-dotenv
        pause
        exit /b 1
    )
)

REM Compile C++ killer if needed
if not exist "DeadboltKiller.exe" (
    echo Compiling DeadboltKiller.cpp...
    g++ -o DeadboltKiller.exe DeadboltKiller.cpp -lpsapi -static-libgcc -static-libstdc++ >nul 2>&1
    if %errorLevel% neq 0 (
        echo Warning: Failed to compile DeadboltKiller.cpp
        echo The system will work but C++ killer will not be available
    ) else (
        echo DeadboltKiller.exe compiled successfully
    )
)

REM Create logs directory
if not exist "logs" mkdir logs

REM Start the defender
echo.
echo ================================================================
echo  DEADBOLT RANSOMWARE DEFENDER STARTING
echo ================================================================
echo.
echo The defender is now starting in the background...
echo This will monitor your system for ransomware-like behavior.
echo.
echo To stop the defender, run: stop_defender.bat
echo To check status, run: status_defender.bat
echo.

REM Start in daemon mode (background)
start /min "Deadbolt Defender" python main.py --daemon

echo Deadbolt Defender started successfully!
echo Check the logs folder for detailed information.
echo.
pause