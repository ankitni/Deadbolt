@echo off
REM Deadbolt Ransomware Defender - Interactive Mode Script
REM This script starts the defender in interactive mode for testing and monitoring

echo Starting Deadbolt Ransomware Defender in Interactive Mode...

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo Running with administrator privileges - Good!
) else (
    echo Warning: Not running as administrator. Some features may not work optimally.
    echo Consider running as administrator for full protection.
    pause
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
        pause
        exit /b 1
    )
)

REM Create logs directory
if not exist "logs" mkdir logs

echo.
echo ================================================================
echo  DEADBOLT RANSOMWARE DEFENDER - INTERACTIVE MODE
echo ================================================================
echo.
echo This mode allows you to monitor the defender in real-time.
echo You can use commands like: status, threats, responses, help, stop
echo.
echo Starting interactive mode...
echo.

REM Start in interactive mode
python main.py --interactive --debug

echo.
echo Deadbolt Defender interactive session ended.
pause