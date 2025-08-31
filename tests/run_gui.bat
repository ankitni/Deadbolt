@echo off
REM ====================================================
REM Deadbolt AI - GUI Launcher (Administrator Mode)
REM ====================================================

echo.
echo ========================================
echo  Deadbolt AI - GUI Control Panel
echo ========================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [INFO] Running with Administrator privileges
    echo.
) else (
    echo [WARNING] Not running as Administrator
    echo Some features may be limited without admin privileges
    echo.
    echo To run with full privileges:
    echo 1. Right-click this file
    echo 2. Select "Run as administrator"
    echo.
    pause
)

REM Set working directory to script location
cd /d "%~dp0"

REM Check if Python is available
python --version >nul 2>&1
if %errorLevel% neq 0 (
    echo [ERROR] Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

echo [INFO] Python found - checking dependencies...

REM Install/check requirements if requirements.txt exists
if exist requirements.txt (
    echo [INFO] Installing/checking Python dependencies...
    python -m pip install -r requirements.txt --quiet
    if %errorLevel% neq 0 (
        echo [WARNING] Some dependencies may not have installed correctly
    )
)

echo.
echo [INFO] Starting Deadbolt AI GUI...
echo.

REM Start the GUI with proper error handling
python -c "
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.getcwd(), 'src'))

try:
    # Try to import and run the GUI
    from ui.main_gui import run_gui
    print('[INFO] GUI modules loaded successfully')
    print('[INFO] Launching Deadbolt AI Control Panel...')
    print()
    exit_code = run_gui()
    sys.exit(exit_code)
except ImportError as e:
    print(f'[ERROR] Failed to import GUI modules: {e}')
    print('[INFO] Trying alternative import method...')
    try:
        # Alternative method
        import subprocess
        result = subprocess.run([sys.executable, 'src/ui/main_gui.py'], 
                              cwd=os.getcwd(), capture_output=False)
        sys.exit(result.returncode)
    except Exception as e2:
        print(f'[ERROR] Alternative method failed: {e2}')
        print()
        print('Please check that all files are in place:')
        print('- src/ui/main_gui.py')
        print('- src/utils/logger.py')
        print('- src/core/ modules')
        sys.exit(1)
except Exception as e:
    print(f'[ERROR] Unexpected error: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"

REM Check exit code
if %errorLevel% neq 0 (
    echo.
    echo [ERROR] GUI exited with error code %errorLevel%
    echo.
    echo Troubleshooting:
    echo 1. Make sure all Python dependencies are installed
    echo 2. Check that PyQt5 is properly installed: pip install PyQt5
    echo 3. Verify all source files are present
    echo 4. Try running as Administrator
    echo.
    pause
) else (
    echo.
    echo [INFO] GUI closed successfully
)

echo.
echo Thank you for using Deadbolt AI!
pause