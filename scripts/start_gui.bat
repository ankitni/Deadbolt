@echo off
REM Deadbolt Ransomware Defender - GUI Launcher
echo ===============================================
echo    🛡️  Deadbolt 5 Ransomware Defender
echo    🖥️  Starting with Graphical Interface
echo ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✅] Running with Administrator privileges
    echo [🛡️] Full protection capabilities enabled
    echo.
) else (
    echo [⚠️] Not running as Administrator
    echo [💡] For full protection, right-click and "Run as Administrator"
    echo.
)

REM Change to project directory
cd /d "%~dp0.."

echo [🚀] Starting Deadbolt Defender GUI...
echo [📂] Project directory: %CD%
echo [⏰] Start time: %DATE% %TIME%
echo.

REM Check if PyQt5 is available
echo [🔍] Checking GUI dependencies...
python -c "import PyQt5, pyqtgraph, matplotlib; print('All GUI dependencies available')" 2>nul
if %errorLevel% neq 0 (
    echo [❌] Missing GUI dependencies! Installing...
    echo [📦] Installing PyQt5, pyqtgraph, matplotlib...
    pip install PyQt5 pyqtgraph matplotlib
    if %errorLevel% neq 0 (
        echo [❌] Failed to install dependencies. Please install manually:
        echo     pip install PyQt5 pyqtgraph matplotlib
        pause
        exit /b 1
    )
    echo [✅] GUI dependencies installed successfully
else (
    echo [✅] All GUI dependencies found
)

REM Start Deadbolt with GUI - try multiple methods
echo [🖥️] Launching full-featured graphical interface...
echo.

REM Method 1: Dedicated full GUI launcher (primary method)
echo [🚀] Method 1: Using dedicated full GUI launcher...
python run_full_gui.py
if %errorLevel% == 0 (
    echo [✅] Full GUI started successfully
    goto :end
)

echo [⚠️] Method 1 failed, trying method 2...

REM Method 2: Direct import from main_gui.py
echo [🚀] Method 2: Direct GUI import...
python -c "import sys; sys.path.insert(0, 'src'); from ui.main_gui import run_gui; run_gui()"
if %errorLevel% == 0 (
    echo [✅] Direct GUI started successfully
    goto :end
)

echo [⚠️] Method 2 failed, trying method 3...

REM Method 3: Enhanced launcher with full GUI
echo [🚀] Method 3: Using enhanced GUI launcher...
python launch_gui.py
if %errorLevel% == 0 (
    echo [✅] Enhanced GUI started successfully
    goto :end
)

echo [⚠️] Method 3 failed, trying method 4...

REM Method 4: Standard deadbolt.py with --gui flag
echo [🚀] Method 4: Using deadbolt.py --gui...
python deadbolt.py --gui
if %errorLevel% == 0 (
    echo [✅] Main GUI started successfully
    goto :end
)

echo [⚠️] Method 4 failed, trying method 5...

REM Method 5: Direct core main with GUI flag
echo [🚀] Method 5: Using core main module...
python -m src.core.main --gui
if %errorLevel% == 0 (
    echo [✅] Core GUI started successfully
    goto :end
)

echo [⚠️] Method 5 failed, trying method 6...

REM Method 6: Minimal GUI (fallback only)
echo [🚀] Method 6: Fallback to minimal GUI...
python minimal_gui.py
if %errorLevel% == 0 (
    echo [✅] Minimal GUI started successfully (fallback mode)
    goto :end
)

REM All methods failed
echo [❌] All GUI startup methods failed!
echo [💡] Troubleshooting suggestions:
echo     1. Check if you're running Windows (GUI requires Windows)
echo     2. Verify Python installation: python --version
echo     3. Install dependencies: pip install PyQt5 pyqtgraph matplotlib
echo     4. Try direct launcher: python run_full_gui.py
echo     5. Try direct import: python -c "from src.ui.main_gui import run_gui; run_gui()" 
echo     6. Check logs folder for error details
echo     7. Run minimal GUI as last resort: python minimal_gui.py
echo.
echo [📞] For support, check the logs or run in debug mode

:end
echo.
echo [📊] GUI session ended
echo [⏰] End time: %DATE% %TIME%
echo.
pause