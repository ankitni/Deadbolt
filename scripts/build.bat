@echo off
REM Deadbolt 5 - Build and Setup Script
REM Compiles C++ components and prepares the system

echo ===============================================
echo  DEADBOLT 5 - BUILD AND SETUP
echo ===============================================

REM Set up paths
cd /d "%~dp0.."
set PROJECT_ROOT=%CD%

echo Project root: %PROJECT_ROOT%

REM Create necessary directories
echo Creating directory structure...
if not exist "bin" mkdir bin
if not exist "logs" mkdir logs
if not exist "build" mkdir build

REM Install Python dependencies
echo.
echo Installing Python dependencies...
pip install -r requirements.txt
if %errorLevel% neq 0 (
    echo Error: Failed to install Python dependencies
    echo Please run: pip install -r requirements.txt
    pause
    exit /b 1
)

REM Compile C++ component
echo.
echo Compiling C++ process killer...
if exist "src\core\DeadboltKiller.cpp" (
    g++ -o bin\DeadboltKiller.exe src\core\DeadboltKiller.cpp -lpsapi -static-libgcc -static-libstdc++
    if %errorLevel% == 0 (
        echo ✓ DeadboltKiller.exe compiled successfully
    ) else (
        echo ✗ Failed to compile DeadboltKiller.cpp
        echo Warning: C++ killer will not be available
    )
) else (
    echo ✗ DeadboltKiller.cpp not found
)

REM Check configuration
echo.
echo Checking configuration...
if exist "config\deadbolt_config.json" (
    echo ✓ Configuration file found
) else (
    echo ! Creating default configuration
    python -c "from src.utils.config_manager import config_manager; config_manager.create_default_config()"
)

REM Test imports
echo.
echo Testing module imports...
python -c "from src.core import DeadboltDefender, ThreatDetector, ThreatResponder, FileSystemWatcher; print('✓ Core modules imported successfully')"
if %errorLevel% neq 0 (
    echo ✗ Failed to import core modules
    pause
    exit /b 1
)

python -c "from src.ui import DeadboltMainWindow; print('✓ UI modules imported successfully')"
if %errorLevel% neq 0 (
    echo ✗ Failed to import UI modules
    echo Warning: GUI functionality may not work
)

echo.
echo ===============================================
echo  BUILD COMPLETE
echo ===============================================
echo.
echo Ready to use Deadbolt 5:
echo.
echo • GUI Mode:        python deadbolt.py --gui
echo • Daemon Mode:     python deadbolt.py --daemon  
echo • Interactive:    python deadbolt.py --interactive
echo.
echo • Using scripts:
echo   - scripts\start_defender.bat
echo   - scripts\start_gui.bat
echo   - scripts\stop_defender.bat
echo.
pause