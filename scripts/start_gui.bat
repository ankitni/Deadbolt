@echo off
REM Enhanced Deadbolt GUI Launcher with Integrated Backend Protection
echo ===============================================
echo    🛡️  Deadbolt 5 Ransomware Defender
echo    🖥️  GUI + Backend Protection
echo ===============================================
echo.

REM Check administrator privileges
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✅] Administrator privileges: ENABLED
    echo [🛡️] Full protection capabilities: ACTIVE
) else (
    echo [⚠️] Administrator privileges: LIMITED
    echo [💡] For full protection: Right-click → "Run as Administrator"
)
echo.

REM Navigate to project directory
cd /d "%~dp0.."
echo [📁] Project directory: %CD%
echo [⏰] Start time: %DATE% %TIME%
echo.

REM Verify dependencies
echo [🔍] Checking dependencies...
python -c "import PyQt5, matplotlib, win10toast; print('[✅] All dependencies available')" 2>nul
if %errorLevel% neq 0 (
    echo [📦] Installing missing dependencies...
    pip install PyQt5 matplotlib win10toast plyer
    if %errorLevel% neq 0 (
        echo [❌] Dependency installation failed
        echo Manual installation: pip install -r requirements.txt
        pause & exit /b 1
    )
    echo [✅] Dependencies installed
) else (
    echo [✅] Dependencies verified
)

REM Check ML model status  
echo [🤖] ML Enhancement status...
python -c "import os; print('[✅] ML Model: Available') if os.path.exists('ml/best_iot_ransomware_model.joblib') else print('[⚠️] ML Model: Missing - Rule-based fallback')"
echo.

REM Launch integrated system
echo [🚀] Starting integrated GUI + Backend protection...
echo [🛡️] Backend protection will auto-start
echo [📊] Real-time threat dashboard enabled
echo [🔔] Desktop notifications active
echo.

REM Primary method: Enhanced main with GUI+Backend
python deadbolt.py --gui
if %errorLevel% == 0 goto success

REM Fallback method: Direct core module
echo [⚠️] Trying fallback method...
python -m src.core.main --gui
if %errorLevel% == 0 goto success

REM Error handling
echo [❌] GUI startup failed!
echo [💡] Try: scripts\start_defender.bat (backend only)
echo [🔧] Or: python deadbolt.py --debug
goto end

:success
echo [✅] GUI session completed successfully

:end
echo [⏰] End time: %DATE% %TIME%
echo [📝] Logs: logs\main.log, logs\ml_detector.log
echo.
pause