@echo off
REM ML-Enhanced Deadbolt Testing Suite
REM Tests the ML-integrated system against various ransomware scenarios

echo ===============================================
echo    🤖 ML-Enhanced Deadbolt Testing Suite
echo    Advanced Ransomware Simulation Testing
echo ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [✅] Running with Administrator privileges
    echo [🛡️] Full ML-enhanced protection capabilities enabled
    echo.
) else (
    echo [❌] Not running as Administrator
    echo [⚠️] Some features may not work without admin privileges
    echo [💡] For full testing, right-click and "Run as Administrator"
    echo.
)

REM Change to project directory
cd /d "%~dp0.."

echo [🔍] Checking ML model status...
python -c "import os; ml_files = ['ml/best_iot_ransomware_model.joblib', 'ml/iot_ransomware_scaler.joblib', 'ml/iot_ransomware_features.joblib']; missing = [f for f in ml_files if not os.path.exists(f)]; print('[✅] ML Model: Available - Enhanced detection enabled') if not missing else print('[⚠️] ML Model: Missing - Using rule-based detection only'); print('Missing files:', missing) if missing else None"
echo.

echo [📋] Test Menu:
echo     1. Quick Test (Mass encryption scenario)
echo     2. Full Test Suite (All scenarios)
echo     3. Start Defender Only (No tests)
echo     4. ML Model Training
echo     5. Exit
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto quick_test
if "%choice%"=="2" goto full_test
if "%choice%"=="3" goto start_defender_only
if "%choice%"=="4" goto train_model
if "%choice%"=="5" goto exit
goto invalid_choice

:quick_test
echo.
echo [🚀] Starting Quick Test...
echo [⏰] Step 1: Starting ML-Enhanced Deadbolt Defender...
start /min "Deadbolt Defender" cmd /c "python deadbolt.py --daemon"

echo [⏱️] Waiting 10 seconds for Deadbolt to initialize...
timeout /t 10 /nobreak >nul

echo [🦠] Step 2: Running Mass Encryption Test...
python test_ransomware_advanced.py --scenario encrypt --delay 5

echo.
echo [✅] Quick test completed!
goto show_results

:full_test
echo.
echo [🚀] Starting Full Test Suite...
echo [⏰] Step 1: Starting ML-Enhanced Deadbolt Defender...
start /min "Deadbolt Defender" cmd /c "python deadbolt.py --daemon"

echo [⏱️] Waiting 15 seconds for Deadbolt to initialize...
timeout /t 15 /nobreak >nul

echo [🧪] Step 2: Running All Ransomware Scenarios...
echo     - Mass Encryption Attack
echo     - Mass Deletion Attack  
echo     - Stealth Rename Attack
echo     - Combined Multi-Vector Attack
echo.
python test_ransomware_advanced.py --scenario all --delay 8

echo.
echo [✅] Full test suite completed!
goto show_results

:start_defender_only
echo.
echo [🛡️] Starting ML-Enhanced Deadbolt Defender only...
echo [💡] Use Ctrl+C to stop when ready
echo.
python deadbolt.py --interactive
goto end

:train_model
echo.
echo [🤖] Training ML Model...
echo [📂] Changing to ML directory...
cd ml
echo [🔄] Starting training process...
python simple_iot_detection.py
cd ..
echo.
echo [✅] ML model training completed (if successful)
echo [💡] Run the test again to use the trained model
pause
goto end

:invalid_choice
echo.
echo [❌] Invalid choice. Please enter 1-5.
pause
goto end

:show_results
echo.
echo ===============================================
echo    📊 TEST RESULTS AND ANALYSIS
echo ===============================================
echo.
echo [📁] Generated test files in: test_files\
echo [📄] Check these log files for results:
echo.
echo [🤖] ML-Enhanced Detection Logs:
echo     - logs\ml_detector.log
echo     - logs\main.log
echo     - logs\detector.log
echo.
echo [📊] Threat Detection Results:
echo     - logs\threats.json
echo     - logs\responses.json
echo.
echo [🔍] What to look for:
echo     ✅ Fast detection (within 2-3 seconds)
echo     ✅ Process termination attempts
echo     ✅ Multi-channel notifications
echo     ✅ ML vs Rule-based detection indicators
echo.
echo [💡] Expected ML improvements:
echo     - Fewer false positives on legitimate processes
echo     - Enhanced network pattern analysis
echo     - Smart process targeting
echo.

REM Display recent threat detections
echo [📋] Recent threat detections:
if exist logs\threats.json (
    echo.
    powershell -Command "Get-Content logs\threats.json | Select-Object -Last 5"
) else (
    echo     No threats.json found - check if detection occurred
)

echo.
echo [🎯] Analysis Tips:
echo     1. Check if ML model was loaded in ml_detector.log
echo     2. Look for 'ML Model detected' messages
echo     3. Verify process termination attempts
echo     4. Check notification delivery
echo.

set /p view_logs="View ML detector log? (y/n): "
if /i "%view_logs%"=="y" (
    if exist logs\ml_detector.log (
        echo.
        echo [📄] Last 20 lines of ML detector log:
        powershell -Command "Get-Content logs\ml_detector.log | Select-Object -Last 20"
    ) else (
        echo [⚠️] ML detector log not found
    )
)

echo.
echo [🏁] Testing complete! 
echo [🛡️] Deadbolt may still be running in background
echo [💡] Use Task Manager to stop if needed
echo.
pause
goto end

:exit
echo.
echo [👋] Exiting test suite...
goto end

:end
echo.
echo [📊] Test session ended: %DATE% %TIME%
echo ===============================================