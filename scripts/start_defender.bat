@echo off
REM Deadbolt Ransomware Defender - ML-Enhanced Admin Start Script
REM Simplified script that ensures admin privileges and starts ML-Enhanced Deadbolt

echo ===============================================
echo    Deadbolt 5 - ML-Enhanced Defender
echo    Starting with Administrator Privileges
echo ===============================================
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo [OK] Running with Administrator privileges
    echo [Security] Full process termination capabilities enabled
    echo [ML] ML-Enhanced detection ready
    echo.
) else (
    echo [ERROR] Not running as Administrator
    echo [WARNING] Process termination will fail without admin privileges
    echo.
    echo Please right-click this file and select "Run as Administrator"
    echo.
    pause
    exit /b 1
)

REM Change to project directory
cd /d "%~dp0.."

echo [Checking] Checking ML model availability...
python -c "import os; ml_files = ['ml/best_iot_ransomware_model.joblib', 'ml/iot_ransomware_scaler.joblib', 'ml/iot_ransomware_features.joblib']; missing = [f for f in ml_files if not os.path.exists(f)]; print('[OK] ML Model: Available - Enhanced detection enabled') if not missing else print('[WARNING] ML Model: Not trained - Using rule-based detection only'); print('    To train ML model: cd ml && python simple_iot_detection.py') if missing else print('    ML-enhanced threat detection with reduced false positives')"
echo.

echo [Testing] Testing ML integration...
python -c "import sys, os; sys.path.insert(0, 'src'); from core.detector import ThreatDetector; detector = ThreatDetector(lambda x: None); print('[OK] ML Detector: Successfully imported'); print('[ML] Model loaded:', 'Yes' if hasattr(detector, 'ml_model') and detector.ml_model else 'No'); detector.start_monitoring(); detector.stop_monitoring(); print('[OK] ML Integration: Ready')" 2>nul
if %errorLevel% == 0 (
    echo [OK] ML Integration: Ready
) else (
    echo [WARNING] ML Integration test failed - will use fallback
)
echo.

echo [Starting] Starting ML-Enhanced Deadbolt Defender...
echo [Directory] Project directory: %CD%
echo [Time] Start time: %DATE% %TIME%
echo [ML] ML Enhancement: Integrated
echo.

REM Start ML-Enhanced Deadbolt in daemon mode (continuous background protection)
echo [Launching] Starting continuous background protection...
echo [🛡️] Deadbolt will run continuously until manually stopped
echo [🔄] Protection will remain active across multiple detections
echo [⚡] Real-time monitoring: ACTIVE
echo.
python deadbolt.py --daemon

REM Alternative startup method if main fails
if %errorLevel% neq 0 (
    echo [Retry] Primary startup failed, trying alternative...
    python -m src.core.main --daemon
)

echo.
echo [Complete] ML-Enhanced Deadbolt Defender has stopped
echo [Time] Stop time: %DATE% %TIME%
echo.
echo [Logs] Check logs folder for ML detection events:
echo     - logs\ml_detector.log (ML-enhanced detection)
echo     - logs\main.log (System events)
echo     - logs\threats.json (Detected threats)
echo.
pause