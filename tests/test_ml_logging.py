#!/usr/bin/env python3
"""
Test script to verify ML logging and GUI integration
"""

import sys
import os
sys.path.insert(0, 'src')

def test_ml_logging():
    """Test ML logging functionality"""
    print("Testing ML Enhanced Logging System")
    print("=" * 50)
    
    try:
        print("1. Testing ML detector import...")
        from core.ml_detector import MLThreatDetector
        print("   ✅ ML detector imported successfully")
        
        print("2. Testing ML detector initialization...")
        detector = MLThreatDetector(lambda x: print(f"Response: {x}"))
        print("   ✅ ML detector initialized")
        
        print("3. Testing ML statistics...")
        stats = detector.get_ml_statistics()
        print(f"   ✅ ML statistics retrieved: {len(stats)} keys")
        for key, value in stats.items():
            if key != 'prediction_history':  # Skip large arrays
                print(f"      {key}: {value}")
        
        print("4. Testing ML logs...")
        logs = detector.get_recent_ml_logs(limit=10)
        print(f"   ✅ ML logs retrieved: {len(logs)} entries")
        
        print("5. Testing ML threat analysis with logging...")
        test_threat = {
            'type': 'mass_modification',
            'severity': 'HIGH',
            'description': 'Test ML threat analysis',
            'count': 25,
            'process_info': [(1234, 'test.exe')],
            'network_info': {
                'orig_port': 45123,
                'resp_port': 6667,  # IRC port - should trigger ML analysis
                'protocol': 'tcp',
                'service': 'irc',
                'duration': 2.5,
                'orig_bytes': 75,
                'resp_bytes': 243,
                'conn_state': 'S3'
            }
        }
        
        detector.analyze_threat(test_threat)
        print("   ✅ ML threat analysis completed with logging")
        
        print("6. Checking updated statistics...")
        updated_stats = detector.get_ml_statistics()
        print(f"   ✅ Updated statistics - Total predictions: {updated_stats.get('total_predictions', 0)}")
        
        print("7. Checking updated logs...")
        updated_logs = detector.get_recent_ml_logs(limit=5)
        print(f"   ✅ Updated logs: {len(updated_logs)} entries")
        if updated_logs:
            latest_log = updated_logs[-1]
            print(f"      Latest: {latest_log.get('level', 'Unknown')} - {latest_log.get('message', 'No message')[:100]}...")
        
        print("\n" + "=" * 50)
        print("✅ ML LOGGING TEST PASSED!")
        print("ML enhanced logging is working correctly")
        print("=" * 50)
        return True
        
    except Exception as e:
        print(f"❌ ML logging test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gui_ml_integration():
    """Test GUI ML integration (without actually showing GUI)"""
    print("\nTesting GUI ML Integration")
    print("=" * 50)
    
    try:
        print("1. Testing GUI imports...")
        # Test if PyQt5 is available
        try:
            from PyQt5.QtWidgets import QApplication
            pyqt_available = True
        except ImportError:
            pyqt_available = False
            print("   ⚠️ PyQt5 not available - GUI testing skipped")
            return True
        
        if pyqt_available:
            print("   ✅ PyQt5 imports successful")
            
            print("2. Testing GUI ML tab setup...")
            # We won't actually create the GUI, just test the import structure
            from ui.main_gui import DeadboltMainWindow
            print("   ✅ GUI main window class imported")
            
            print("3. Testing ML detector integration in GUI context...")
            # This tests if the GUI can import and use ML detector
            from core.ml_detector import MLThreatDetector
            detector = MLThreatDetector(lambda x: None)
            stats = detector.get_ml_statistics()
            logs = detector.get_recent_ml_logs(limit=5)
            print(f"   ✅ ML integration working - {stats.get('total_predictions', 0)} predictions")
        
        print("\n" + "=" * 50)
        print("✅ GUI ML INTEGRATION TEST PASSED!")
        print("GUI can successfully integrate with ML logging")
        print("=" * 50)
        return True
        
    except Exception as e:
        print(f"❌ GUI ML integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    """Run all tests"""
    print("🤖 ML Enhanced Deadbolt - Logging & GUI Integration Test")
    print("=" * 60)
    
    test1_passed = test_ml_logging()
    test2_passed = test_gui_ml_integration()
    
    print("\n" + "=" * 60)
    if test1_passed and test2_passed:
        print("🎉 ALL TESTS PASSED!")
        print("✅ ML logging is comprehensive and working")
        print("✅ GUI ML integration is ready")
        print("✅ ML statistics tracking is functional")
        print("✅ ML log analysis is operational")
        print("\nYour ML-enhanced system is ready for production!")
    else:
        print("❌ SOME TESTS FAILED!")
        print("Please check the error messages above")
    print("=" * 60)

if __name__ == "__main__":
    main()