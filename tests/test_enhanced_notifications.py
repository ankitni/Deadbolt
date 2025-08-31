#!/usr/bin/env python3
"""
Test script to verify enhanced notification system is working properly
This script tests the enhanced AlertManager with all notification methods
"""

import sys
import os
import time

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_enhanced_alert_manager():
    """Test the enhanced AlertManager functionality."""
    print("🧪 Testing Enhanced AlertManager System")
    print("=" * 50)
    
    try:
        # Import the enhanced AlertManager
        from ui.alerts import alert_manager
        
        print("✅ Enhanced AlertManager imported successfully")
        print(f"Available notification methods: {alert_manager.available_methods}")
        
        # Test 1: Basic alert
        print("\n--- Test 1: Basic Alert ---")
        alert_manager.show_alert(
            title="Test Alert",
            message="This is a basic test notification to verify the alert system.",
            severity="MEDIUM"
        )
        print("✅ Basic alert sent")
        time.sleep(3)
        
        # Test 2: High severity alert (should force notification)
        print("\n--- Test 2: High Severity Alert ---")
        alert_manager.show_alert(
            title="High Priority Test",
            message="This is a high priority test alert with forced notification.",
            severity="HIGH",
            force_notification=True
        )
        print("✅ High severity alert sent")
        time.sleep(3)
        
        # Test 3: Ransomware alert (specialized method)
        print("\n--- Test 3: Ransomware Alert ---")
        alert_manager.show_ransomware_alert(
            threat_type="mass_encryption",
            file_count=25,
            threat_score=95.7
        )
        print("✅ Ransomware alert sent")
        time.sleep(3)
        
        # Test 4: Test all methods
        print("\n--- Test 4: Testing All Methods ---")
        success = alert_manager.test_notifications()
        if success:
            print("✅ Notification test completed successfully")
        else:
            print("⚠️ Some notification methods may not be available")
        
        return True
        
    except ImportError as e:
        print(f"❌ Failed to import AlertManager: {e}")
        return False
    except Exception as e:
        print(f"❌ Test failed: {e}")
        return False

def test_core_integration():
    """Test that core components can use the enhanced AlertManager."""
    print("\n🔗 Testing Core Integration")
    print("=" * 50)
    
    try:
        # Test ML detector integration
        print("--- Testing ML Detector Integration ---")
        from core.ml_detector import MLThreatDetector
        
        def mock_responder(response_info):
            print(f"Mock responder called: {response_info.get('response_level', 'Unknown')}")
        
        detector = MLThreatDetector(mock_responder)
        print("✅ ML Detector with enhanced notifications initialized")
        
        # Test responder integration
        print("\n--- Testing Responder Integration ---")
        from core.responder import ThreatResponder
        
        responder = ThreatResponder()
        print("✅ Threat Responder with enhanced notifications initialized")
        
        return True
        
    except Exception as e:
        print(f"❌ Core integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_notification_dependencies():
    """Test notification library dependencies."""
    print("\n📦 Testing Notification Dependencies")
    print("=" * 50)
    
    results = {}
    
    # Test win10toast
    try:
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
        toaster.show_toast(
            title="🧪 Dependency Test - win10toast",
            msg="Win10toast library is working correctly!",
            duration=3,
            threaded=True
        )
        results['win10toast'] = True
        print("✅ win10toast: Working")
    except Exception as e:
        results['win10toast'] = False
        print(f"❌ win10toast: Failed - {e}")
    
    time.sleep(1)
    
    # Test plyer
    try:
        from plyer import notification
        notification.notify(
            title="🧪 Dependency Test - plyer",
            message="Plyer library is working correctly!",
            timeout=3
        )
        results['plyer'] = True
        print("✅ plyer: Working")
    except Exception as e:
        results['plyer'] = False
        print(f"❌ plyer: Failed - {e}")
    
    time.sleep(1)
    
    # Test Windows API
    try:
        import ctypes
        import threading
        
        def show_test_popup():
            ctypes.windll.user32.MessageBoxW(
                0,
                "Windows API notification is working correctly!",
                "🧪 Dependency Test - Windows API",
                0x40  # MB_ICONINFORMATION
            )
        
        # Show in separate thread so it doesn't block
        threading.Thread(target=show_test_popup, daemon=True).start()
        results['winapi'] = True
        print("✅ Windows API: Working")
    except Exception as e:
        results['winapi'] = False
        print(f"❌ Windows API: Failed - {e}")
    
    print(f"\nSummary: {sum(results.values())}/{len(results)} notification methods working")
    return sum(results.values()) > 0

def main():
    """Run all notification tests."""
    print("🛡️ Deadbolt Enhanced Notification System Test")
    print("=" * 60)
    print(f"Testing on: Windows")
    print(f"Python version: {sys.version}")
    print()
    
    test_results = []
    
    # Test dependencies first
    test_results.append(("Dependencies", test_notification_dependencies()))
    
    # Test enhanced AlertManager
    test_results.append(("AlertManager", test_enhanced_alert_manager()))
    
    # Test core integration
    test_results.append(("Core Integration", test_core_integration()))
    
    # Summary
    print("\n" + "=" * 60)
    print("🏁 TEST SUMMARY")
    print("=" * 60)
    
    passed = 0
    total = len(test_results)
    
    for test_name, result in test_results:
        status = "✅ PASSED" if result else "❌ FAILED"
        print(f"{test_name:20} {status}")
        if result:
            passed += 1
    
    print(f"\nOverall: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n🎉 All tests passed! Enhanced notifications are working correctly.")
        print("\nThe notification system should now work properly when:")
        print("- Ransomware is detected by start_defender.bat")
        print("- ML model detects malicious behavior")
        print("- Process termination occurs")
        print("- Critical threats are neutralized")
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Some notifications may not work.")
        print("\nCheck the error messages above to troubleshoot issues.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    
    print("\n" + "=" * 60)
    print("To test with actual ransomware detection:")
    print("1. Run: scripts\\start_defender.bat")
    print("2. Run: python good.py (or any ransomware test)")
    print("3. You should see desktop notifications when threats are detected")
    print("=" * 60)
    
    input("\nPress Enter to exit...")
    sys.exit(0 if success else 1)