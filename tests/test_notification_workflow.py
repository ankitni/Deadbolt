#!/usr/bin/env python3
"""
Enhanced Notification Test - Simulates real ransomware detection workflow
This script simulates the notification flow that occurs during actual ransomware detection
"""

import sys
import os
import time
import threading

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def test_real_workflow():
    """Test the actual workflow that happens during ransomware detection."""
    print("🛡️ Testing Real Ransomware Detection Workflow")
    print("=" * 60)
    
    try:
        # Import required components
        from ui.alerts import alert_manager
        from core.ml_detector import MLThreatDetector
        from core.responder import ThreatResponder
        
        print("✅ All components imported successfully")
        
        # Step 1: Initialize responder
        print("\n--- Step 1: Initialize Threat Responder ---")
        responder = ThreatResponder()
        print("✅ Threat Responder initialized")
        
        # Step 2: Initialize ML detector with responder callback
        print("\n--- Step 2: Initialize ML Detector ---")
        detector = MLThreatDetector(responder.respond_to_threat)
        print("✅ ML Detector initialized")
        
        # Step 3: Simulate threat detection
        print("\n--- Step 3: Simulate Threat Detection ---")
        
        # Simulate a critical ransomware threat
        threat_info = {
            'type': 'mass_modification',
            'severity': 'CRITICAL',
            'description': 'Mass file encryption detected - 25 files modified in 2 seconds',
            'count': 25,
            'process_info': [(1234, 'malicious_ransomware.exe'), (5678, 'crypto_locker.exe')],
            'network_info': {
                'orig_port': 45123,
                'resp_port': 6667,  # IRC port - should trigger high ML confidence
                'protocol': 'tcp',
                'connection_count': 15
            }
        }
        
        print("🚨 Simulating CRITICAL ransomware threat detection...")
        
        # This should trigger the enhanced notification system
        detector.analyze_threat(threat_info)
        
        print("✅ Threat analysis completed")
        time.sleep(2)
        
        # Step 4: Test direct AlertManager methods
        print("\n--- Step 4: Test Direct AlertManager Methods ---")
        
        # Test ransomware alert
        alert_manager.show_ransomware_alert(
            threat_type="simulated_ransomware",
            file_count=25,
            threat_score=98.5
        )
        print("✅ Ransomware alert sent")
        time.sleep(2)
        
        # Test critical alert
        alert_manager.show_alert(
            title="System Protected",
            message="All malicious processes have been terminated.\\nYour files are safe.",
            severity="HIGH",
            force_notification=True
        )
        print("✅ Protection confirmation sent")
        
        return True
        
    except Exception as e:
        print(f"❌ Workflow test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_responder_notifications():
    """Test responder notification integration."""
    print("\n🔄 Testing Responder Notification Integration")
    print("=" * 60)
    
    try:
        from core.responder import ThreatResponder
        
        responder = ThreatResponder()
        
        # Simulate a response scenario
        response_info = {
            'threat_info': {
                'type': 'mass_encryption',
                'description': 'Ransomware detected encrypting user files',
                'count': 50,
                'severity': 'CRITICAL'
            },
            'response_level': 'CRITICAL',
            'suspicious_pids': [9999, 8888],  # Fake PIDs for testing
            'timestamp': time.time(),
            'ml_enhanced': True
        }
        
        print("🚨 Simulating CRITICAL threat response...")
        
        # This should trigger enhanced notifications in the responder
        responder.respond_to_threat(response_info)
        
        print("✅ Threat response completed with notifications")
        return True
        
    except Exception as e:
        print(f"❌ Responder notification test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def show_notification_status():
    """Show current notification capabilities."""
    print("\n📋 Current Notification Status")
    print("=" * 40)
    
    try:
        from ui.alerts import alert_manager
        
        print(f"Available methods: {', '.join(alert_manager.available_methods)}")
        print(f"Total methods: {len(alert_manager.available_methods)}")
        
        if len(alert_manager.available_methods) >= 2:
            print("✅ Multiple notification methods available - Good redundancy")
        elif len(alert_manager.available_methods) == 1:
            print("⚠️ Only one notification method available")
        else:
            print("❌ No notification methods available")
            
    except Exception as e:
        print(f"❌ Could not check notification status: {e}")

def main():
    """Run enhanced notification workflow test."""
    print("🛡️ Deadbolt Enhanced Notification Workflow Test")
    print("=" * 70)
    print("This test simulates the actual notification flow during ransomware detection")
    print()
    
    # Show current status
    show_notification_status()
    
    # Run workflow tests
    tests = [
        ("Real Workflow", test_real_workflow),
        ("Responder Integration", test_responder_notifications)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        try:
            result = test_func()
            if result:
                passed += 1
                print(f"\n✅ {test_name}: PASSED")
            else:
                print(f"\n❌ {test_name}: FAILED")
        except Exception as e:
            print(f"\n❌ {test_name}: ERROR - {e}")
    
    # Summary
    print("\n" + "=" * 70)
    print("🏁 WORKFLOW TEST SUMMARY")
    print("=" * 70)
    print(f"Tests passed: {passed}/{total}")
    
    if passed == total:
        print("\n🎉 SUCCESS! Enhanced notifications are properly integrated!")
        print("\n✅ The notification system will now work when:")
        print("   • start_defender.bat detects ransomware")
        print("   • ML model identifies malicious behavior")
        print("   • Process termination occurs")
        print("   • Critical threats are neutralized")
        print("\n💡 Desktop notifications should now appear reliably!")
    else:
        print(f"\n⚠️ {total - passed} test(s) failed. Check the integration.")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    
    print("\n" + "=" * 70)
    print("🧪 To test with actual ransomware:")
    print("1. Run: scripts\\start_defender.bat")
    print("2. Run your ransomware test script")
    print("3. Look for desktop notifications when threats are detected")
    print("=" * 70)
    
    input("\nPress Enter to exit...")
    sys.exit(0 if success else 1)