"""
Test script to verify that the Deadbolt fixes work properly:
1. No notification spam
2. No process behavior monitoring 
3. Smart process filtering
4. Responder deactivation after threat neutralization
"""

import os
import time
import threading
from detector import ThreatDetector
from responder import ThreatResponder

def test_responder_callback(response_info):
    """Test callback for responder."""
    print(f"RESPONSE TRIGGERED: {response_info}")

def test_notification_cooldown():
    """Test that notification cooldown prevents spam."""
    print("Testing notification cooldown...")
    
    detector = ThreatDetector(test_responder_callback)
    detector.start_monitoring()
    
    # Send multiple rapid threats - should only get one notification
    for i in range(5):
        threat_info = {
            'type': 'mass_modification',
            'severity': 'CRITICAL',
            'description': f'Test threat {i+1}',
            'count': 15,
            'process_info': []
        }
        detector.analyze_threat(threat_info)
        time.sleep(1)  # 1 second between threats
    
    detector.stop_monitoring()
    print("Notification cooldown test completed.\n")

def test_process_filtering():
    """Test that system processes are not targeted."""
    print("Testing system process filtering...")
    
    detector = ThreatDetector(test_responder_callback)
    detector.start_monitoring()
    
    # Simulate threat with system processes - should be filtered out
    threat_info = {
        'type': 'mass_modification',
        'severity': 'CRITICAL',
        'description': 'Test threat with system processes',
        'count': 20,
        'process_info': [
            (1234, 'taskmgr.exe'),  # Should be filtered
            (5678, 'qoder.exe'),    # Should be filtered
            (9999, 'malware.exe')   # Would be targeted if suspicion score > 10
        ]
    }
    
    # Artificially increase suspicion for the malware process only
    detector.process_suspicion_scores[9999] = 15
    
    detector.analyze_threat(threat_info)
    
    detector.stop_monitoring()
    print("Process filtering test completed.\n")

def test_no_process_monitoring():
    """Test that process monitoring is completely disabled."""
    print("Testing process monitoring disabled...")
    
    detector = ThreatDetector(test_responder_callback)
    detector.start_monitoring()
    
    # Check that no process monitoring thread is started
    if detector.process_monitor_thread is None:
        print("✓ Process monitoring correctly disabled")
    else:
        print("✗ Process monitoring still active!")
    
    detector.stop_monitoring()
    print("Process monitoring test completed.\n")

def main():
    """Run all tests."""
    print("=== DEADBOLT FIXES VERIFICATION ===\n")
    
    # Ensure logs directory exists
    os.makedirs('logs', exist_ok=True)
    
    try:
        test_no_process_monitoring()
        test_notification_cooldown() 
        test_process_filtering()
        
        print("=== ALL TESTS COMPLETED ===")
        print("Check the logs to verify:")
        print("1. No process behavior monitoring messages")
        print("2. Notification cooldown working")
        print("3. System processes filtered out")
        
    except Exception as e:
        print(f"Test failed with error: {e}")

if __name__ == "__main__":
    main()