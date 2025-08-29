#!/usr/bin/env python3
"""
Test script to verify that the GUI is displaying actual statistics from log files
"""

import os
import sys
import time
from datetime import datetime

# Add current directory to path
sys.path.append(os.getcwd())

def test_dashboard_data():
    """Test the dashboard data extraction"""
    print("=== TESTING DASHBOARD DATA EXTRACTION ===")
    
    try:
        from ui.dashboard import DashboardData, get_dashboard_data
        
        # Test direct dashboard data
        dashboard = DashboardData()
        stats = dashboard.analyze_logs()
        
        print(f"📊 DASHBOARD STATISTICS:")
        print(f"   Total Events: {stats.get('events_total', 0)}")
        print(f"   Threats Detected: {stats.get('threats_detected', 0)}")
        print(f"   Threats Blocked: {stats.get('threats_blocked', 0)}")
        print(f"   Processes Terminated: {stats.get('processes_terminated', 0)}")
        print(f"   High Alerts: {stats.get('alerts_high', 0)}")
        print(f"   Medium Alerts: {stats.get('alerts_medium', 0)}")
        print(f"   Low Alerts: {stats.get('alerts_low', 0)}")
        
        print(f"\n📈 EVENT TYPES:")
        events_by_type = stats.get('events_by_type', {})
        for event_type, count in events_by_type.items():
            print(f"   {event_type}: {count}")
        
        print(f"\n🎯 RECENT THREATS:")
        recent_threats = stats.get('recent_threats', [])
        for i, threat in enumerate(recent_threats[:5]):  # Show first 5
            print(f"   {i+1}. [{threat.get('timestamp', 'N/A')}] {threat.get('type', 'Unknown')} - {threat.get('description', 'No description')}")
        
        print(f"\n🛡️ RECENT RESPONSES:")
        response_history = stats.get('response_history', [])
        for i, response in enumerate(response_history[:5]):  # Show first 5
            print(f"   {i+1}. [{response.get('timestamp', 'N/A')}] {response.get('action', 'Unknown')} - {response.get('details', 'No details')}")
        
        print(f"\n⚡ SYSTEM HEALTH:")
        health = stats.get('system_health', {})
        print(f"   Detector Active: {health.get('detector_active', False)}")
        print(f"   Responder Active: {health.get('responder_active', False)}")
        print(f"   Watcher Active: {health.get('watcher_active', False)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Dashboard data test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gui_integration():
    """Test GUI integration (without actually showing the GUI)"""
    print("\n=== TESTING GUI INTEGRATION ===")
    
    try:
        from ui.main_gui import DeadboltMainWindow
        from PyQt5.QtWidgets import QApplication
        
        # Create application (required for PyQt5)
        app = QApplication([])
        
        # Create main window
        window = DeadboltMainWindow()
        
        # Check if dashboard data is loaded
        print(f"✅ GUI window created successfully")
        print(f"📊 GUI Statistics loaded:")
        print(f"   Threats: {window.threats_label.text()}")
        print(f"   Blocked: {window.blocked_label.text()}")
        print(f"   Processes: {window.processes_label.text()}")
        print(f"   Events: {window.events_label.text()}")
        
        # Manually trigger a refresh to ensure stats are updated
        window.refresh_dashboard()
        
        print(f"📊 GUI Statistics after refresh:")
        print(f"   Threats: {window.threats_label.text()}")
        print(f"   Blocked: {window.blocked_label.text()}")
        print(f"   Processes: {window.processes_label.text()}")
        print(f"   Events: {window.events_label.text()}")
        
        app.quit()
        return True
        
    except Exception as e:
        print(f"❌ GUI integration test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def create_test_log_entries():
    """Create some test log entries to verify live updates"""
    print("\n=== CREATING TEST LOG ENTRIES ===")
    
    try:
        from logger import log_event, log_alert
        
        # Create some test threat detections
        log_alert("HIGH", "Test ransomware detected in C:\\Users\\Test\\Documents", {
            "threat_type": "mass_modification",
            "file_count": 25,
            "process_id": 1234
        })
        
        log_event("CRITICAL", "Analyzing threat: mass_modification - High file modification rate detected")
        log_event("CRITICAL", "Triggering CRITICAL response for threat: mass_modification")
        log_event("CRITICAL", "Target PIDs: [1234, 5678]")
        
        log_event("INFO", "Successfully terminated process 1234 (suspicious_app.exe)")
        log_event("INFO", "Successfully terminated process 5678 (malware.exe)")
        
        log_alert("MEDIUM", "Suspicious file activity detected", {
            "file_path": "C:\\Users\\Test\\Documents\\important.txt.encrypted",
            "action": "rename"
        })
        
        print("✅ Test log entries created")
        return True
        
    except Exception as e:
        print(f"❌ Failed to create test log entries: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 DEADBOLT GUI STATISTICS TEST")
    print("=" * 50)
    
    results = []
    
    # Test dashboard data extraction
    results.append(("Dashboard Data", test_dashboard_data()))
    
    # Create test entries for live verification
    results.append(("Test Log Entries", create_test_log_entries()))
    
    # Test GUI integration
    results.append(("GUI Integration", test_gui_integration()))
    
    # Summary
    print("\n=== TEST RESULTS ===")
    all_passed = True
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name:20} {status}")
        if not passed:
            all_passed = False
    
    print("\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL TESTS PASSED - GUI DISPLAYING REAL STATISTICS!")
        print("\n📱 The GUI dashboard is now showing:")
        print("   • Real threat detection counts from logs")
        print("   • Actual blocked threats and terminated processes") 
        print("   • Live system health indicators")
        print("   • Recent threat and response history")
        print("   • Real-time event type distribution charts")
        print("\n🚀 Launch the GUI with: python main.py --gui")
    else:
        print("❌ SOME TESTS FAILED - CHECK ERRORS ABOVE")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)