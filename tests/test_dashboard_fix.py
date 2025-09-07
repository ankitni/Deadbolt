#!/usr/bin/env python3
"""
Test script to verify the dashboard fix for threat by hour display
"""

import os
import sys

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_dashboard_data():
    """Test the dashboard data extraction with our fix"""
    print("=== TESTING DASHBOARD DATA EXTRACTION ===")
    
    try:
        from src.ui.dashboard import DashboardData
        
        # Test dashboard data extraction
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
        
        print(f"\n📈 ALERTS BY HOUR:")
        alerts_by_time = stats.get('alerts_by_time', [])
        print(f"   Data points: {len(alerts_by_time)}")
        print(f"   Values: {alerts_by_time}")
        
        # Check if we have any non-zero values
        non_zero_count = sum(1 for x in alerts_by_time if x > 0)
        print(f"   Non-zero hours: {non_zero_count}")
        
        if non_zero_count > 0:
            print("✅ SUCCESS: Threat by hour dashboard should now display data!")
        else:
            print("⚠️  WARNING: No threat data found - dashboard may still be empty")
        
        print(f"\n📅 RECENT ALERTS:")
        recent_alerts = stats.get('recent_alerts', [])
        print(f"   Count: {len(recent_alerts)}")
        for i, alert in enumerate(recent_alerts[:5]):  # Show first 5
            print(f"   {i+1}. [{alert.get('timestamp', 'N/A')}] {alert.get('severity', 'N/A')}: {alert.get('message', 'N/A')}")
        
        return non_zero_count > 0
        
    except Exception as e:
        print(f"❌ Error testing dashboard data: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    success = test_dashboard_data()
    print(f"\n{'='*50}")
    if success:
        print("🎉 DASHBOARD FIX VERIFICATION COMPLETE - THREAT BY HOUR SHOULD NOW WORK!")
    else:
        print("❌ DASHBOARD FIX VERIFICATION FAILED - FURTHER INVESTIGATION NEEDED")
    print("="*50)