#!/usr/bin/env python3
"""
Test script to verify the GUI dashboard fix for threat by hour display
"""

import os
import sys

# Add current directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

def test_gui_dashboard():
    """Test the GUI dashboard with our fix"""
    print("=== TESTING GUI DASHBOARD ===")
    
    try:
        # Import the dashboard module
        from src.ui.dashboard import DashboardData
        
        # Create dashboard data instance
        dashboard = DashboardData()
        
        # Analyze logs
        stats = dashboard.analyze_logs()
        
        print("Dashboard statistics:")
        print(f"  Threats detected: {stats.get('threats_detected', 0)}")
        print(f"  High alerts: {stats.get('alerts_high', 0)}")
        print(f"  Medium alerts: {stats.get('alerts_medium', 0)}")
        print(f"  Low alerts: {stats.get('alerts_low', 0)}")
        
        # Check alerts by time
        alerts_by_time = stats.get('alerts_by_time', [0] * 24)
        print(f"  Alerts by hour: {alerts_by_time}")
        
        # Check if we have any data in the hourly distribution
        non_zero_hours = sum(1 for count in alerts_by_time if count > 0)
        print(f"  Non-zero hours: {non_zero_hours}")
        
        if non_zero_hours > 0:
            print("✅ SUCCESS: Threat by hour data is now available!")
            print("The GUI dashboard should now display the threat activity by hour chart.")
            return True
        else:
            print("⚠️  WARNING: No hourly threat data found")
            return False
            
    except Exception as e:
        print(f"❌ Error testing GUI dashboard: {e}")
        import traceback
        traceback.print_exc()
        return False

def show_sample_data():
    """Show sample of what the threat by hour chart will display"""
    print("\n=== SAMPLE THREAT BY HOUR DATA ===")
    
    try:
        from src.ui.dashboard import DashboardData
        
        # Get dashboard data
        dashboard = DashboardData()
        stats = dashboard.analyze_logs()
        
        alerts_by_time = stats.get('alerts_by_time', [0] * 24)
        
        print("Hourly threat distribution:")
        for hour in range(24):
            if alerts_by_time[hour] > 0:
                print(f"  {hour:02d}:00 - {hour:02d}:59 | {'█' * min(alerts_by_time[hour], 50)} ({alerts_by_time[hour]})")
        
        # Find peak hour
        if any(alerts_by_time):
            peak_hour = alerts_by_time.index(max(alerts_by_time))
            print(f"\nPeak threat activity: {peak_hour:02d}:00 - {peak_hour:02d}:59 ({max(alerts_by_time)} threats)")
        
    except Exception as e:
        print(f"Error showing sample data: {e}")

if __name__ == "__main__":
    print("Testing GUI dashboard fix for threat by hour display...\n")
    
    success = test_gui_dashboard()
    show_sample_data()
    
    print(f"\n{'='*60}")
    if success:
        print("🎉 GUI DASHBOARD FIX VERIFICATION COMPLETE!")
        print("The 'Threats by Hour' dashboard should now display data.")
    else:
        print("❌ GUI DASHBOARD FIX VERIFICATION FAILED!")
        print("The 'Threats by Hour' dashboard may still be empty.")
    print("="*60)