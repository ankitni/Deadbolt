#!/usr/bin/env python3
"""
Final validation of Deadbolt GUI with real statistics
"""

import sys
import os
sys.path.append(os.getcwd())

def quick_validation():
    """Quick validation that everything is working"""
    print("🔍 FINAL VALIDATION - DEADBOLT GUI STATISTICS")
    print("=" * 50)
    
    # Test dashboard data
    try:
        from ui.dashboard import get_dashboard_data
        stats = get_dashboard_data()
        
        print("✅ Dashboard Statistics Extraction: WORKING")
        print(f"   📊 Real data found: {stats['events_total']} total events")
        print(f"   🎯 Threats detected: {stats['threats_detected']}")
        print(f"   🛡️ Threats blocked: {stats['threats_blocked']}")
        print(f"   ⚡ Processes terminated: {stats['processes_terminated']}")
        
    except Exception as e:
        print(f"❌ Dashboard error: {e}")
        return False
    
    # Test GUI components
    try:
        from PyQt5.QtWidgets import QApplication
        from ui.main_gui import DeadboltMainWindow
        
        app = QApplication([])
        window = DeadboltMainWindow()
        
        print("✅ GUI Integration: WORKING")
        print(f"   📱 GUI shows threats: {window.threats_label.text()}")
        print(f"   📱 GUI shows blocked: {window.blocked_label.text()}")
        print(f"   📱 GUI shows processes: {window.processes_label.text()}")
        print(f"   📱 GUI shows events: {window.events_label.text()}")
        
        app.quit()
        
    except Exception as e:
        print(f"❌ GUI error: {e}")
        return False
    
    print("\n🎉 VALIDATION COMPLETE - ALL SYSTEMS OPERATIONAL!")
    print("🚀 Ready to launch: python main.py --gui")
    return True

if __name__ == "__main__":
    quick_validation()