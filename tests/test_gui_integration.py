#!/usr/bin/env python3
"""
Test script to verify GUI integration and configuration management
"""

import os
import sys
import time
import json

# Add current directory to path
sys.path.append(os.getcwd())

def test_config_manager():
    """Test the configuration manager functionality"""
    print("=== TESTING CONFIGURATION MANAGER ===")
    
    try:
        from config_manager import config_manager
        import config
        
        print("✅ Config manager imported successfully")
        
        # Test current config
        current_config = config_manager.get_current_config()
        print(f"📋 Current config: {json.dumps(current_config, indent=2)}")
        
        # Test updating rules
        print("🔧 Testing rule updates...")
        success = config_manager.update_rules(
            mass_delete_count=15,
            mass_delete_interval=10,
            mass_rename_count=12,
            mass_rename_interval=8
        )
        
        if success:
            print("✅ Rules updated and saved successfully")
        else:
            print("❌ Failed to save rule updates")
        
        # Test updating actions
        print("🔧 Testing action updates...")
        success = config_manager.update_actions(
            log_only=False,
            kill_process=True,
            shutdown=False,
            dry_run=False
        )
        
        if success:
            print("✅ Actions updated and saved successfully")
        else:
            print("❌ Failed to save action updates")
        
        # Test directory updates
        print("🔧 Testing directory updates...")
        test_dirs = [
            r"C:\Users\MADHURIMA\Documents\testtxt",
            r"C:\Users\MADHURIMA\Documents"
        ]
        
        success = config_manager.update_target_dirs(test_dirs)
        
        if success:
            print("✅ Directories updated and saved successfully")
        else:
            print("❌ Failed to save directory updates")
        
        # Verify changes
        updated_config = config_manager.get_current_config()
        print(f"📋 Updated config: {json.dumps(updated_config, indent=2)}")
        
        return True
        
    except Exception as e:
        print(f"❌ Config manager test failed: {e}")
        return False

def test_gui_availability():
    """Test if GUI components are available"""
    print("\\n=== TESTING GUI AVAILABILITY ===")
    
    try:
        from PyQt5.QtWidgets import QApplication
        print("✅ PyQt5 available")
        
        from ui.main_gui import DeadboltMainWindow
        print("✅ GUI main window available")
        
        from ui.dashboard import DashboardData
        print("✅ Dashboard components available")
        
        from ui.alerts import AlertManager
        print("✅ Alert manager available")
        
        return True
        
    except Exception as e:
        print(f"❌ GUI test failed: {e}")
        return False

def test_integration():
    """Test the integration between components"""
    print("\\n=== TESTING INTEGRATION ===")
    
    try:
        # Test logger
        from logger import log_event, log_alert
        log_event("INFO", "Integration test started")
        log_alert("MEDIUM", "Test alert from integration test")
        print("✅ Logger integration working")
        
        # Test config module
        import config
        print(f"✅ Config module loaded - TARGET_DIRS: {len(config.TARGET_DIRS)} directories")
        
        # Test main defender
        from main import DeadboltDefender
        print("✅ Main defender class available")
        
        return True
        
    except Exception as e:
        print(f"❌ Integration test failed: {e}")
        return False

def main():
    """Run all tests"""
    print("🧪 DEADBOLT GUI INTEGRATION TEST")
    print("=" * 50)
    
    results = []
    
    # Test configuration manager
    results.append(("Config Manager", test_config_manager()))
    
    # Test GUI availability
    results.append(("GUI Components", test_gui_availability()))
    
    # Test integration
    results.append(("Component Integration", test_integration()))
    
    # Summary
    print("\\n=== TEST RESULTS ===")
    all_passed = True
    for test_name, passed in results:
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{test_name:20} {status}")
        if not passed:
            all_passed = False
    
    print("\\n" + "=" * 50)
    if all_passed:
        print("🎉 ALL TESTS PASSED - GUI INTEGRATION SUCCESSFUL!")
        print("\\n📱 You can now use:")
        print("   • python main.py          (auto-starts GUI)")
        print("   • python main.py --gui    (explicit GUI mode)")
        print("   • python main.py --daemon (CLI background mode)")
        print("   • start_gui.bat           (Windows shortcut)")
    else:
        print("❌ SOME TESTS FAILED - CHECK ERRORS ABOVE")
    
    return all_passed

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)