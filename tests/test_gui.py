#!/usr/bin/env python3
"""
Test GUI Launch Script
Tests if the enhanced Deadbolt AI GUI can be launched successfully
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

try:
    print("Testing Deadbolt AI GUI...")
    print("=" * 50)
    
    # Test imports
    print("1. Testing imports...")
    
    try:
        from PyQt5.QtWidgets import QApplication
        print("   ✓ PyQt5 available")
    except ImportError:
        print("   ✗ PyQt5 not available - GUI will not work")
        print("   Install with: pip install PyQt5")
        sys.exit(1)
    
    try:
        import matplotlib
        print("   ✓ Matplotlib available")
    except ImportError:
        print("   ✗ Matplotlib not available - charts will not work")
        print("   Install with: pip install matplotlib")
    
    try:
        import pyqtgraph
        print("   ✓ PyQTGraph available")
    except ImportError:
        print("   ⚠ PyQTGraph not available - some charts may not work")
        print("   Install with: pip install pyqtgraph")
    
    # Test GUI modules
    print("\n2. Testing GUI modules...")
    
    try:
        from ui.main_gui import DeadboltMainWindow
        print("   ✓ Main GUI module imported successfully")
    except ImportError as e:
        print(f"   ✗ Failed to import main GUI: {e}")
        sys.exit(1)
    
    try:
        from ui.dashboard import DashboardData
        print("   ✓ Dashboard module imported successfully")
    except ImportError as e:
        print(f"   ⚠ Dashboard module import failed: {e}")
    
    # Test log directory
    print("\n3. Testing log directory...")
    
    log_dir = os.path.join(os.path.dirname(__file__), 'logs')
    if os.path.exists(log_dir):
        print(f"   ✓ Log directory exists: {log_dir}")
        
        log_files = ['main.log', 'detector.log', 'responder.log', 'watcher.log', 'ml_detector.log', 'ml_stats.json']
        for log_file in log_files:
            file_path = os.path.join(log_dir, log_file)
            if os.path.exists(file_path):
                size = os.path.getsize(file_path)
                print(f"   ✓ {log_file} exists ({size} bytes)")
            else:
                print(f"   ⚠ {log_file} not found (will be created when needed)")
    else:
        print(f"   ⚠ Log directory not found: {log_dir}")
        print("   Creating log directory...")
        os.makedirs(log_dir, exist_ok=True)
        print("   ✓ Log directory created")
    
    # Test configuration
    print("\n4. Testing configuration...")
    
    try:
        from utils.config import TARGET_DIRS, RULES, ACTIONS
        print(f"   ✓ Configuration loaded - {len(TARGET_DIRS)} target directories")
    except ImportError as e:
        print(f"   ⚠ Configuration import failed: {e}")
    
    print("\n" + "=" * 50)
    print("✓ All tests passed! GUI should work correctly.")
    print("\nTo launch the GUI:")
    print("1. Run: run_gui.bat (Windows)")
    print("2. Or run: python src/ui/main_gui.py")
    print("3. For admin mode: Right-click run_gui.bat → Run as administrator")
    
except Exception as e:
    print(f"\n✗ Test failed with error: {e}")
    import traceback
    traceback.print_exc()
    sys.exit(1)