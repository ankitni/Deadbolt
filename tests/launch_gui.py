#!/usr/bin/env python3
"""
Robust GUI launcher for Deadbolt that handles import issues
"""

import sys
import os
import warnings

# Suppress the pkg_resources deprecation warning
warnings.filterwarnings("ignore", category=DeprecationWarning, module="pkg_resources")

def setup_python_path():
    """Set up Python path for proper imports"""
    # Get the project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(project_root, 'src')
    core_path = os.path.join(src_path, 'core')
    ui_path = os.path.join(src_path, 'ui')
    utils_path = os.path.join(src_path, 'utils')
    
    # Add all necessary paths
    for path in [project_root, src_path, core_path, ui_path, utils_path]:
        if path not in sys.path:
            sys.path.insert(0, path)
    
    return project_root

def check_gui_dependencies():
    """Check if all GUI dependencies are available"""
    missing_deps = []
    
    try:
        import PyQt5
    except ImportError:
        missing_deps.append('PyQt5')
    
    try:
        import pyqtgraph
    except ImportError:
        missing_deps.append('pyqtgraph')
    
    try:
        import matplotlib
    except ImportError:
        missing_deps.append('matplotlib')
    
    return missing_deps

def main():
    """Launch Deadbolt with GUI"""
    print("🛡️ Deadbolt GUI Launcher")
    print("=" * 30)
    
    # Set up Python path
    project_root = setup_python_path()
    print(f"📂 Project root: {project_root}")
    
    # Check dependencies
    missing_deps = check_gui_dependencies()
    if missing_deps:
        print(f"❌ Missing dependencies: {', '.join(missing_deps)}")
        print("📦 Please install them with:")
        print(f"   pip install {' '.join(missing_deps)}")
        return 1
    
    print("✅ All GUI dependencies found")
    
    try:
        # Import PyQt5 first
        from PyQt5.QtWidgets import QApplication
        print("✅ PyQt5 imported successfully")
        
        # Import main module
        from main import main as deadbolt_main
        print("✅ Deadbolt main module imported")
        
        # Set GUI mode arguments
        original_argv = sys.argv.copy()
        sys.argv = ['deadbolt.py', '--gui']
        
        print("🚀 Starting Deadbolt GUI...")
        print("" * 30)
        
        # Start Deadbolt
        result = deadbolt_main()
        
        # Restore original argv
        sys.argv = original_argv
        
        return result
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        print("💡 This could be due to:")
        print("   1. Missing dependencies")
        print("   2. Incorrect Python path setup")
        print("   3. Module structure issues")
        return 1
    except Exception as e:
        print(f"❌ Error starting Deadbolt GUI: {e}")
        import traceback
        print("📋 Full traceback:")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⏹️ GUI startup cancelled by user")
        sys.exit(1)