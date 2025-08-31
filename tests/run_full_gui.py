#!/usr/bin/env python3
"""
Direct launcher for the full Deadbolt GUI
This script directly imports and runs the complete PyQt5 GUI from main_gui.py
"""

import sys
import os
import warnings

# Suppress warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)

def setup_paths():
    """Set up Python paths for proper imports"""
    project_root = os.path.dirname(os.path.abspath(__file__))
    src_path = os.path.join(project_root, 'src')
    utils_path = os.path.join(src_path, 'utils')
    core_path = os.path.join(src_path, 'core')
    ui_path = os.path.join(src_path, 'ui')
    
    # Add to Python path in the correct order
    paths_to_add = [project_root, src_path, utils_path, core_path, ui_path]
    for path in paths_to_add:
        if path not in sys.path:
            sys.path.insert(0, path)
    
    return project_root

def check_dependencies():
    """Check if all required dependencies are available"""
    missing_deps = []
    
    try:
        import PyQt5
        print("✅ PyQt5 found")
    except ImportError:
        missing_deps.append('PyQt5')
    
    try:
        import pyqtgraph
        print("✅ pyqtgraph found")
    except ImportError:
        missing_deps.append('pyqtgraph')
    
    try:
        import matplotlib
        print("✅ matplotlib found")
    except ImportError:
        missing_deps.append('matplotlib')
    
    return missing_deps

def ensure_directories():
    """Ensure required directories exist"""
    project_root = os.path.dirname(os.path.abspath(__file__))
    logs_dir = os.path.join(project_root, 'logs')
    
    # Create logs directory if it doesn't exist
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir, exist_ok=True)
        print(f"📁 Created logs directory: {logs_dir}")
    
    # Create a basic log file if it doesn't exist
    log_file = os.path.join(logs_dir, 'deadbolt.log')
    if not os.path.exists(log_file):
        with open(log_file, 'w') as f:
            f.write(f"[{os.path.basename(__file__)}] INFO: Log file created\n")
        print(f"📜 Created log file: {log_file}")

def main():
    """Launch the full Deadbolt GUI"""
    print("🛡️  Deadbolt 5 - Full GUI Launcher")
    print("=" * 40)
    
    # Set up paths
    project_root = setup_paths()
    print(f"📂 Project root: {project_root}")
    
    # Ensure required directories exist
    ensure_directories()
    
    # Check dependencies
    print("🔍 Checking dependencies...")
    missing_deps = check_dependencies()
    
    if missing_deps:
        print(f"❌ Missing dependencies: {', '.join(missing_deps)}")
        print("📦 Please install them with:")
        print(f"   pip install {' '.join(missing_deps)}")
        return 1
    
    print("✅ All dependencies found")
    print()
    
    try:
        # Import the full GUI with multiple approaches
        print("🚀 Starting full Deadbolt GUI...")
        
        # Method 1: Direct import from ui.main_gui
        try:
            from ui.main_gui import run_gui
            print("🖥️  Launching GUI application...")
            return run_gui()
        except ImportError as e1:
            print(f"Method 1 failed: {e1}")
            
            # Method 2: Import from src.ui.main_gui
            try:
                from src.ui.main_gui import run_gui
                print("🖥️  Launching GUI application (method 2)...")
                return run_gui()
            except ImportError as e2:
                print(f"Method 2 failed: {e2}")
                
                # Method 3: Manual import with explicit path
                try:
                    import importlib.util
                    gui_path = os.path.join(project_root, 'src', 'ui', 'main_gui.py')
                    spec = importlib.util.spec_from_file_location("main_gui", gui_path)
                    main_gui = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(main_gui)
                    print("🖥️  Launching GUI application (method 3)...")
                    return main_gui.run_gui()
                except Exception as e3:
                    print(f"Method 3 failed: {e3}")
                    raise ImportError(f"All import methods failed: {e1}, {e2}, {e3}")
    
    except Exception as e:
        print(f"❌ Error starting GUI: {e}")
        import traceback
        print("📋 Full traceback:")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n⏹️  GUI startup cancelled by user")
        sys.exit(1)