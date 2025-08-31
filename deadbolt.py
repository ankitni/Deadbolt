#!/usr/bin/env python3
"""
Deadbolt Ransomware Protection System - Main Entry Point
Organized project structure with proper imports
"""

import sys
import os

# Add src directory to Python path for imports
src_path = os.path.join(os.path.dirname(__file__), 'src')
sys.path.insert(0, src_path)

# Ensure all required paths are available
utils_path = os.path.join(src_path, 'utils')
core_path = os.path.join(src_path, 'core')
sys.path.insert(0, utils_path)
sys.path.insert(0, core_path)

def main():
    """Main entry point for Deadbolt system"""
    try:
        # Import the main function from core module
        from core.main import main as core_main
        return core_main()
    except ImportError as e:
        print(f"Import error: {e}")
        print("Please ensure all dependencies are installed.")
        print("Run: pip install -r requirements.txt")
        return 1
    except Exception as e:
        print(f"Error starting Deadbolt: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())