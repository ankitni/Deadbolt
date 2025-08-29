#!/usr/bin/env python3
"""
Simple test script to verify notification display functionality
"""

import sys
import time

def test_win10toast():
    """Test the win10toast library directly."""
    try:
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
        
        print("Testing win10toast notification...")
        toaster.show_toast(
            title="🧪 Test Notification",
            msg="This is a test notification to verify Windows toast functionality works properly.",
            duration=5,
            threaded=False  # Wait for completion
        )
        print("✅ Win10toast notification sent successfully!")
        return True
    except Exception as e:
        print(f"❌ Win10toast failed: {e}")
        return False

def test_plyer():
    """Test alternative notification using plyer library."""
    try:
        from plyer import notification
        print("Testing plyer notification...")
        notification.notify(
            title="🧪 Test Notification (Plyer)",
            message="This is a test notification using the plyer library as an alternative.",
            timeout=5
        )
        print("✅ Plyer notification sent successfully!")
        return True
    except Exception as e:
        print(f"❌ Plyer failed: {e}")
        return False

def test_windows_api():
    """Test Windows API notification directly."""
    try:
        import ctypes
        print("Testing Windows API notification...")
        
        # Use Windows MessageBox as fallback
        ctypes.windll.user32.MessageBoxW(
            0, 
            "This is a test notification using Windows API",
            "🧪 Test Notification (Windows API)", 
            0x40  # MB_ICONINFORMATION
        )
        print("✅ Windows API notification displayed!")
        return True
    except Exception as e:
        print(f"❌ Windows API failed: {e}")
        return False

def main():
    """Test all notification methods."""
    print("=== NOTIFICATION COMPATIBILITY TEST ===\n")
    print(f"Python version: {sys.version}")
    print(f"Platform: Windows 24H2\n")
    
    methods = [
        ("Win10Toast", test_win10toast),
        ("Plyer", test_plyer),
        ("Windows API", test_windows_api)
    ]
    
    working_methods = []
    
    for name, test_func in methods:
        print(f"--- Testing {name} ---")
        try:
            if test_func():
                working_methods.append(name)
            time.sleep(2)  # Pause between tests
        except KeyboardInterrupt:
            print("Test cancelled by user")
            break
        print()
    
    print("=== RESULTS ===")
    if working_methods:
        print(f"✅ Working notification methods: {', '.join(working_methods)}")
    else:
        print("❌ No notification methods working!")
    
    return len(working_methods) > 0

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)