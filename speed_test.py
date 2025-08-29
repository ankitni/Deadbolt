#!/usr/bin/env python3
"""
Ultra-Fast Deadbolt Test - Verify speed improvements
Tests the new aggressive detection and termination settings
"""

import os
import sys
import time
import subprocess
import threading
from datetime import datetime

def run_deadbolt():
    """Start Deadbolt in the background"""
    print("🛡️ Starting Deadbolt with AGGRESSIVE settings...")
    try:
        deadbolt_process = subprocess.Popen(
            [sys.executable, "deadbolt.py", "--daemon"],
            cwd=os.path.dirname(__file__),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )
        time.sleep(3)  # Give Deadbolt time to start
        print(f"   ✅ Deadbolt started (PID: {deadbolt_process.pid})")
        return deadbolt_process
    except Exception as e:
        print(f"   ❌ Failed to start Deadbolt: {e}")
        return None

def run_ransomware_test():
    """Run good.py and measure how fast it gets killed"""
    print("🦠 Running ransomware simulation...")
    start_time = time.time()
    
    try:
        ransomware_process = subprocess.Popen(
            [sys.executable, "good.py"],
            cwd=os.path.dirname(__file__),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        print(f"   📍 Ransomware simulation started (PID: {ransomware_process.pid})")
        
        # Monitor for 20 seconds max
        for i in range(200):  # Check every 0.1 seconds
            if ransomware_process.poll() is not None:
                # Process terminated
                kill_time = time.time() - start_time
                print(f"   🔪 Ransomware KILLED in {kill_time:.2f} seconds!")
                
                if kill_time < 5:
                    print("   ✅ EXCELLENT: Killed in under 5 seconds")
                elif kill_time < 10:
                    print("   ⚠️  GOOD: Killed in under 10 seconds")
                else:
                    print("   ❌ SLOW: Took more than 10 seconds")
                
                return kill_time
            
            time.sleep(0.1)
        
        # If we get here, process wasn't killed in 20 seconds
        print("   ❌ FAILED: Ransomware NOT killed within 20 seconds")
        try:
            ransomware_process.terminate()
            ransomware_process.wait(timeout=5)
        except:
            pass
        return None
        
    except Exception as e:
        print(f"   ❌ Error running ransomware test: {e}")
        return None

def main():
    """Main test function"""
    print("🚀 DEADBOLT SPEED TEST - Aggressive Settings")
    print("=" * 50)
    print("Testing new settings:")
    print("  ⚡ 4 file modifications = CRITICAL (was 8)")
    print("  ⚡ 2 second detection window (was 5)")
    print("  ⚡ Instant force-kill (no graceful termination)")
    print("  ⚡ 3 second notification cooldown (was 10)")
    print()
    
    # Ensure test directory exists
    test_dir = r"C:\Users\MADHURIMA\Documents\testtxt"
    if os.path.exists(test_dir):
        import shutil
        shutil.rmtree(test_dir)
        print(f"🧹 Cleaned test directory: {test_dir}")
    
    # Start Deadbolt
    deadbolt_proc = run_deadbolt()
    if not deadbolt_proc:
        return
    
    try:
        # Run the speed test
        kill_time = run_ransomware_test()
        
        if kill_time:
            print(f"\n🎯 RESULT: Ransomware killed in {kill_time:.2f} seconds")
            print(f"📊 Performance: {'EXCELLENT' if kill_time < 5 else 'GOOD' if kill_time < 10 else 'NEEDS IMPROVEMENT'}")
        else:
            print("\n💥 CRITICAL: Deadbolt failed to stop the ransomware!")
            print("   Check admin privileges and logs for details")
        
    finally:
        # Clean up
        print("\n🧹 Cleaning up...")
        try:
            deadbolt_proc.terminate()
            deadbolt_proc.wait(timeout=5)
            print("   ✅ Deadbolt stopped")
        except:
            try:
                deadbolt_proc.kill()
            except:
                pass
    
    print("\n✅ Speed test complete!")
    print("Check the enhanced notifications during the test.")

if __name__ == "__main__":
    main()