#!/usr/bin/env python3
"""
Test Deadbolt's behavior-based detection against good.py ransomware
Focus on file behavior patterns, not extensions or filenames
"""

import os
import sys
import time
import subprocess
import threading
from datetime import datetime

def test_deadbolt_detection():
    """Test if Deadbolt can detect and stop the ransomware simulation"""
    print("🛡️ DEADBOLT BEHAVIOR-BASED DETECTION TEST")
    print("=" * 50)
    print(f"⏰ Test Time: {datetime.now().strftime('%H:%M:%S')}")
    print("🎯 Focus: FILE BEHAVIOR PATTERNS ONLY")
    print("   • Mass file modifications (encryption)")
    print("   • Sequential file operations")
    print("   • Process identification and termination")
    print()
    
    # Clean up any previous test
    test_dir = r"C:\Users\MADHURIMA\Documents\testtxt"
    if os.path.exists(test_dir):
        try:
            import shutil
            shutil.rmtree(test_dir)
            print("🧹 Cleaned up previous test directory")
        except:
            pass
    
    # Step 1: Start Deadbolt in daemon mode
    print("🚀 Starting Deadbolt system...")
    try:
        deadbolt_process = subprocess.Popen([
            sys.executable, "deadbolt.py", "--daemon"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Give system time to initialize
        time.sleep(5)
        
        if deadbolt_process.poll() is None:
            print("   ✅ Deadbolt started successfully")
            print(f"   📍 Process ID: {deadbolt_process.pid}")
        else:
            stdout, stderr = deadbolt_process.communicate()
            print(f"   ❌ Deadbolt failed to start")
            print(f"   Error: {stderr}")
            return False
            
    except Exception as e:
        print(f"   ❌ Error starting Deadbolt: {e}")
        return False
    
    # Step 2: Launch ransomware simulation
    print("\n🦠 Launching ransomware simulation...")
    print("   Expected behavior:")
    print("   • Creates 100 files")
    print("   • Modifies files rapidly (encryption)")
    print("   • Should trigger mass_modification detection")
    
    try:
        ransomware_process = subprocess.Popen([
            sys.executable, "good.py"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        print(f"   📍 Ransomware PID: {ransomware_process.pid}")
        print("   🔍 Monitoring for detection and termination...")
        
        # Monitor for up to 30 seconds
        start_time = time.time()
        max_wait_time = 30
        detected = False
        
        while time.time() - start_time < max_wait_time:
            # Check if ransomware process is still running
            poll_result = ransomware_process.poll()
            if poll_result is not None:
                detection_time = time.time() - start_time
                print(f"\n   🎯 SUCCESS: Ransomware process terminated!")
                print(f"   ⏱️ Detection time: {detection_time:.2f} seconds")
                print(f"   📊 Exit code: {poll_result}")
                detected = True
                break
            
            elapsed = int(time.time() - start_time)
            print(f"   ⏳ Monitoring... {elapsed}s", end='\r')
            time.sleep(0.5)
        
        if not detected:
            print(f"\n   ❌ TIMEOUT: Process not terminated after {max_wait_time}s")
            try:
                ransomware_process.terminate()
                print("   🔪 Manually terminated ransomware")
            except:
                pass
        
        # Step 3: Analyze detection logs
        print(f"\n📋 Analyzing detection evidence...")
        evidence = analyze_detection_logs()
        
        # Step 4: Check file protection
        print(f"\n🛡️ Checking file protection...")
        protection_result = check_file_protection()
        
        # Step 5: Generate report
        print(f"\n📊 TEST RESULTS:")
        print(f"   • Process terminated: {'✅ YES' if detected else '❌ NO'}")
        print(f"   • Threats detected: {evidence['threats_detected']}")
        print(f"   • Mass modifications detected: {evidence['mass_modifications']}")
        print(f"   • Responses triggered: {evidence['responses_triggered']}")
        print(f"   • Files protected: {'✅ YES' if protection_result else '❌ NO'}")
        
        return detected
        
    except Exception as e:
        print(f"   ❌ Error running ransomware: {e}")
        return False
    
    finally:
        # Cleanup
        try:
            if deadbolt_process and deadbolt_process.poll() is None:
                deadbolt_process.terminate()
                print("🧹 Deadbolt system stopped")
        except:
            pass

def analyze_detection_logs():
    """Analyze logs for detection evidence"""
    evidence = {
        'threats_detected': 0,
        'mass_modifications': 0,
        'responses_triggered': 0,
        'log_entries': []
    }
    
    # Check detector log
    detector_log = 'logs/detector.log'
    if os.path.exists(detector_log):
        try:
            with open(detector_log, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-20:]  # Last 20 lines
                
            for line in recent_lines:
                if 'mass_modification' in line.lower():
                    evidence['mass_modifications'] += 1
                    evidence['log_entries'].append(f"🎯 {line.strip()}")
                elif 'analyzing threat' in line.lower():
                    evidence['threats_detected'] += 1
                elif 'critical response' in line.lower():
                    evidence['responses_triggered'] += 1
                    
        except Exception as e:
            print(f"   ⚠️ Error reading detector.log: {e}")
    
    # Show evidence
    if evidence['log_entries']:
        print("   📝 Detection evidence:")
        for entry in evidence['log_entries'][-3:]:
            print(f"      {entry}")
    
    return evidence

def check_file_protection():
    """Check if files were protected"""
    test_dir = r"C:\Users\MADHURIMA\Documents\testtxt"
    if not os.path.exists(test_dir):
        print("   ✅ No test directory - attack prevented!")
        return True
    
    try:
        files = os.listdir(test_dir)
        encrypted_files = [f for f in files if f.endswith(('.gujd', '.sdif'))]
        
        print(f"   📁 Files in directory: {len(files)}")
        print(f"   🔒 Encrypted files: {len(encrypted_files)}")
        
        # If very few files were encrypted, protection was successful
        if len(encrypted_files) < 10:
            print("   ✅ Most files protected!")
            return True
        else:
            print("   ⚠️ Some files were encrypted")
            return False
            
    except Exception as e:
        print(f"   ⚠️ Error checking files: {e}")
        return False

def main():
    """Main test function"""
    success = test_deadbolt_detection()
    
    print("\n" + "=" * 50)
    if success:
        print("🎉 DETECTION TEST PASSED!")
        print("   Deadbolt successfully detected and stopped the ransomware")
    else:
        print("❌ DETECTION TEST FAILED!")
        print("   Deadbolt did not detect or stop the ransomware")
        print("\n💡 TROUBLESHOOTING:")
        print("   1. Check if mass_modification threshold is correct")
        print("   2. Verify file monitoring is active")
        print("   3. Check process termination logic")
        print("   4. Review detection logs for errors")

if __name__ == "__main__":
    main()