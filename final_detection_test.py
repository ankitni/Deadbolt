#!/usr/bin/env python3
"""
FINAL DEADBOLT TEST - Organized System vs Ransomware Simulation
Tests the organized Deadbolt system against the good.py ransomware simulator
"""

import os
import sys
import time
import subprocess
import threading
from datetime import datetime

def print_banner():
    """Print test banner"""
    print("=" * 70)
    print("🛡️  DEADBOLT 5 - FINAL DETECTION TEST")
    print("=" * 70)
    print(f"⏰ Test Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("📁 Organized Project Structure")
    print("🎯 Target: good.py ransomware simulator")
    print("📊 Real-time log monitoring and statistics")
    print("=" * 70)
    print()

def cleanup_test_environment():
    """Clean up previous test artifacts"""
    print("🧹 Cleaning up test environment...")
    
    # Clean up previous test files
    test_dir = r"C:\Users\MADHURIMA\Documents\testtxt"
    if os.path.exists(test_dir):
        try:
            import shutil
            shutil.rmtree(test_dir)
            print(f"   ✅ Removed old test directory: {test_dir}")
        except Exception as e:
            print(f"   ⚠️ Could not remove {test_dir}: {e}")
    
    # Clear relevant log files for fresh test
    log_files = ['logs/main.log', 'logs/detector.log', 'logs/responder.log', 'logs/watcher.log']
    for log_file in log_files:
        if os.path.exists(log_file):
            try:
                # Keep existing logs but add a test marker
                with open(log_file, 'a') as f:
                    f.write(f"\n{'='*50}\n")
                    f.write(f"FINAL TEST STARTED: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"{'='*50}\n")
                print(f"   ✅ Marked test start in: {log_file}")
            except Exception as e:
                print(f"   ⚠️ Could not mark {log_file}: {e}")
    
    print("   ✅ Test environment prepared")

def start_deadbolt_system():
    """Start the organized Deadbolt system"""
    print("🚀 Starting Deadbolt system...")
    
    try:
        # Start Deadbolt in daemon mode using the organized structure
        deadbolt_process = subprocess.Popen([
            sys.executable, "deadbolt.py", "--daemon"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Give system time to initialize
        time.sleep(5)
        
        # Check if process is still running
        if deadbolt_process.poll() is None:
            print("   ✅ Deadbolt system started successfully")
            print(f"   📍 Process ID: {deadbolt_process.pid}")
            return deadbolt_process
        else:
            stdout, stderr = deadbolt_process.communicate()
            print(f"   ❌ Deadbolt failed to start")
            print(f"   📄 stdout: {stdout}")
            print(f"   📄 stderr: {stderr}")
            return None
            
    except Exception as e:
        print(f"   ❌ Error starting Deadbolt: {e}")
        return None

def run_ransomware_simulation():
    """Run the ransomware simulation"""
    print("🦠 Launching ransomware simulation (good.py)...")
    
    try:
        # Start the ransomware simulation
        ransomware_process = subprocess.Popen([
            sys.executable, "good.py"
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        print(f"   📍 Ransomware PID: {ransomware_process.pid}")
        print("   ⚠️ Monitoring for detection and termination...")
        
        # Monitor the process for up to 30 seconds
        start_time = time.time()
        max_wait_time = 30
        
        while time.time() - start_time < max_wait_time:
            # Check if process is still running
            poll_result = ransomware_process.poll()
            if poll_result is not None:
                print(f"   🎯 DETECTION SUCCESS: Ransomware process terminated!")
                print(f"   📊 Exit code: {poll_result}")
                print(f"   ⏱️ Time to detection: {time.time() - start_time:.2f} seconds")
                return True, time.time() - start_time
            
            print(f"   ⏳ Waiting... {int(time.time() - start_time)}s", end='\r')
            time.sleep(1)
        
        # If we get here, the process wasn't terminated
        print(f"\n   ❌ DETECTION FAILED: Ransomware process still running after {max_wait_time}s")
        
        # Try to get output
        try:
            stdout, stderr = ransomware_process.communicate(timeout=5)
            print(f"   📄 Ransomware output: {stdout[:200]}...")
        except:
            pass
        
        # Manually terminate the process
        try:
            ransomware_process.terminate()
            print("   🔪 Manually terminated ransomware process")
        except:
            pass
        
        return False, max_wait_time
        
    except Exception as e:
        print(f"   ❌ Error running ransomware simulation: {e}")
        return False, 0

def analyze_detection_logs():
    """Analyze the detection logs for evidence"""
    print("\n📋 Analyzing detection logs...")
    
    evidence = {
        'threats_detected': 0,
        'responses_triggered': 0,
        'processes_terminated': 0,
        'log_entries': []
    }
    
    # Check detector.log
    detector_log = 'logs/detector.log'
    if os.path.exists(detector_log):
        try:
            with open(detector_log, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-50:]  # Last 50 lines
                
            for line in recent_lines:
                if 'FINAL TEST STARTED' in line:
                    evidence['log_entries'].append(f"🏁 Test marker found in detector.log")
                elif 'Analyzing threat:' in line:
                    evidence['threats_detected'] += 1
                    evidence['log_entries'].append(f"🎯 Threat detected: {line.strip()}")
                elif 'CRITICAL response' in line or 'Triggering CRITICAL' in line:
                    evidence['responses_triggered'] += 1
                    evidence['log_entries'].append(f"🚨 Critical response: {line.strip()}")
                elif 'mass_modification' in line or 'suspicious_filename' in line:
                    evidence['log_entries'].append(f"🔍 Suspicious activity: {line.strip()}")
                    
        except Exception as e:
            print(f"   ⚠️ Error reading detector.log: {e}")
    
    # Check responder.log
    responder_log = 'logs/responder.log'
    if os.path.exists(responder_log):
        try:
            with open(responder_log, 'r') as f:
                lines = f.readlines()
                recent_lines = lines[-30:]  # Last 30 lines
                
            for line in recent_lines:
                if 'Successfully terminated' in line:
                    evidence['processes_terminated'] += 1
                    evidence['log_entries'].append(f"⚡ Process terminated: {line.strip()}")
                elif 'THREAT RESPONSE INITIATED' in line:
                    evidence['log_entries'].append(f"🛡️ Response initiated: {line.strip()}")
                elif 'C++ killer' in line:
                    evidence['log_entries'].append(f"🔪 C++ killer activated: {line.strip()}")
                    
        except Exception as e:
            print(f"   ⚠️ Error reading responder.log: {e}")
    
    # Print analysis results
    print(f"   📊 Threats Detected: {evidence['threats_detected']}")
    print(f"   🚨 Responses Triggered: {evidence['responses_triggered']}")
    print(f"   ⚡ Processes Terminated: {evidence['processes_terminated']}")
    
    if evidence['log_entries']:
        print(f"\n   📝 Recent Detection Evidence:")
        for entry in evidence['log_entries'][-10:]:  # Show last 10 entries
            print(f"      {entry}")
    
    return evidence

def check_file_protection():
    """Check if files were protected from the ransomware"""
    print("\n🛡️ Checking file protection...")
    
    test_dir = r"C:\Users\MADHURIMA\Documents\testtxt"
    if not os.path.exists(test_dir):
        print("   ✅ No test directory created - attack prevented!")
        return True
    
    try:
        files = os.listdir(test_dir)
        encrypted_files = [f for f in files if f.endswith(('.gujd', '.sdif'))]
        ransom_notes = [f for f in files if 'DECRYPT' in f.upper() or 'RANSOM' in f.upper() or 'READ_ME' in f.upper()]
        
        print(f"   📁 Files in test directory: {len(files)}")
        print(f"   🔒 Encrypted files found: {len(encrypted_files)}")
        print(f"   📜 Ransom notes found: {len(ransom_notes)}")
        
        if encrypted_files:
            print(f"   ⚠️ Some files were encrypted: {encrypted_files[:3]}...")
            return False
        else:
            print("   ✅ No encrypted files found - protection successful!")
            return True
            
    except Exception as e:
        print(f"   ⚠️ Error checking files: {e}")
        return False

def generate_test_report(detection_success, detection_time, log_evidence, protection_success):
    """Generate final test report"""
    print("\n" + "=" * 70)
    print("📊 FINAL TEST REPORT")
    print("=" * 70)
    
    # Overall result
    if detection_success and protection_success:
        result = "🎉 SUCCESS"
        color = "✅"
    elif detection_success:
        result = "🟡 PARTIAL SUCCESS"
        color = "⚠️"
    else:
        result = "❌ FAILURE"
        color = "❌"
    
    print(f"{color} Overall Result: {result}")
    print()
    
    # Detection analysis
    print("🎯 DETECTION ANALYSIS:")
    print(f"   • Process termination: {'✅ YES' if detection_success else '❌ NO'}")
    print(f"   • Detection time: {detection_time:.2f} seconds")
    print(f"   • Threats detected in logs: {log_evidence['threats_detected']}")
    print(f"   • Responses triggered: {log_evidence['responses_triggered']}")
    print(f"   • Processes terminated: {log_evidence['processes_terminated']}")
    
    # Protection analysis
    print(f"\n🛡️ PROTECTION ANALYSIS:")
    print(f"   • File protection: {'✅ SUCCESS' if protection_success else '❌ FAILED'}")
    
    # System performance
    print(f"\n⚡ SYSTEM PERFORMANCE:")
    if detection_time < 10:
        print("   • Response speed: ✅ EXCELLENT (< 10s)")
    elif detection_time < 20:
        print("   • Response speed: 🟡 GOOD (< 20s)")
    else:
        print("   • Response speed: ❌ SLOW (> 20s)")
    
    # Recommendations
    print(f"\n💡 RECOMMENDATIONS:")
    if not detection_success:
        print("   • Check system configuration")
        print("   • Verify process monitoring is active")
        print("   • Review detection thresholds")
    elif not protection_success:
        print("   • Detection worked but files were partially encrypted")
        print("   • Consider faster response mechanisms")
    else:
        print("   • System is performing optimally")
        print("   • Continue monitoring for false positives")
    
    print("\n" + "=" * 70)

def main():
    """Main test execution"""
    print_banner()
    
    try:
        # Step 1: Cleanup
        cleanup_test_environment()
        time.sleep(2)
        
        # Step 2: Start Deadbolt
        deadbolt_process = start_deadbolt_system()
        if not deadbolt_process:
            print("❌ Cannot continue test - Deadbolt failed to start")
            return
        
        time.sleep(3)
        
        # Step 3: Run ransomware simulation
        detection_success, detection_time = run_ransomware_simulation()
        
        # Step 4: Give time for logs to be written
        time.sleep(5)
        
        # Step 5: Analyze logs
        log_evidence = analyze_detection_logs()
        
        # Step 6: Check file protection
        protection_success = check_file_protection()
        
        # Step 7: Generate report
        generate_test_report(detection_success, detection_time, log_evidence, protection_success)
        
        # Step 8: Cleanup
        print("\n🧹 Cleaning up...")
        try:
            deadbolt_process.terminate()
            deadbolt_process.wait(timeout=10)
            print("   ✅ Deadbolt system stopped")
        except:
            try:
                deadbolt_process.kill()
                print("   ⚡ Deadbolt system forcefully stopped")
            except:
                print("   ⚠️ Could not stop Deadbolt process")
    
    except KeyboardInterrupt:
        print("\n\n🛑 Test interrupted by user")
    except Exception as e:
        print(f"\n❌ Test error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    main()