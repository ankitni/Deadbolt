#!/usr/bin/env python3
"""
Test script to verify that the improved responder can detect and kill ransomware processes.
This creates an actual process that performs file modifications and tests if the system can terminate it.
"""

import os
import sys
import time
import subprocess
import threading
from pathlib import Path

def create_test_ransomware_process():
    """Create a Python script that simulates ransomware behavior."""
    test_script = '''
import os
import time
import sys

# Simulate ransomware behavior
print("FAKE RANSOMWARE: Starting file encryption simulation...")
sys.stdout.flush()

test_dir = r"C:\\Users\\MADHURIMA\\Documents\\test_ransomware_target"
os.makedirs(test_dir, exist_ok=True)

# Create files and modify them rapidly
for i in range(100):
    try:
        # Create file
        file_path = os.path.join(test_dir, f"victim_file_{i}.txt")
        with open(file_path, "w") as f:
            f.write(f"Original content {i}")
        
        # Modify file (simulate encryption)
        with open(file_path, "w") as f:
            f.write(f"ENCRYPTED_CONTENT_{i}_XXXXXXXX")
        
        # Rename to .encrypted
        encrypted_path = file_path + ".encrypted"
        if os.path.exists(file_path):
            os.rename(file_path, encrypted_path)
        
        print(f"FAKE RANSOMWARE: Encrypted file {i}")
        sys.stdout.flush()
        time.sleep(0.1)  # Fast but detectable
        
    except Exception as e:
        print(f"FAKE RANSOMWARE: Error: {e}")
        sys.stdout.flush()

# Create ransom note
ransom_note = os.path.join(test_dir, "DECRYPT_YOUR_FILES.txt")
with open(ransom_note, "w") as f:
    f.write("Your files have been encrypted! Pay ransom to decrypt!")

print("FAKE RANSOMWARE: Ransom note created")
sys.stdout.flush()

# Keep running to test termination
print("FAKE RANSOMWARE: Keeping process alive for termination test...")
sys.stdout.flush()
while True:
    time.sleep(1)
'''
    
    script_path = "test_fake_ransomware.py"
    with open(script_path, "w") as f:
        f.write(test_script)
    
    return script_path

def test_system_response():
    """Test the complete system response to actual ransomware behavior."""
    print("=== TESTING IMPROVED DEADBOLT SYSTEM ===")
    print("This test will:")
    print("1. Start the Deadbolt detection system")
    print("2. Launch a fake ransomware process")
    print("3. Verify the system detects and terminates the threat")
    print()
    
    # Step 1: Create test ransomware script
    print("📝 Creating test ransomware script...")
    ransomware_script = create_test_ransomware_process()
    
    # Step 2: Start Deadbolt system in background
    print("🛡️ Starting Deadbolt system...")
    deadbolt_process = subprocess.Popen([
        sys.executable, "main.py"
    ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    
    # Give system time to initialize
    time.sleep(3)
    
    try:
        # Step 3: Launch fake ransomware
        print("🦠 Launching fake ransomware process...")
        ransomware_process = subprocess.Popen([
            sys.executable, ransomware_script
        ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        print(f"   📍 Ransomware PID: {ransomware_process.pid}")
        
        # Step 4: Monitor for detection and termination
        print("⏳ Monitoring system response...")
        
        start_time = time.time()
        max_wait_time = 30  # Wait up to 30 seconds
        
        while time.time() - start_time < max_wait_time:
            # Check if ransomware process is still running
            poll_result = ransomware_process.poll()
            if poll_result is not None:
                print(f"✅ SUCCESS: Ransomware process terminated! Exit code: {poll_result}")
                break
            
            print(f"   ⏱️ Waiting... {int(time.time() - start_time)}s")
            time.sleep(2)
        else:
            print("❌ TIMEOUT: Ransomware process was not terminated within 30 seconds")
            ransomware_process.terminate()
        
        # Step 5: Check logs for evidence of detection
        print("\n📋 Checking detection logs...")
        try:
            with open("logs/detector.log", "r") as f:
                recent_logs = f.readlines()[-20:]  # Last 20 lines
                
            print("Recent detector log entries:")
            for line in recent_logs:
                if "mass_modification" in line or "CRITICAL" in line:
                    print(f"   🔍 {line.strip()}")
        except FileNotFoundError:
            print("   ⚠️ Detector log not found")
        
        print("\n📋 Checking responder logs...")
        try:
            with open("logs/responder.log", "r") as f:
                recent_logs = f.readlines()[-10:]  # Last 10 lines
                
            print("Recent responder log entries:")
            for line in recent_logs:
                if "THREAT RESPONSE" in line or "terminated" in line or "CRITICAL" in line:
                    print(f"   🎯 {line.strip()}")
        except FileNotFoundError:
            print("   ⚠️ Responder log not found")
    
    finally:
        # Clean up
        print("\\n🧹 Cleaning up...")
        try:
            if ransomware_process.poll() is None:
                ransomware_process.terminate()
        except:
            pass
        
        try:
            deadbolt_process.terminate()
        except:
            pass
        
        # Remove test files
        try:
            os.remove(ransomware_script)
        except:
            pass
        
        # Remove test directory
        try:
            import shutil
            test_dir = r"C:\\Users\\MADHURIMA\\Documents\\test_ransomware_target"
            if os.path.exists(test_dir):
                shutil.rmtree(test_dir)
        except:
            pass
    
    print("\\n=== TEST COMPLETE ===")

if __name__ == "__main__":
    test_system_response()