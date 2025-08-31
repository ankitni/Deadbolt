#!/usr/bin/env python3
"""
Advanced Ransomware Simulator for Testing ML-Enhanced Deadbolt
Tests various ransomware behaviors with network simulation
"""

import os
import sys
import time
import shutil
import threading
import socket
import random
from datetime import datetime

class NetworkSimulator:
    """Simulate suspicious network activity"""
    
    def __init__(self):
        self.active = False
        self.connections = []
    
    def simulate_irc_connection(self):
        """Simulate IRC connection (suspicious)"""
        try:
            # Simulate connection to IRC port 6667
            print(f"[NETWORK] Simulating IRC connection to port 6667...")
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(2)
            
            # Try to connect to localhost:6667 (will fail but creates network activity)
            try:
                sock.connect(('127.0.0.1', 6667))
            except:
                pass  # Expected to fail
            finally:
                sock.close()
                
            return {
                'orig_port': random.randint(49000, 65000),
                'resp_port': 6667,
                'protocol': 'tcp',
                'service': 'irc',
                'duration': 2.5,
                'orig_bytes': 75,
                'resp_bytes': 243,
                'conn_state': 'S3',
                'history': 'ShAdDaf'
            }
        except Exception as e:
            print(f"[NETWORK] Simulation error: {e}")
            return None
    
    def simulate_http_connection(self):
        """Simulate normal HTTP connection (benign)"""
        return {
            'orig_port': random.randint(49000, 65000),
            'resp_port': 80,
            'protocol': 'tcp',
            'service': 'http',
            'duration': 1.5,
            'orig_bytes': 512,
            'resp_bytes': 8192,
            'conn_state': 'SF',
            'history': 'ShADadfF'
        }

class AdvancedRansomwareSimulator:
    """Advanced ransomware simulator with ML test scenarios"""
    
    def __init__(self, target_dir="test_files"):
        self.target_dir = target_dir
        self.network_sim = NetworkSimulator()
        self.files_created = []
        self.is_running = False
        
    def setup_test_environment(self):
        """Create test environment"""
        print(f"[SETUP] Creating test environment in {self.target_dir}")
        
        # Create target directory
        if os.path.exists(self.target_dir):
            shutil.rmtree(self.target_dir)
        os.makedirs(self.target_dir, exist_ok=True)
        
        # Create test files
        test_files = [
            "document1.txt",
            "document2.docx", 
            "image1.jpg",
            "image2.png",
            "data.xlsx",
            "presentation.pptx",
            "archive.zip",
            "database.db",
            "config.ini",
            "script.py"
        ]
        
        for filename in test_files:
            filepath = os.path.join(self.target_dir, filename)
            with open(filepath, 'w') as f:
                f.write(f"Test content for {filename}\n" * 10)
            self.files_created.append(filepath)
        
        print(f"[SETUP] Created {len(self.files_created)} test files")
    
    def cleanup_test_environment(self):
        """Clean up test environment"""
        print(f"[CLEANUP] Removing test environment...")
        if os.path.exists(self.target_dir):
            shutil.rmtree(self.target_dir)
    
    def scenario_mass_encryption(self):
        """Test Scenario 1: Mass file encryption with network activity"""
        print("\n" + "="*60)
        print("🦠 SCENARIO 1: Mass Encryption Attack (with IRC)")
        print("="*60)
        
        # Simulate suspicious IRC network activity
        network_info = self.network_sim.simulate_irc_connection()
        if network_info:
            print(f"[NETWORK] IRC connection: {network_info['resp_port']}")
        
        encrypted_count = 0
        start_time = time.time()
        
        # Rapid file encryption simulation
        for i, filepath in enumerate(self.files_created[:8]):  # Encrypt 8 files rapidly
            if not os.path.exists(filepath):
                continue
                
            # Rename to .encrypted extension
            encrypted_path = filepath + ".encrypted"
            
            try:
                # Simulate encryption process
                with open(filepath, 'rb') as original:
                    data = original.read()
                
                # Simple "encryption" (XOR with key)
                encrypted_data = bytes([b ^ 0x42 for b in data])
                
                with open(encrypted_path, 'wb') as encrypted:
                    encrypted.write(encrypted_data)
                
                # Remove original
                os.remove(filepath)
                encrypted_count += 1
                
                print(f"[ENCRYPT] {os.path.basename(filepath)} -> {os.path.basename(encrypted_path)}")
                
                # Small delay to simulate realistic encryption speed
                time.sleep(0.1)
                
            except Exception as e:
                print(f"[ERROR] Failed to encrypt {filepath}: {e}")
        
        elapsed = time.time() - start_time
        print(f"[RESULT] Encrypted {encrypted_count} files in {elapsed:.2f} seconds")
        
        # Create ransom note
        ransom_note = os.path.join(self.target_dir, "README_DECRYPT.txt")
        with open(ransom_note, 'w') as f:
            f.write("""
YOUR FILES HAVE BEEN ENCRYPTED!

All your important files have been encrypted with strong encryption.
To recover your files, you need to pay a ransom.

Contact: evil@ransomware.com
Bitcoin Address: 1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2

DEADBOLT TEST - This is a simulation!
""")
        print(f"[RANSOM] Created ransom note: {ransom_note}")
        
        return {
            'type': 'mass_modification',
            'severity': 'CRITICAL',
            'description': 'Mass file encryption attack',
            'count': encrypted_count,
            'process_info': [(os.getpid(), 'test_ransomware_advanced.py')],
            'network_info': network_info,
            'files_affected': [f + ".encrypted" for f in self.files_created[:encrypted_count]]
        }
    
    def scenario_mass_deletion(self):
        """Test Scenario 2: Mass file deletion"""
        print("\n" + "="*60)
        print("🗑️ SCENARIO 2: Mass Deletion Attack")
        print("="*60)
        
        deleted_count = 0
        start_time = time.time()
        
        # Delete remaining files rapidly
        remaining_files = [f for f in self.files_created if os.path.exists(f)]
        
        for filepath in remaining_files[:6]:  # Delete 6 files rapidly
            try:
                os.remove(filepath)
                deleted_count += 1
                print(f"[DELETE] Removed {os.path.basename(filepath)}")
                time.sleep(0.05)  # Very rapid deletion
            except Exception as e:
                print(f"[ERROR] Failed to delete {filepath}: {e}")
        
        elapsed = time.time() - start_time
        print(f"[RESULT] Deleted {deleted_count} files in {elapsed:.2f} seconds")
        
        return {
            'type': 'mass_delete',
            'severity': 'HIGH',
            'description': 'Mass file deletion attack',
            'count': deleted_count,
            'process_info': [(os.getpid(), 'test_ransomware_advanced.py')],
            'network_info': self.network_sim.simulate_http_connection()  # Normal traffic
        }
    
    def scenario_stealth_rename(self):
        """Test Scenario 3: Stealth file renaming"""
        print("\n" + "="*60)
        print("🎭 SCENARIO 3: Stealth Rename Attack")
        print("="*60)
        
        renamed_count = 0
        start_time = time.time()
        
        # Create some new files for renaming
        temp_files = []
        for i in range(5):
            temp_file = os.path.join(self.target_dir, f"temp_{i}.tmp")
            with open(temp_file, 'w') as f:
                f.write(f"Temporary file {i}")
            temp_files.append(temp_file)
        
        # Rapid renaming to suspicious extensions
        for i, filepath in enumerate(temp_files):
            try:
                new_path = filepath.replace('.tmp', '.locked')
                os.rename(filepath, new_path)
                renamed_count += 1
                print(f"[RENAME] {os.path.basename(filepath)} -> {os.path.basename(new_path)}")
                time.sleep(0.08)  # Rapid renaming
            except Exception as e:
                print(f"[ERROR] Failed to rename {filepath}: {e}")
        
        elapsed = time.time() - start_time
        print(f"[RESULT] Renamed {renamed_count} files in {elapsed:.2f} seconds")
        
        return {
            'type': 'mass_rename',
            'severity': 'MEDIUM',
            'description': 'Mass file renaming attack',
            'count': renamed_count,
            'process_info': [(os.getpid(), 'test_ransomware_advanced.py')],
            'network_info': self.network_sim.simulate_irc_connection()  # Suspicious network
        }
    
    def scenario_combined_attack(self):
        """Test Scenario 4: Combined multi-vector attack"""
        print("\n" + "="*60)
        print("💥 SCENARIO 4: Combined Multi-Vector Attack")
        print("="*60)
        
        # Create more test files
        for i in range(10):
            temp_file = os.path.join(self.target_dir, f"combined_{i}.dat")
            with open(temp_file, 'w') as f:
                f.write(f"Combined test file {i}\n" * 5)
        
        # Phase 1: Encrypt some files
        print("[PHASE 1] Encryption phase...")
        for i in range(4):
            source = os.path.join(self.target_dir, f"combined_{i}.dat")
            if os.path.exists(source):
                encrypted = source + ".enc"
                with open(source, 'r') as f:
                    content = f.read()
                with open(encrypted, 'w') as f:
                    f.write("ENCRYPTED:" + content[::-1])  # Simple encryption
                os.remove(source)
                print(f"[ENCRYPT] combined_{i}.dat -> combined_{i}.dat.enc")
                time.sleep(0.1)
        
        # Phase 2: Delete some files
        print("[PHASE 2] Deletion phase...")
        for i in range(4, 7):
            source = os.path.join(self.target_dir, f"combined_{i}.dat")
            if os.path.exists(source):
                os.remove(source)
                print(f"[DELETE] combined_{i}.dat")
                time.sleep(0.05)
        
        # Phase 3: Rename remaining files
        print("[PHASE 3] Rename phase...")
        for i in range(7, 10):
            source = os.path.join(self.target_dir, f"combined_{i}.dat")
            if os.path.exists(source):
                renamed = source.replace('.dat', '.crypted')
                os.rename(source, renamed)
                print(f"[RENAME] combined_{i}.dat -> combined_{i}.crypted")
                time.sleep(0.08)
        
        return {
            'type': 'combined_attack',
            'severity': 'CRITICAL',
            'description': 'Multi-vector ransomware attack',
            'count': 10,
            'process_info': [(os.getpid(), 'test_ransomware_advanced.py')],
            'network_info': self.network_sim.simulate_irc_connection()
        }
    
    def run_all_scenarios(self, delay_between=5):
        """Run all test scenarios"""
        print("\n🧪 DEADBOLT ML-ENHANCED TESTING SUITE")
        print("="*60)
        print("Testing against various ransomware attack patterns...")
        print("The ML-enhanced detector should:")
        print("  🤖 Use AI to reduce false positives") 
        print("  ⚡ Maintain 2-second detection speed")
        print("  🎯 Smart process targeting")
        print("="*60)
        
        self.is_running = True
        results = []
        
        try:
            # Setup
            self.setup_test_environment()
            
            # Wait for Deadbolt to start monitoring
            print(f"\n⏱️ Waiting {delay_between} seconds for Deadbolt to initialize...")
            time.sleep(delay_between)
            
            # Run scenarios
            scenarios = [
                ("Mass Encryption", self.scenario_mass_encryption),
                ("Mass Deletion", self.scenario_mass_deletion), 
                ("Stealth Rename", self.scenario_stealth_rename),
                ("Combined Attack", self.scenario_combined_attack)
            ]
            
            for i, (name, scenario_func) in enumerate(scenarios, 1):
                print(f"\n🎯 STARTING SCENARIO {i}: {name}")
                print("⏰ Starting in 3 seconds...")
                time.sleep(3)
                
                result = scenario_func()
                results.append(result)
                
                print(f"✅ SCENARIO {i} COMPLETED")
                if i < len(scenarios):
                    print(f"⏱️ Next scenario in {delay_between} seconds...")
                    time.sleep(delay_between)
            
            print("\n" + "="*60)
            print("🎉 ALL SCENARIOS COMPLETED")
            print("="*60)
            print("Check Deadbolt logs for ML detection results:")
            print("  📄 logs/ml_detector.log - ML-enhanced detection events")
            print("  📄 logs/main.log - System events")
            print("  📄 logs/threats.json - Detected threats")
            print("="*60)
            
        except KeyboardInterrupt:
            print("\n⏹️ Test interrupted by user")
        except Exception as e:
            print(f"\n❌ Test error: {e}")
            import traceback
            traceback.print_exc()
        finally:
            self.is_running = False
            # Keep test files for manual inspection
            print("\n📁 Test files preserved for inspection in:", self.target_dir)
            # self.cleanup_test_environment()  # Comment out to keep files for inspection

def main():
    """Main test function"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Advanced Ransomware Simulator for ML-Enhanced Deadbolt Testing")
    parser.add_argument("--scenario", choices=['encrypt', 'delete', 'rename', 'combined', 'all'], 
                       default='all', help="Scenario to run")
    parser.add_argument("--delay", type=int, default=5, help="Delay between scenarios (seconds)")
    parser.add_argument("--target-dir", default="test_files", help="Target directory for test files")
    
    args = parser.parse_args()
    
    simulator = AdvancedRansomwareSimulator(args.target_dir)
    
    if args.scenario == 'all':
        simulator.run_all_scenarios(args.delay)
    else:
        simulator.setup_test_environment()
        
        if args.scenario == 'encrypt':
            simulator.scenario_mass_encryption()
        elif args.scenario == 'delete':
            simulator.scenario_mass_deletion()
        elif args.scenario == 'rename':
            simulator.scenario_stealth_rename()
        elif args.scenario == 'combined':
            simulator.scenario_combined_attack()

if __name__ == "__main__":
    main()