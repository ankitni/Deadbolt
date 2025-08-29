"""
Ransomware Simulator for Testing Deadbolt Defender
This script simulates ransomware behavior to test the detection system.
WARNING: This is for testing purposes only. Use in a controlled environment.
"""

import os
import time
import random
import threading
from cryptography.fernet import Fernet
import tempfile
import shutil
import argparse

class RansomwareSimulator:
    """Simulates various ransomware behaviors for testing purposes."""
    
    def __init__(self, test_dir=None, intensity='medium'):
        self.test_dir = test_dir or self._create_test_directory()
        self.intensity = intensity
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.is_running = False
        self.encrypted_files = []
        
        # Behavior parameters based on intensity
        self.behavior_params = {
            'low': {'file_count': 5, 'delay': 2, 'batch_size': 2},
            'medium': {'file_count': 15, 'delay': 1, 'batch_size': 5},
            'high': {'file_count': 30, 'delay': 0.5, 'batch_size': 10},
            'extreme': {'file_count': 50, 'delay': 0.1, 'batch_size': 15}
        }
        
        self.params = self.behavior_params.get(intensity, self.behavior_params['medium'])
        
        print(f"Ransomware Simulator initialized:")
        print(f"  Test Directory: {self.test_dir}")
        print(f"  Intensity: {intensity}")
        print(f"  Parameters: {self.params}")
        
    def _create_test_directory(self):
        """Create a temporary test directory with sample files."""
        test_dir = os.path.join(tempfile.gettempdir(), "ransomware_test")
        os.makedirs(test_dir, exist_ok=True)
        
        # Create subdirectories
        subdirs = ['documents', 'pictures', 'videos', 'archives']
        for subdir in subdirs:
            os.makedirs(os.path.join(test_dir, subdir), exist_ok=True)
        
        # Create test files with different extensions
        file_types = [
            ('documents', ['.txt', '.doc', '.pdf', '.xlsx']),
            ('pictures', ['.jpg', '.png', '.gif', '.bmp']),
            ('videos', ['.mp4', '.avi', '.mkv', '.mov']),
            ('archives', ['.zip', '.rar', '.7z', '.tar'])
        ]
        
        for subdir, extensions in file_types:
            for i in range(5):
                for ext in extensions:
                    filename = f"test_file_{i}{ext}"
                    filepath = os.path.join(test_dir, subdir, filename)
                    
                    # Create files with some content
                    content = f"This is test file {filename}\n" * 10
                    with open(filepath, 'w', encoding='utf-8', errors='ignore') as f:
                        f.write(content)
        
        return test_dir
    
    def simulate_mass_encryption(self):
        """Simulate mass file encryption behavior."""
        print(f"\n🔥 Starting MASS ENCRYPTION simulation...")
        
        # Get all files in test directory
        all_files = []
        for root, dirs, files in os.walk(self.test_dir):
            for file in files:
                if not file.endswith('.encrypted'):
                    all_files.append(os.path.join(root, file))
        
        # Limit to configured number of files
        target_files = all_files[:self.params['file_count']]
        
        print(f"Targeting {len(target_files)} files for encryption...")
        
        # Encrypt files in batches to trigger mass modification detection
        for i in range(0, len(target_files), self.params['batch_size']):
            batch = target_files[i:i + self.params['batch_size']]
            
            print(f"Encrypting batch {i//self.params['batch_size'] + 1}: {len(batch)} files")
            
            # Encrypt all files in this batch quickly
            for filepath in batch:
                try:
                    self._encrypt_file(filepath)
                except Exception as e:
                    print(f"Error encrypting {filepath}: {e}")
            
            # Small delay between batches
            time.sleep(self.params['delay'])
    
    def simulate_mass_deletion(self):
        """Simulate mass file deletion behavior."""
        print(f"\n🗑️ Starting MASS DELETION simulation...")
        
        # Get some files to delete
        delete_files = []
        for root, dirs, files in os.walk(self.test_dir):
            for file in files:
                if not file.endswith('.encrypted') and len(delete_files) < self.params['file_count']:
                    delete_files.append(os.path.join(root, file))
        
        print(f"Targeting {len(delete_files)} files for deletion...")
        
        # Delete files in batches
        for i in range(0, len(delete_files), self.params['batch_size']):
            batch = delete_files[i:i + self.params['batch_size']]
            
            print(f"Deleting batch {i//self.params['batch_size'] + 1}: {len(batch)} files")
            
            for filepath in batch:
                try:
                    os.remove(filepath)
                    print(f"  Deleted: {os.path.basename(filepath)}")
                except Exception as e:
                    print(f"Error deleting {filepath}: {e}")
            
            time.sleep(self.params['delay'])
    
    def simulate_mass_rename(self):
        """Simulate mass file renaming behavior."""
        print(f"\n📝 Starting MASS RENAME simulation...")
        
        # Get files to rename
        rename_files = []
        for root, dirs, files in os.walk(self.test_dir):
            for file in files:
                if not file.endswith('.locked') and len(rename_files) < self.params['file_count']:
                    rename_files.append(os.path.join(root, file))
        
        print(f"Targeting {len(rename_files)} files for renaming...")
        
        # Rename files in batches
        for i in range(0, len(rename_files), self.params['batch_size']):
            batch = rename_files[i:i + self.params['batch_size']]
            
            print(f"Renaming batch {i//self.params['batch_size'] + 1}: {len(batch)} files")
            
            for filepath in batch:
                try:
                    new_path = filepath + '.locked'
                    os.rename(filepath, new_path)
                    print(f"  Renamed: {os.path.basename(filepath)} -> {os.path.basename(new_path)}")
                except Exception as e:
                    print(f"Error renaming {filepath}: {e}")
            
            time.sleep(self.params['delay'])
    
    def create_ransom_notes(self):
        """Create typical ransom note files."""
        print(f"\n📄 Creating RANSOM NOTES...")
        
        ransom_notes = [
            "DECRYPT_FILES.txt",
            "HOW_TO_RECOVER.txt", 
            "RANSOM_NOTE.txt",
            "README_DECRYPT.txt",
            "HELP_RESTORE_FILES.txt"
        ]
        
        ransom_content = """
YOUR FILES HAVE BEEN ENCRYPTED!

All your important files have been encrypted with military-grade encryption.
To recover your files, you need to pay the ransom fee.

PAYMENT INSTRUCTIONS:
1. Purchase Bitcoin worth $500
2. Send to address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
3. Email us the transaction ID: recover@evil-ransomware.onion

WARNING:
- Do not try to decrypt files yourself
- Do not contact authorities
- You have 72 hours to pay
- After 72 hours, the price doubles
- After 1 week, files will be permanently deleted

This is a TEST simulation for security testing purposes.
"""
        
        for note_name in ransom_notes:
            note_path = os.path.join(self.test_dir, note_name)
            try:
                with open(note_path, 'w', encoding='utf-8') as f:
                    f.write(ransom_content)
                print(f"  Created ransom note: {note_name}")
            except Exception as e:
                print(f"Error creating ransom note {note_name}: {e}")
    
    def _encrypt_file(self, filepath):
        """Encrypt a single file."""
        try:
            # Read file content
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            # Encrypt the data
            encrypted_data = self.cipher.encrypt(file_data)
            
            # Write encrypted data to new file
            encrypted_path = filepath + '.encrypted'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Remove original file
            os.remove(filepath)
            
            self.encrypted_files.append(encrypted_path)
            print(f"    Encrypted: {os.path.basename(filepath)}")
            
        except Exception as e:
            print(f"    Error encrypting {filepath}: {e}")
    
    def high_cpu_simulation(self):
        """Simulate high CPU usage typical of encryption processes."""
        print(f"\n⚡ Starting HIGH CPU simulation...")
        
        def cpu_intensive_task():
            # Simulate CPU-intensive encryption work
            for _ in range(1000000):
                # Fake encryption work
                data = b"fake data for encryption" * 1000
                encrypted = self.cipher.encrypt(data)
                decrypted = self.cipher.decrypt(encrypted)
        
        # Start multiple threads to increase CPU usage
        threads = []
        for i in range(4):  # 4 threads for high CPU usage
            thread = threading.Thread(target=cpu_intensive_task)
            thread.daemon = True
            thread.start()
            threads.append(thread)
            time.sleep(0.1)  # Stagger thread starts
        
        # Let it run for a few seconds
        time.sleep(5)
        print("High CPU simulation completed")
    
    def run_full_simulation(self):
        """Run a complete ransomware simulation."""
        print("\n" + "="*60)
        print("🚨 STARTING FULL RANSOMWARE SIMULATION 🚨")
        print("="*60)
        
        self.is_running = True
        
        try:
            # Phase 1: High CPU activity (like real ransomware)
            self.high_cpu_simulation()
            
            # Phase 2: Create ransom notes (should trigger suspicious filename detection)
            self.create_ransom_notes()
            time.sleep(2)
            
            # Phase 3: Mass encryption (should trigger mass modification detection)
            self.simulate_mass_encryption()
            time.sleep(2)
            
            # Phase 4: Mass renaming (should trigger mass rename detection)
            self.simulate_mass_rename()
            time.sleep(2)
            
            # Phase 5: Mass deletion (should trigger mass delete detection)
            self.simulate_mass_deletion()
            
        except KeyboardInterrupt:
            print("\n⚠️ Simulation interrupted by user")
        except Exception as e:
            print(f"\n❌ Simulation error: {e}")
        finally:
            self.is_running = False
            print("\n" + "="*60)
            print("🏁 RANSOMWARE SIMULATION COMPLETED")
            print("="*60)
    
    def cleanup(self):
        """Clean up test files and directories."""
        print(f"\n🧹 Cleaning up test directory: {self.test_dir}")
        try:
            shutil.rmtree(self.test_dir)
            print("✅ Cleanup completed successfully")
        except Exception as e:
            print(f"❌ Cleanup error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Ransomware Simulator for Testing')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high', 'extreme'], 
                       default='medium', help='Simulation intensity level')
    parser.add_argument('--test-dir', help='Custom test directory path')
    parser.add_argument('--scenario', choices=['full', 'encryption', 'deletion', 'rename', 'notes'], 
                       default='full', help='Specific scenario to test')
    parser.add_argument('--cleanup', action='store_true', help='Clean up after simulation')
    
    args = parser.parse_args()
    
    print("🧪 RANSOMWARE SIMULATOR - FOR TESTING ONLY")
    print("⚠️  WARNING: This simulates malicious behavior for security testing")
    print("   Use only in controlled environments!")
    print()
    
    simulator = RansomwareSimulator(test_dir=args.test_dir, intensity=args.intensity)
    
    try:
        if args.scenario == 'full':
            simulator.run_full_simulation()
        elif args.scenario == 'encryption':
            simulator.simulate_mass_encryption()
        elif args.scenario == 'deletion':
            simulator.simulate_mass_deletion()
        elif args.scenario == 'rename':
            simulator.simulate_mass_rename()
        elif args.scenario == 'notes':
            simulator.create_ransom_notes()
        
        # Wait for user input before cleanup
        if args.cleanup:
            input("\nPress Enter to clean up test files...")
            simulator.cleanup()
        else:
            print(f"\n📁 Test files are located at: {simulator.test_dir}")
            print("💡 You can manually inspect the files or run with --cleanup to auto-clean")
            
    except KeyboardInterrupt:
        print("\n⚠️ Simulation interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
