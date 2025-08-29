# Modified simulated ransomware encryption script for testing Deadbolt
import os
import time
import sys
import random
import string
from datetime import datetime

# Remove the problematic import
# from encryption import encrypt_files as encryption_module_encrypt_files

def generate_random_content(length=50):
    """Generate random text content"""
    letters = string.ascii_letters + string.digits + " " * 10
    return ''.join(random.choice(letters) for _ in range(length))

def encrypt_files():
    """Simulate ransomware encryption on test files"""
    # Define the target directory
    target_dir = r"C:\Users\MADHURIMA\Documents\testtxt"
    
    # Create the directory if it doesn't exist
    if not os.path.exists(target_dir):
        try:
            os.makedirs(target_dir)
            print(f"Created directory: {target_dir}")
        except Exception as e:
            print(f"Error creating directory: {e}")
            sys.exit(1)
    
    # Always create new test files for simulation
    print("Creating new test files...")
    for i in range(1, 101):
        file_path = os.path.join(target_dir, f"test_{i}.txt")
        try:
            with open(file_path, 'w') as f:
                f.write(generate_random_content())
            print(f"Created file: {file_path}")
        except Exception as e:
            print(f"Error creating file {i}: {e}")

    # Create ransom notes
    ransom_notes = [
        "HOW_TO_DECRYPT_FILES.txt",
        "YOUR_FILES_ARE_LOCKED.txt",
        "READ_ME.txt"
    ]
    ransom_message = (
        "Your files have been encrypted!\n"
        "To recover your data, send 1 Bitcoin to the address below.\n"
        "Contact us at evil@ransomware.com for instructions.\n"
        "Do not try to recover files yourself.\n"
    )
    for note in ransom_notes:
        note_path = os.path.join(target_dir, note)
        with open(note_path, 'w') as f:
            f.write(ransom_message)
        print(f"Ransom note created: {note_path}")
    
    # Simulate full ransomware behavior
    print(f"\n[!] RANSOMWARE ATTACK STARTED IN {target_dir}")
    print(f"[!] Current time: {datetime.now().strftime('%H:%M:%S')}")
    print("[!] Your files are being encrypted!")
    print("[!] DO NOT TURN OFF YOUR COMPUTER\n")

    files_encrypted = 0
    try:
        files = [f for f in os.listdir(target_dir) if os.path.isfile(os.path.join(target_dir, f)) and not (f.endswith('.gujd') or f.endswith('.sdif')) and f not in ransom_notes]
        extensions = ['.gujd', '.sdif']
        for filename in files:
            original_path = os.path.join(target_dir, filename)
            # Randomly choose one of the ransomware extensions
            chosen_ext = random.choice(extensions)
            if '.' in filename:
                base, ext = os.path.splitext(filename)
                encrypted_name = base + chosen_ext
            else:
                encrypted_name = filename + chosen_ext
            encrypted_path = os.path.join(target_dir, encrypted_name)
            try:
                with open(original_path, 'rb') as original_file:
                    content = original_file.read()
                with open(encrypted_path, 'wb') as encrypted_file:
                    encrypted_file.write(b'ENCRYPTED_BY_RANSOMWARE:' + content)
                os.remove(original_path)
                files_encrypted += 1
                print(f"[!] Encrypted: {filename} -> {encrypted_name}")
                # Print warning every 10 files
                if files_encrypted % 10 == 0:
                    print(f"[!!] {files_encrypted} files encrypted!")
                time.sleep(0.05)  # Fast, noisy
            except Exception as e:
                print(f"Error encrypting {filename}: {e}")
    except Exception as e:
        print(f"Error listing directory: {e}")
    print(f"\n[+] RANSOMWARE simulation complete. Encrypted {files_encrypted} files.")
    print(f"[+] Your files are now locked. Read the ransom notes for instructions.")

if __name__ == "__main__":
    try:
        encrypt_files()
    except KeyboardInterrupt:
        print("\n[!] Encryption simulation stopped by user")
    except Exception as e:
        print(f"\n[!] Error during encryption simulation: {e}")