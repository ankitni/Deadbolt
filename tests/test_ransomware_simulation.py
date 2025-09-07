import os
import time

# Simulate ransomware behavior by rapidly creating and deleting files
test_dir = r"C:\Users\MADHURIMA\Documents\testtxt"

print("Starting ransomware simulation...")
print(f"Target directory: {test_dir}")

# Create multiple files rapidly to trigger mass modification detection
for i in range(20):
    file_path = os.path.join(test_dir, f"ransomware_test_{i}.txt")
    with open(file_path, "w") as f:
        f.write("This is a test file for ransomware detection.")
    time.sleep(0.1)  # Small delay between file creations

print("Created 20 test files.")

# Now rapidly modify them to simulate encryption
print("Simulating file encryption...")
for i in range(20):
    file_path = os.path.join(test_dir, f"ransomware_test_{i}.txt")
    if os.path.exists(file_path):
        with open(file_path, "w") as f:
            f.write("ENCRYPTED" * 100)  # Simulate encryption by changing content
        time.sleep(0.05)  # Very rapid modifications

print("Simulation complete. Check if Deadbolt detected the threat.")