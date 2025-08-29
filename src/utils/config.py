# Configuration settings for Deadbolt AI
import os

# Try to load environment variables from .env file if available
try:
    from dotenv import load_dotenv
    load_dotenv()
    env_loaded = True
except ImportError:
    env_loaded = False

# Directories to monitor - can be overridden with TARGET_DIRS env var
default_dirs = [
    r"C:\Users\MADHURIMA\Documents\testtxt",  # Test directory for comprehensive testing
    r"C:\Users\MADHURIMA\Documents",
    # Add more directories as needed
]

# Load from environment variable if available
env_dirs = os.getenv("TARGET_DIRS")
TARGET_DIRS = env_dirs.split(";") if env_dirs else default_dirs

# Event debouncing to prevent event floods
DEBOUNCE_SECONDS = float(os.getenv("DEBOUNCE_SECONDS", "1.0"))

# File extensions to ignore
IGNORED_EXTENSIONS = (
    ".tmp", ".log", ".swp", ".DS_Store", ".lock", ".bak", ".part", ".crdownload"
)

# Suspicious file extensions (potential ransomware indicators)
SUSPICIOUS_PATTERNS = {
    "extensions": [".enc", ".locked", ".crypted", ".crypt", ".crypto", ".encrypted", 
                   ".xxx", ".zzz", ".666", ".virus", ".evil", ".hacked", ".ransom"],
    "filenames": ["DECRYPT", "RANSOM", "README", "HOW_TO", "HELP_DECRYPT", "RESTORE"]
}

# Detection rules with thresholds - AGGRESSIVE BEHAVIOR-BASED DETECTION
RULES = {
    "mass_delete": {
        "count": int(os.getenv("MASS_DELETE_COUNT", "3")),  # 3 deletions in 2 seconds - FASTER
        "interval": int(os.getenv("MASS_DELETE_INTERVAL", "2"))
    },
    "mass_rename": {
        "count": int(os.getenv("MASS_RENAME_COUNT", "3")),  # 3 renames in 2 seconds - FASTER
        "interval": int(os.getenv("MASS_RENAME_INTERVAL", "2"))  
    },
    "mass_modification": {
        "count": int(os.getenv("MASS_MODIFICATION_COUNT", "4")),  # 4 modifications in 2 seconds - MUCH FASTER
        "interval": int(os.getenv("MASS_MODIFICATION_INTERVAL", "2"))
    }
}

# Response actions configuration
ACTIONS = {
    "log_only": os.getenv("LOG_ONLY", "False").lower() == "true",
    # kill_process is CRITICAL for ransomware protection - enabled by default
    # This allows immediate termination of suspicious processes
    "kill_process": os.getenv("KILL_PROCESS", "True").lower() == "true",
    "shutdown": os.getenv("SHUTDOWN", "False").lower() == "true",
    "dry_run": os.getenv("DRY_RUN", "False").lower() == "true"  # Test mode, don't take real actions
}