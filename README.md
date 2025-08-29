# Deadbolt Ransomware Defender

A comprehensive behavior-based ransomware detection and prevention system for Windows.

## 🛡️ Features

- **Real-time File System Monitoring**: Monitors directories for suspicious file operations
- **Behavior-based Detection**: Uses smart rules to detect ransomware patterns:
  - Mass file deletion
  - Mass file renaming/moving
  - Mass file modifications (potential encryption)
  - Suspicious file extensions (.encrypted, .locked, etc.)
  - Suspicious filenames (ransom notes)
- **Advanced Process Analysis**: Monitors process behavior patterns
- **Multi-layer Response System**: 
  - Python-based process termination
  - C++ advanced process killer
  - Emergency protective measures
- **Real-time Notifications**: Windows toast notifications for immediate alerts
- **Comprehensive Logging**: Detailed logs in the `logs` folder

## 📋 Requirements

- Windows 10/11
- Python 3.7 or later
- Administrator privileges (recommended for full protection)

### Python Dependencies
```
watchdog
psutil
win10toast
python-dotenv
```

### Optional: C++ Compiler
For the advanced DeadboltKiller component:
- MinGW-w64 (g++)
- OR Microsoft Visual Studio (cl)

## 🚀 Quick Start

### Option 1: Easy Start (Recommended)
1. Right-click on `start_defender.bat` and select "Run as administrator"
2. The script will automatically:
   - Check and install Python dependencies
   - Compile the C++ killer (if compiler available)
   - Start the defender in background mode

### Option 2: Manual Installation
1. Install Python dependencies:
   ```bash
   pip install watchdog psutil win10toast python-dotenv
   ```

2. (Optional) Compile the C++ killer:
   ```bash
   g++ -o DeadboltKiller.exe DeadboltKiller.cpp -lpsapi -static-libgcc -static-libstdc++
   ```

3. Start the defender:
   ```bash
   python main.py
   ```

## 🎮 Usage

### Batch Scripts (Recommended)
- **`start_defender.bat`** - Start the defender (run as administrator)
- **`stop_defender.bat`** - Stop the defender
- **`status_defender.bat`** - Check defender status
- **`interactive_defender.bat`** - Run in interactive mode for testing

### Command Line Options
```bash
# Start in daemon mode (background)
python main.py --daemon

# Start in interactive mode
python main.py --interactive

# Enable debug logging
python main.py --debug

# Check status
python main.py --status
```

### Interactive Commands
When running in interactive mode, you can use:
- `status` - Show system status
- `threats` - Show detected threats
- `responses` - Show response history
- `help` - Show available commands
- `stop` - Stop the defender

## ⚙️ Configuration

Edit `config.py` to customize:

### Monitored Directories
```python
TARGET_DIRS = [
    r"C:\Users\MADHURIMA\Documents",
    r"C:\Users\MADHURIMA\Desktop",
    # Add more directories as needed
]
```

### Detection Rules
```python
RULES = {
    "mass_delete": {
        "count": 10,  # Number of deletions
        "interval": 5  # Within 5 seconds
    },
    "mass_rename": {
        "count": 10,  # Number of renames
        "interval": 5  # Within 5 seconds
    }
}
```

### Response Actions
```python
ACTIONS = {
    "kill_process": True,    # Enable process termination
    "dry_run": False,        # Set to True for testing
    "log_only": False        # Set to True to only log threats
}
```

## 📊 System Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   File System   │    │   Threat       │    │   Response      │
│   Watcher       │───▶│   Detector     │───▶│   Handler       │
│   (watcher.py)  │    │   (detector.py)│    │   (responder.py)│
└─────────────────┘    └─────────────────┘    └─────────────────┘
         │                       │                       │
         ▼                       ▼                       ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Watchdog      │    │   Behavior      │    │   Python +      │
│   Monitoring    │    │   Analysis      │    │   C++ Killer    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔍 How It Works

1. **Monitoring Phase**:
   - `watcher.py` monitors file system events using the Watchdog library
   - Tracks file creations, deletions, modifications, and renames
   - Monitors process behavior in the background

2. **Detection Phase**:
   - `detector.py` analyzes events for suspicious patterns
   - Calculates threat scores based on multiple factors
   - Identifies potentially malicious processes

3. **Response Phase**:
   - `responder.py` takes action based on threat level
   - Attempts Python-based process termination first
   - Falls back to C++ advanced killer for resistant processes
   - Sends real-time notifications to user

## 📁 File Structure

```
deadbolt 5/
├── main.py                 # Main orchestrator
├── watcher.py             # File system watcher
├── detector.py            # Threat detection engine
├── responder.py           # Response handler
├── config.py              # Configuration settings
├── DeadboltKiller.cpp     # C++ advanced process killer
├── start_defender.bat     # Start script
├── stop_defender.bat      # Stop script
├── status_defender.bat    # Status check script
├── interactive_defender.bat # Interactive mode script
├── logs/                  # Log directory
│   ├── main.log          # Main system log
│   ├── watcher.log       # File system events
│   ├── detector.log      # Threat detection log
│   ├── responder.log     # Response actions log
│   ├── threats.json      # Detected threats (JSON)
│   └── responses.json    # Response history (JSON)
└── ui/                   # UI components (existing)
    ├── main_gui.py
    ├── dashboard.py
    └── alerts.py
```

## 🚨 Alert Levels

- **LOW**: Logging only, no action taken
- **MEDIUM**: Enhanced monitoring, user notification
- **HIGH**: Process analysis, potential termination
- **CRITICAL**: Immediate response, emergency measures

## 🔒 Security Features

- **Administrative Privilege Detection**: Warns if not running with proper privileges
- **Process Resistance Handling**: Multiple termination methods for stubborn processes
- **Emergency Response**: Broad protective measures for critical threats
- **Safe Process Filtering**: Avoids terminating system processes and itself

## 🐛 Troubleshooting

### Common Issues

1. **"Access Denied" errors**:
   - Run as administrator
   - Check Windows Defender exclusions

2. **Python import errors**:
   - Install required packages: `pip install watchdog psutil win10toast python-dotenv`

3. **C++ killer not available**:
   - Install MinGW-w64 or Visual Studio
   - System will work without it, but with reduced capability

4. **No notifications**:
   - Check Windows notification settings
   - Ensure win10toast is properly installed

### Log Files
Check the `logs` directory for detailed information:
- `main.log` - Overall system status
- `detector.log` - Threat analysis details
- `responder.log` - Response actions
- `threats.json` - Raw threat data
- `responses.json` - Response history

## ⚠️ Important Notes

1. **This is a defensive tool** - Use only for legitimate system protection
2. **Test in dry-run mode first** - Set `dry_run: True` in config.py
3. **Monitor logs regularly** - Check for false positives
4. **Keep backups** - This tool cannot recover encrypted files
5. **Administrative privileges** - Required for optimal protection

## 🤝 Contributing

This is a security tool. Please test thoroughly before making changes and ensure all modifications maintain system safety.

## 📄 License

This tool is provided for educational and legitimate security purposes only.

---

**⚡ Remember: Prevention is better than cure. Keep your system updated and maintain regular backups!**