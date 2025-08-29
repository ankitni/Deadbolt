# Deadbolt 5 - Project Structure

## Overview
Deadbolt 5 is a behavior-based ransomware detection and prevention system for Windows that monitors file system activity and responds to suspicious behavior patterns.

## Project Structure

```
deadbolt 5/
├── src/                          # Source code
│   ├── core/                     # Core system components
│   │   ├── main.py              # Main system orchestrator
│   │   ├── detector.py          # Threat detection engine
│   │   ├── responder.py         # Response handler
│   │   ├── watcher.py           # File system monitor
│   │   └── DeadboltKiller.cpp   # C++ process termination
│   ├── ui/                       # User interface
│   │   ├── main_gui.py          # Main GUI application
│   │   ├── dashboard.py         # Monitoring dashboard
│   │   └── alerts.py            # Alert management
│   └── utils/                    # Utility modules
│       ├── config.py            # Configuration constants
│       ├── config_manager.py    # Configuration management
│       └── logger.py            # Logging utilities
├── tests/                        # Test suite
│   ├── unit/                    # Unit tests
│   ├── integration/             # Integration tests
│   ├── test_*.py               # Test scripts
│   └── validation scripts
├── scripts/                      # Batch scripts
│   ├── start_defender.bat      # Start system
│   ├── stop_defender.bat       # Stop system
│   └── status_defender.bat     # Check status
├── config/                       # Configuration files
│   └── deadbolt_config.json    # System configuration
├── logs/                         # Log files
│   ├── main.log                # Main system log
│   ├── detector.log            # Detection events
│   ├── responder.log           # Response actions
│   └── watcher.log             # File monitoring
├── bin/                          # Compiled binaries
│   └── DeadboltKiller.exe      # C++ process killer
├── docs/                         # Documentation
├── examples/                     # Usage examples
├── build/                        # Build artifacts
├── deadbolt.py                   # Main entry point
├── requirements.txt              # Python dependencies
└── README.md                     # Project documentation
```

## Quick Start

### Installation
1. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

2. Compile C++ component (optional):
   ```bash
   cd src/core
   g++ -o ../../bin/DeadboltKiller.exe DeadboltKiller.cpp -lpsapi -static-libgcc -static-libstdc++
   ```

### Usage

#### GUI Mode (Recommended)
```bash
python deadbolt.py --gui
```

#### Command Line Mode
```bash
python deadbolt.py --daemon
```

#### Interactive Mode
```bash
python deadbolt.py --interactive
```

#### Using Batch Scripts
- Start: `scripts\start_defender.bat`
- Stop: `scripts\stop_defender.bat`
- Status: `scripts\status_defender.bat`

## Core Features

### Detection Engine
- Real-time file system monitoring
- Behavior-based threat detection
- Mass modification/deletion detection
- Suspicious file pattern recognition
- Ransom note detection

### Response System
- Multi-layer process termination
- Python primary response
- C++ fallback termination
- Smart target identification
- False positive prevention

### User Interface
- Real-time dashboard with live statistics
- System health monitoring
- Alert management
- Configuration interface
- Log viewing and filtering

### Configuration Management
- Persistent settings storage
- Directory path management
- Detection rule customization
- Response action configuration

## System Requirements

- **OS**: Windows 10/11
- **Python**: 3.7+
- **Privileges**: Administrator (recommended)
- **Dependencies**: See requirements.txt

## Architecture

The system follows a modular architecture with clear separation of concerns:

1. **File System Watcher**: Monitors directories for file events
2. **Threat Detector**: Analyzes events for suspicious patterns
3. **Response Handler**: Takes action against detected threats
4. **User Interface**: Provides monitoring and configuration capabilities

## Security Features

- Safe process filtering to avoid system processes
- Configurable detection thresholds
- Notification cooldown to prevent spam
- Comprehensive logging for audit trails
- Multi-layer fallback termination

## Development

### Adding New Features
1. Core functionality: Add to `src/core/`
2. UI components: Add to `src/ui/`
3. Utilities: Add to `src/utils/`
4. Tests: Add to `tests/`

### Testing
- Unit tests: `tests/unit/`
- Integration tests: `tests/integration/`
- Run all tests: Check `tests/` directory

## License
This project is part of a security research initiative. Use responsibly and in accordance with local laws and regulations.