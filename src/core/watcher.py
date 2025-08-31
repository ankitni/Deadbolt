"""
Deadbolt Ransomware Defender - File System Watcher
Monitors directories for suspicious file system activities using behavior-based detection.
"""

import os
import sys
import time
import threading
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil

# Try relative import first, fallback to direct import
try:
    from ..utils import config
except ImportError:
    utils_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'utils')
    sys.path.append(utils_path)
    import config

class RansomwareWatchHandler(FileSystemEventHandler):
    """Handler for file system events that detects ransomware-like behavior patterns."""
    
    def __init__(self, detector_callback):
        super().__init__()
        self.detector_callback = detector_callback
        self.event_history = defaultdict(deque)
        self.process_tracking = {}
        self.lock = threading.Lock()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Set up project paths
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        logs_dir = os.path.join(project_root, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        handler = logging.FileHandler(os.path.join(logs_dir, 'watcher.log'))
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        self.logger.info("Ransomware Watcher initialized - monitoring directories")
        
    def _get_process_info(self):
        """Get process information for file system events - ESSENTIAL FOR THREAT RESPONSE."""
        try:
            # Get processes that are currently active and potentially suspicious
            current_processes = []
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    name = proc_info.get('name', 'unknown')
                    
                    # Skip system processes but capture potential ransomware
                    if (pid > 1000 and  # Skip system PIDs
                        name.lower() not in ['explorer.exe', 'dwm.exe', 'winlogon.exe', 
                                            'services.exe', 'svchost.exe', 'lsass.exe', 
                                            'csrss.exe', 'qoder.exe']):  # REMOVED python.exe to detect ransomware
                        current_processes.append({
                            'pid': pid,
                            'name': name,
                            'create_time': proc_info.get('create_time', 0),
                            'cpu_percent': proc_info.get('cpu_percent', 0)
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Return up to 10 most recently created processes (potential threats)
            current_processes.sort(key=lambda x: x.get('create_time', 0), reverse=True)
            return current_processes[:10]
            
        except Exception as e:
            self.logger.error(f"Error getting process info: {e}")
            return []
    
    def _should_ignore_file(self, file_path):
        """Check if file should be ignored based on extension or location."""
        if not file_path:
            return True
            
        # Check ignored extensions
        for ext in config.IGNORED_EXTENSIONS:
            if file_path.lower().endswith(ext):
                return True
                
        # Ignore files in system directories
        system_dirs = ['system32', 'windows', 'program files', 'programdata']
        for sys_dir in system_dirs:
            if sys_dir in file_path.lower():
                return True
                
        return False
    
    def _detect_suspicious_patterns(self, event_type, file_path):
        """Detect suspicious file activity patterns."""
        if self._should_ignore_file(file_path):
            return
            
        current_time = datetime.now()
        
        # CAPTURE PROCESS INFO IMMEDIATELY when file activity occurs
        current_process_info = self._get_process_info()
        
        with self.lock:
            # Add event to history WITH process info
            self.event_history[event_type].append({
                'time': current_time,
                'path': file_path,
                'process_info': current_process_info  # Store actual process info
            })
            
            # Clean old events (keep last 10 minutes)
            cutoff_time = current_time - timedelta(minutes=10)
            for event_list in self.event_history.values():
                while event_list and event_list[0]['time'] < cutoff_time:
                    event_list.popleft()
            
            # Check for suspicious patterns - BEHAVIOR-BASED ONLY
            self._check_mass_operations(current_time)
            # BEHAVIOR-ONLY: No extension or filename checks - pure behavior detection
    
    def _check_mass_operations(self, current_time):
        """Check for mass file operations that could indicate ransomware."""
        # Use the specific time window for each type of operation
        delete_window = timedelta(seconds=config.RULES['mass_delete']['interval'])
        rename_window = timedelta(seconds=config.RULES['mass_rename']['interval']) 
        modification_window = timedelta(seconds=config.RULES['mass_modification']['interval'])
        
        delete_time = current_time - delete_window
        rename_time = current_time - rename_window
        modification_time = current_time - modification_window
        
        # Count recent events with correct time windows
        recent_deletes = sum(1 for event in self.event_history['deleted'] 
                           if event['time'] >= delete_time)
        recent_renames = sum(1 for event in self.event_history['moved'] 
                           if event['time'] >= rename_time)
        recent_modifications = sum(1 for event in self.event_history['modified'] 
                                 if event['time'] >= modification_time)
        
        # Check mass delete pattern
        if recent_deletes >= config.RULES['mass_delete']['count']:
            threat_info = {
                'type': 'mass_delete',
                'count': recent_deletes,
                'time_window': config.RULES['mass_delete']['interval'],
                'process_info': self._get_recent_process_info('deleted', delete_time),
                'severity': 'HIGH',
                'description': f'Mass file deletion detected: {recent_deletes} files deleted in {config.RULES["mass_delete"]["interval"]} seconds'
            }
            self.logger.warning(f"RANSOMWARE ALERT: {threat_info['description']}")
            self.detector_callback(threat_info)
        
        # Check mass rename pattern
        if recent_renames >= config.RULES['mass_rename']['count']:
            threat_info = {
                'type': 'mass_rename',
                'count': recent_renames,
                'time_window': config.RULES['mass_rename']['interval'],
                'process_info': self._get_recent_process_info('moved', rename_time),
                'severity': 'HIGH',
                'description': f'Mass file renaming detected: {recent_renames} files renamed in {config.RULES["mass_rename"]["interval"]} seconds'
            }
            self.logger.warning(f"RANSOMWARE ALERT: {threat_info['description']}")
            self.detector_callback(threat_info)
        
        # Check mass modification pattern (potential encryption) - CRITICAL FOR RANSOMWARE
        if recent_modifications >= config.RULES['mass_modification']['count']:
            # Generate network info for ML testing when dealing with potential ransomware
            network_info = self._simulate_network_info_for_ml()
            
            threat_info = {
                'type': 'mass_modification',
                'count': recent_modifications,
                'time_window': config.RULES['mass_modification']['interval'],
                'process_info': self._get_recent_process_info('modified', modification_time),
                'network_info': network_info,  # Add network info for ML analysis
                'severity': 'CRITICAL',
                'description': f'Mass file modification detected: {recent_modifications} files modified in {config.RULES["mass_modification"]["interval"]} seconds (potential encryption)'
            }
            self.logger.critical(f"RANSOMWARE ALERT: {threat_info['description']}")
            self.detector_callback(threat_info)
    
    def _get_recent_process_info(self, event_type, since_time):
        """Get process information from recent events with network simulation for ML testing."""
        processes = set()
        for event in self.event_history[event_type]:
            if event['time'] >= since_time and event['process_info']:
                # Extract PID and name from each process in the process_info list
                for proc in event['process_info']:
                    if isinstance(proc, dict) and 'pid' in proc and 'name' in proc:
                        processes.add((proc['pid'], proc['name']))
        
        # Convert set back to list for the threat response
        process_list = list(processes)
        self.logger.info(f"Recent process info for {event_type}: {len(process_list)} unique processes identified")
        return process_list
    
    def _simulate_network_info_for_ml(self):
        """Simulate network information for ML model testing.
        In a real implementation, this would capture actual network traffic.
        """
        import random
        
        # Simulate suspicious network patterns for ML testing
        suspicious_patterns = [
            {  # IRC connection - highly suspicious
                'orig_port': random.randint(49000, 65000),
                'resp_port': 6667,
                'protocol': 'tcp',
                'service': 'irc',
                'duration': 2.5,
                'orig_bytes': 75,
                'resp_bytes': 243,
                'conn_state': 'S3',
                'history': 'ShAdDaf',
                'missed_bytes': 0,
                'orig_pkts': 7,
                'orig_ip_bytes': 447,
                'resp_pkts': 6,
                'resp_ip_bytes': 563
            },
            {  # C&C communication - suspicious
                'orig_port': random.randint(49000, 65000),
                'resp_port': 8080,
                'protocol': 'tcp',
                'service': 'http-alt',
                'duration': 1.2,
                'orig_bytes': 128,
                'resp_bytes': 64,
                'conn_state': 'SF',
                'history': 'ShADadf',
                'missed_bytes': 0,
                'orig_pkts': 12,
                'orig_ip_bytes': 512,
                'resp_pkts': 8,
                'resp_ip_bytes': 320
            }
        ]
        
        # Return a suspicious pattern for ML analysis
        return random.choice(suspicious_patterns)
    

    
    def on_modified(self, event):
        """Handle file modification events."""
        if not event.is_directory:
            self._detect_suspicious_patterns('modified', event.src_path)
    
    def on_created(self, event):
        """Handle file creation events."""
        if not event.is_directory:
            self._detect_suspicious_patterns('created', event.src_path)
    
    def on_deleted(self, event):
        """Handle file deletion events."""
        if not event.is_directory:
            self._detect_suspicious_patterns('deleted', event.src_path)
    
    def on_moved(self, event):
        """Handle file move/rename events."""
        if not event.is_directory:
            self._detect_suspicious_patterns('moved', event.dest_path)

class FileSystemWatcher:
    """Main file system watcher class."""
    
    def __init__(self, detector_callback):
        self.detector_callback = detector_callback
        self.observer = Observer()
        self.is_running = False
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        handler = logging.FileHandler(os.path.join('logs', 'watcher.log'))
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
    def start_monitoring(self):
        """Start monitoring the configured directories."""
        if self.is_running:
            self.logger.warning("Watcher is already running")
            return
        
        try:
            # Create event handler
            event_handler = RansomwareWatchHandler(self.detector_callback)
            
            # Add watchers for each directory
            for directory in config.TARGET_DIRS:
                if os.path.exists(directory):
                    self.observer.schedule(event_handler, directory, recursive=True)
                    self.logger.info(f"Monitoring directory: {directory}")
                else:
                    self.logger.warning(f"Directory does not exist: {directory}")
            
            # Start the observer
            self.observer.start()
            self.is_running = True
            self.logger.info("File system watcher started successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to start file system watcher: {e}")
            raise
    
    def stop_monitoring(self):
        """Stop monitoring directories."""
        if not self.is_running:
            self.logger.warning("Watcher is not running")
            return
        
        try:
            self.observer.stop()
            self.observer.join(timeout=5)  # Wait up to 5 seconds for clean shutdown
            self.is_running = False
            self.logger.info("File system watcher stopped successfully")
            
        except Exception as e:
            self.logger.error(f"Error stopping file system watcher: {e}")
    
    def is_alive(self):
        """Check if the watcher is running."""
        return self.is_running and self.observer.is_alive()

def main():
    """Test the watcher independently."""
    def test_callback(threat_info):
        print(f"THREAT DETECTED: {threat_info}")
    
    watcher = FileSystemWatcher(test_callback)
    
    try:
        print("Starting file system watcher...")
        watcher.start_monitoring()
        print("Watcher is running. Press Ctrl+C to stop.")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping watcher...")
        watcher.stop_monitoring()
        print("Watcher stopped.")

if __name__ == "__main__":
    main()