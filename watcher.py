"""
Deadbolt Ransomware Defender - File System Watcher
Monitors directories for suspicious file system activities using behavior-based detection.
"""

import os
import time
import threading
import logging
from datetime import datetime, timedelta
from collections import defaultdict, deque
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import psutil
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
        handler = logging.FileHandler(os.path.join('logs', 'watcher.log'))
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        self.logger.info("Ransomware Watcher initialized - monitoring directories")
        
    def _get_process_info(self):
        """Get minimal process information for file system events only."""
        # SIMPLIFIED: Only return empty list to avoid CPU-based process analysis
        # This focuses detection purely on file system behavior patterns
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
        
        with self.lock:
            # Add event to history
            self.event_history[event_type].append({
                'time': current_time,
                'path': file_path,
                'process_info': self._get_process_info()
            })
            
            # Clean old events (keep last 10 minutes)
            cutoff_time = current_time - timedelta(minutes=10)
            for event_list in self.event_history.values():
                while event_list and event_list[0]['time'] < cutoff_time:
                    event_list.popleft()
            
            # Check for suspicious patterns
            self._check_mass_operations(current_time)
            self._check_suspicious_extensions(file_path)
            self._check_suspicious_filenames(file_path)
    
    def _check_mass_operations(self, current_time):
        """Check for mass file operations that could indicate ransomware."""
        time_window = timedelta(seconds=config.RULES['mass_delete']['interval'])
        recent_time = current_time - time_window
        
        # Count recent events
        recent_deletes = sum(1 for event in self.event_history['deleted'] 
                           if event['time'] >= recent_time)
        recent_renames = sum(1 for event in self.event_history['moved'] 
                           if event['time'] >= recent_time)
        recent_modifications = sum(1 for event in self.event_history['modified'] 
                                 if event['time'] >= recent_time)
        
        # Check mass delete pattern
        if recent_deletes >= config.RULES['mass_delete']['count']:
            threat_info = {
                'type': 'mass_delete',
                'count': recent_deletes,
                'time_window': config.RULES['mass_delete']['interval'],
                'process_info': self._get_recent_process_info('deleted', recent_time),
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
                'process_info': self._get_recent_process_info('moved', recent_time),
                'severity': 'HIGH',
                'description': f'Mass file renaming detected: {recent_renames} files renamed in {config.RULES["mass_rename"]["interval"]} seconds'
            }
            self.logger.warning(f"RANSOMWARE ALERT: {threat_info['description']}")
            self.detector_callback(threat_info)
        
        # Check mass modification pattern (potential encryption)
        if recent_modifications >= 10:  # Reduced threshold for testing
            threat_info = {
                'type': 'mass_modification',
                'count': recent_modifications,
                'time_window': config.RULES['mass_rename']['interval'],
                'process_info': self._get_recent_process_info('modified', recent_time),
                'severity': 'CRITICAL',
                'description': f'Mass file modification detected: {recent_modifications} files modified in {config.RULES["mass_rename"]["interval"]} seconds (potential encryption)'
            }
            self.logger.critical(f"RANSOMWARE ALERT: {threat_info['description']}")
            self.detector_callback(threat_info)
    
    def _get_recent_process_info(self, event_type, since_time):
        """Get process information from recent events."""
        processes = set()
        for event in self.event_history[event_type]:
            if event['time'] >= since_time and event['process_info']:
                for proc in event['process_info']:
                    processes.add((proc['pid'], proc['name']))
        return list(processes)
    
    def _check_suspicious_extensions(self, file_path):
        """Check for suspicious file extensions."""
        for ext in config.SUSPICIOUS_PATTERNS['extensions']:
            if file_path.lower().endswith(ext):
                threat_info = {
                    'type': 'suspicious_extension',
                    'file_path': file_path,
                    'extension': ext,
                    'process_info': self._get_process_info(),
                    'severity': 'HIGH',
                    'description': f'File with suspicious extension created: {file_path}'
                }
                self.logger.warning(f"RANSOMWARE ALERT: {threat_info['description']}")
                self.detector_callback(threat_info)
    
    def _check_suspicious_filenames(self, file_path):
        """Check for suspicious filenames."""
        filename = os.path.basename(file_path).upper()
        for pattern in config.SUSPICIOUS_PATTERNS['filenames']:
            if pattern in filename:
                threat_info = {
                    'type': 'suspicious_filename',
                    'file_path': file_path,
                    'pattern': pattern,
                    'process_info': self._get_process_info(),
                    'severity': 'CRITICAL',
                    'description': f'Suspicious filename detected: {file_path} (contains: {pattern})'
                }
                self.logger.critical(f"RANSOMWARE ALERT: {threat_info['description']}")
                self.detector_callback(threat_info)
    
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