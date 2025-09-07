# Dashboard data extraction and analysis module for Deadbolt AI

import os
import re
import json
from datetime import datetime, timedelta
import threading
import time

# Add parent directory to path so we can import modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import utils with fallback handling
try:
    from ..utils.logger import get_log_path, LOG_DIR
except ImportError:
    try:
        from utils.logger import get_log_path, LOG_DIR
    except ImportError:
        # Fallback if logger not available
        def get_log_path():
            return os.path.join(os.getcwd(), 'logs', 'deadbolt.log')
        LOG_DIR = os.path.join(os.getcwd(), 'logs')

class DashboardData:
    """Class to extract and analyze log data for the dashboard"""
    
    def __init__(self):
        self.log_files = {
            'main': os.path.join(LOG_DIR, 'main.log'),
            'detector': os.path.join(LOG_DIR, 'detector.log'),
            'responder': os.path.join(LOG_DIR, 'responder.log'),
            'watcher': os.path.join(LOG_DIR, 'watcher.log'),
            'ml_detector': os.path.join(LOG_DIR, 'ml_detector.log'),  # Add ML detector log
            'deadbolt': get_log_path()  # Main deadbolt log
        }
        self.stats = {
            'alerts_high': 0,
            'alerts_medium': 0, 
            'alerts_low': 0,
            'events_total': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'processes_terminated': 0,
            'events_by_type': {},
            'alerts_by_time': [0] * 24,  # 24 hours
            'alerts_by_day': [0] * 7,    # 7 days of week
            'recent_alerts': [],          # List of recent alerts
            'recent_threats': [],         # List of recent threats
            'monitored_paths_status': {},  # Status of monitored paths
            'response_history': [],       # Response actions taken
            'system_health': {
                'detector_active': False,
                'responder_active': False,
                'watcher_active': False,
                'ml_active': False,
                'ml_monitoring': False
            }
        }
        self.lock = threading.Lock()
    
    def analyze_logs(self, max_lines=1000):
        """Analyze all log files to extract comprehensive dashboard data"""
        try:
            with self.lock:
                # Reset stats
                self._reset_stats()
                
                # Analyze each log file
                for log_name, log_path in self.log_files.items():
                    if os.path.exists(log_path):
                        self._analyze_single_log(log_name, log_path, max_lines)
                
                # Sort recent items by timestamp
                self.stats['recent_alerts'].sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                self.stats['recent_threats'].sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                self.stats['response_history'].sort(key=lambda x: x.get('timestamp', ''), reverse=True)
                
                # Keep only most recent items
                self.stats['recent_alerts'] = self.stats['recent_alerts'][:50]
                self.stats['recent_threats'] = self.stats['recent_threats'][:50]
                self.stats['response_history'] = self.stats['response_history'][:50]
                
                return self.stats
        except Exception as e:
            print(f"Error analyzing logs: {str(e)}")
            return self.stats
    
    def _reset_stats(self):
        """Reset statistics to default values"""
        self.stats.update({
            'alerts_high': 0,
            'alerts_medium': 0,
            'alerts_low': 0,
            'events_total': 0,
            'threats_detected': 0,
            'threats_blocked': 0,
            'processes_terminated': 0,
            'events_by_type': {},
            'alerts_by_time': [0] * 24,
            'alerts_by_day': [0] * 7,
            'recent_alerts': [],
            'recent_threats': [],
            'monitored_paths_status': {},
            'response_history': [],
            'system_health': {
                'detector_active': False,
                'responder_active': False,
                'watcher_active': False,
                'ml_active': False,
                'ml_monitoring': False
            }
        })
    
    def _analyze_single_log(self, log_name, log_path, max_lines):
        """Analyze a single log file"""
        try:
            with open(log_path, 'r', encoding='utf-8') as f:
                # Read the last max_lines lines (or less if file is smaller)
                lines = f.readlines()
                if len(lines) > max_lines:
                    lines = lines[-max_lines:]
                
                # Update total events count
                self.stats['events_total'] += len(lines)
                
                # Process each line based on log type
                for line in lines:
                    self._process_log_line(line.strip(), log_name)
                    
        except Exception as e:
            print(f"Error analyzing {log_name} log: {str(e)}")
    
    def _process_log_line(self, line, log_name):
        """Process a single log line to extract data based on log type"""
        if not line.strip():
            return
            
        # Try different log formats
        timestamp_str = None
        level = None
        message = None
        
        # Format 1: [timestamp] LEVEL: message (logger.py format)
        match1 = re.match(r'\[(.*?)\] (\w+): (.*)', line)
        if match1:
            timestamp_str, level, message = match1.groups()
        else:
            # Format 2: timestamp - component - LEVEL - message (main.py format)
            match2 = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - ([^-]+) - (\w+) - (.*)', line)
            if match2:
                timestamp_str, component, level, message = match2.groups()
            else:
                # Format 3: timestamp - LEVEL - message (simple format)
                match3 = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - (\w+) - (.*)', line)
                if match3:
                    timestamp_str, level, message = match3.groups()
                else:
                    # Format 4: timestamp - LEVEL - message (without milliseconds)
                    match4 = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) - (\w+) - (.*)', line)
                    if match4:
                        timestamp_str, level, message = match4.groups()
                    else:
                        return  # Skip lines that don't match any format
        
        # Update event type stats
        if level in self.stats['events_by_type']:
            self.stats['events_by_type'][level] += 1
        else:
            self.stats['events_by_type'][level] = 1
        
        # Process based on log type and content
        self._analyze_log_content(line, log_name, level, message, timestamp_str)
    
    def _analyze_log_content(self, line, log_name, level, message, timestamp_str):
        """Analyze specific log content based on log type"""
        try:
            # Check for alerts
            if 'ALERT' in level or '[ALERT' in message:
                alert_match = re.search(r'\[ALERT-(\w+)\] (.*)', message)
                if alert_match:
                    severity, alert_msg = alert_match.groups()
                    self._process_alert(severity, alert_msg, timestamp_str)
            
            # Check for MULTI-CHANNEL ALERT entries
            if 'MULTI-CHANNEL ALERT SENT' in message:
                # Extract severity and score from the message
                severity_match = re.search(r'Level: (\w+)', message)
                severity = severity_match.group(1) if severity_match else "HIGH"
                self._process_alert(severity, message, timestamp_str)
            
            # Check for threat analysis entries as well
            if 'Analyzing threat:' in message:
                # Treat threat analysis as a MEDIUM severity alert for dashboard purposes
                threat_match = re.search(r'Analyzing threat: (\w+)', message)
                threat_type = threat_match.group(1) if threat_match else "UNKNOWN"
                self._process_alert("MEDIUM", f"Threat detected: {threat_type}", timestamp_str)
            
            # Detector log analysis
            if log_name == 'detector':
                self._analyze_detector_log(level, message, timestamp_str)
            
            # Responder log analysis
            elif log_name == 'responder':
                self._analyze_responder_log(level, message, timestamp_str)
            
            # Watcher log analysis
            elif log_name == 'watcher':
                self._analyze_watcher_log(level, message, timestamp_str)
            
            # ML detector log analysis
            elif log_name == 'ml_detector':
                self._analyze_ml_detector_log(level, message, timestamp_str)
            
            # Main log analysis
            elif log_name in ['main', 'deadbolt']:
                self._analyze_main_log(level, message, timestamp_str)
            
            # System health indicators
            self._update_system_health(log_name, level, message)
            
        except Exception as e:
            print(f"Error analyzing log content: {str(e)}")
    
    def _analyze_detector_log(self, level, message, timestamp_str):
        """Analyze detector-specific log entries"""
        # Threat detection
        if 'Analyzing threat:' in message:
            threat_match = re.search(r'Analyzing threat: (\w+) - (.*)', message)
            if threat_match:
                threat_type, description = threat_match.groups()
                self.stats['threats_detected'] += 1
                self.stats['recent_threats'].append({
                    'timestamp': timestamp_str,
                    'type': threat_type,
                    'description': description,
                    'severity': level
                })
        
        # Critical responses
        if 'Triggering CRITICAL response' in message:
            self.stats['threats_blocked'] += 1
        
        # Process identification
        if 'Target PIDs:' in message:
            pids_match = re.search(r'Target PIDs: \[(.*?)\]', message)
            if pids_match:
                pids_str = pids_match.group(1)
                if pids_str.strip():  # Non-empty PIDs
                    pid_count = len([p.strip() for p in pids_str.split(',') if p.strip()])
                    self.stats['processes_terminated'] += pid_count
    
    def _analyze_responder_log(self, level, message, timestamp_str):
        """Analyze responder-specific log entries"""
        # Process termination
        if 'Successfully terminated' in message:
            self.stats['processes_terminated'] += 1
            
        # Response actions
        if 'THREAT RESPONSE INITIATED' in message:
            self.stats['response_history'].append({
                'timestamp': timestamp_str,
                'action': 'Response Initiated',
                'details': message,
                'severity': level
            })
        
        # C++ killer activation
        if 'Invoking C++ killer' in message:
            self.stats['response_history'].append({
                'timestamp': timestamp_str,
                'action': 'C++ Killer Activated',
                'details': message,
                'severity': 'CRITICAL'
            })
        
        # Emergency response
        if 'EMERGENCY RESPONSE' in message:
            self.stats['response_history'].append({
                'timestamp': timestamp_str,
                'action': 'Emergency Response',
                'details': message,
                'severity': 'CRITICAL'
            })
    
    def _analyze_watcher_log(self, level, message, timestamp_str):
        """Analyze watcher-specific log entries"""
        # Monitored paths
        if "Watching" in message or "Monitoring directory" in message:
            path_match = re.search(r'(?:Watching|Monitoring directory): (.+)$', message)
            if path_match:
                path = path_match.group(1)
                self.stats['monitored_paths_status'][path] = "Active"
        
        if "Skipping invalid path" in message:
            path_match = re.search(r"Skipping invalid path: (.+)$", message)
            if path_match:
                path = path_match.group(1)
                self.stats['monitored_paths_status'][path] = "Invalid"
        
        # File system events
        if "RANSOMWARE ALERT" in message:
            self.stats['threats_detected'] += 1
    
    def _analyze_ml_detector_log(self, level, message, timestamp_str):
        """Analyze ML detector-specific log entries"""
        # ML threat detection
        if 'ML HIGH THREAT DETECTED' in message:
            self.stats['threats_detected'] += 1
            self.stats['recent_threats'].append({
                'timestamp': timestamp_str,
                'type': 'ML_HIGH_THREAT',
                'description': 'ML detected high-confidence threat',
                'severity': 'CRITICAL'
            })
        
        if 'ML Model detected malicious behavior' in message:
            self.stats['threats_detected'] += 1
            # Extract confidence if available
            conf_match = re.search(r'Confidence: ([0-9.]+)', message)
            confidence = conf_match.group(1) if conf_match else 'Unknown'
            self.stats['recent_threats'].append({
                'timestamp': timestamp_str,
                'type': 'ML_MALICIOUS',
                'description': f'ML detected malicious behavior (Confidence: {confidence})',
                'severity': 'CRITICAL'
            })
        
        if 'IRC PATTERN DETECTED' in message:
            self.stats['threats_detected'] += 1
            self.stats['recent_threats'].append({
                'timestamp': timestamp_str,
                'type': 'IRC_PATTERN',
                'description': 'IRC communication pattern detected',
                'severity': 'WARNING'
            })
        
        if 'ML-ENHANCED ALERT SENT' in message:
            self.stats['threats_blocked'] += 1
            self.stats['response_history'].append({
                'timestamp': timestamp_str,
                'action': 'ML-Enhanced Alert Sent',
                'details': message,
                'severity': 'CRITICAL'
            })
        
        if 'Triggering ML-enhanced' in message:
            self.stats['response_history'].append({
                'timestamp': timestamp_str,
                'action': 'ML-Enhanced Response Triggered',
                'details': message,
                'severity': 'CRITICAL'
            })
        
        # ML system status
        if 'ML model loaded successfully' in message:
            self.stats['system_health']['ml_active'] = True
        
        if 'ML-Enhanced threat detection monitoring started' in message:
            self.stats['system_health']['ml_monitoring'] = True
        
        if 'ML-Enhanced threat detection monitoring stopped' in message:
            self.stats['system_health']['ml_monitoring'] = False
    
    def _analyze_main_log(self, level, message, timestamp_str):
        """Analyze main log entries"""
        # System startup/shutdown
        if "Deadbolt Defender started" in message:
            self.stats['system_health']['detector_active'] = True
            self.stats['system_health']['responder_active'] = True
            self.stats['system_health']['watcher_active'] = True
        
        if "monitoring stopped" in message or "Shutdown complete" in message:
            self.stats['system_health']['detector_active'] = False
            self.stats['system_health']['responder_active'] = False
            self.stats['system_health']['watcher_active'] = False
    
    def _update_system_health(self, log_name, level, message):
        """Update system health indicators"""
        current_time = datetime.now()
        
        # Component activity indicators
        if log_name == 'detector' and level in ['INFO', 'WARNING', 'CRITICAL']:
            self.stats['system_health']['detector_active'] = True
            
        if log_name == 'responder' and level in ['INFO', 'WARNING', 'CRITICAL']:
            self.stats['system_health']['responder_active'] = True
            
        if log_name == 'watcher' and level in ['INFO', 'WARNING', 'CRITICAL']:
            self.stats['system_health']['watcher_active'] = True
    
    def _process_alert(self, severity, message, timestamp):
        """Process an alert entry"""
        # Update alert counts
        if severity == "HIGH":
            self.stats['alerts_high'] += 1
        elif severity == "MEDIUM":
            self.stats['alerts_medium'] += 1
        elif severity == "LOW":
            self.stats['alerts_low'] += 1
        
        # Update alerts by time
        try:
            # Try different timestamp formats
            dt = None
            formats_to_try = [
                "%Y-%m-%d %H:%M:%S",  # Format like "2025-08-30 03:50:29"
                "%Y-%m-%d %H:%M:%S,%f"  # Format like "2025-08-30 03:50:29,566"
            ]
            
            for fmt in formats_to_try:
                try:
                    dt = datetime.strptime(timestamp, fmt)
                    break
                except ValueError:
                    continue
            
            if dt is None:
                # If we can't parse the timestamp, skip this alert for hourly stats
                return
            
            hour = dt.hour
            day = dt.weekday()  # 0 = Monday, 6 = Sunday
            
            self.stats['alerts_by_time'][hour] += 1
            self.stats['alerts_by_day'][day] += 1
            
            # Add to recent alerts (keep most recent 100)
            self.stats['recent_alerts'].append({
                'timestamp': timestamp,
                'severity': severity,
                'message': message
            })
            
            # Keep only the most recent 100 alerts
            if len(self.stats['recent_alerts']) > 100:
                self.stats['recent_alerts'] = self.stats['recent_alerts'][-100:]
        except Exception as e:
            print(f"Error processing alert timestamp: {str(e)}")
    
    def get_stats(self):
        """Get the current statistics"""
        with self.lock:
            return self.stats.copy()
    
    def get_recent_alerts(self, count=10):
        """Get the most recent alerts"""
        with self.lock:
            return self.stats['recent_alerts'][-count:]
    
    def get_alerts_by_time(self):
        """Get alerts by hour of day"""
        with self.lock:
            return self.stats['alerts_by_time']
    
    def get_alerts_by_day(self):
        """Get alerts by day of week"""
        with self.lock:
            return self.stats['alerts_by_day']
    
    def get_events_by_type(self):
        """Get event counts by type"""
        with self.lock:
            return self.stats['events_by_type']

# Background thread for continuous log monitoring
class DashboardMonitor(threading.Thread):
    """Background thread to continuously monitor logs for dashboard updates"""
    
    def __init__(self, update_interval=30):
        """Initialize the monitor thread
        
        Args:
            update_interval: How often to update stats in seconds
        """
        super().__init__(daemon=True)
        self.dashboard = DashboardData()
        self.update_interval = update_interval
        self.running = True
        self.callbacks = []
    
    def run(self):
        """Run the monitoring thread"""
        while self.running:
            # Update dashboard data
            self.dashboard.analyze_logs()
            
            # Call any registered callbacks with the updated data
            stats = self.dashboard.get_stats()
            for callback in self.callbacks:
                try:
                    callback(stats)
                except Exception as e:
                    print(f"Error in dashboard callback: {str(e)}")
            
            # Sleep until next update
            time.sleep(self.update_interval)
    
    def stop(self):
        """Stop the monitoring thread"""
        self.running = False
    
    def register_callback(self, callback):
        """Register a callback function to be called when stats are updated
        
        The callback will receive the stats dictionary as its argument
        """
        if callback not in self.callbacks:
            self.callbacks.append(callback)
    
    def unregister_callback(self, callback):
        """Unregister a previously registered callback"""
        if callback in self.callbacks:
            self.callbacks.remove(callback)
    
    def get_current_stats(self):
        """Get the current statistics"""
        return self.dashboard.get_stats()

# Helper functions for dashboard data
def get_dashboard_data():
    """Get a snapshot of dashboard data"""
    dashboard = DashboardData()
    return dashboard.analyze_logs()

def start_dashboard_monitor(callback=None, update_interval=30):
    """Start a background dashboard monitor thread
    
    Args:
        callback: Optional function to call when stats are updated
        update_interval: How often to update stats in seconds
        
    Returns:
        The monitor thread object
    """
    monitor = DashboardMonitor(update_interval)
    if callback:
        monitor.register_callback(callback)
    monitor.start()
    return monitor

# For testing
if __name__ == "__main__":
    def print_stats(stats):
        print(f"High alerts: {stats['alerts_high']}")
        print(f"Medium alerts: {stats['alerts_medium']}")
        print(f"Low alerts: {stats['alerts_low']}")
        print(f"Total events: {stats['events_total']}")
        print(f"Event types: {stats['events_by_type']}")
        print("Recent alerts:")
        for alert in stats['recent_alerts'][-5:]:
            print(f"  [{alert['timestamp']}] {alert['severity']}: {alert['message']}")
    
    # Test the dashboard data
    print("Initial dashboard data:")
    data = get_dashboard_data()
    print_stats(data)
    
    # Test the monitor
    print("\nStarting monitor...")
    monitor = start_dashboard_monitor(print_stats, 5)
    
    # Run for a while
    try:
        time.sleep(30)
    except KeyboardInterrupt:
        pass
    
    # Stop the monitor
    monitor.stop()
    print("\nMonitor stopped")