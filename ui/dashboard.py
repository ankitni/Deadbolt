# Dashboard data extraction and analysis module for Deadbolt AI

import os
import re
import json
from datetime import datetime, timedelta
import threading
import time

# Add parent directory to path so we can import modules
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import get_log_path, LOG_DIR

class DashboardData:
    """Class to extract and analyze log data for the dashboard"""
    
    def __init__(self):
        self.log_file = get_log_path()
        self.stats = {
            'alerts_high': 0,
            'alerts_medium': 0,
            'alerts_low': 0,
            'events_total': 0,
            'events_by_type': {},
            'alerts_by_time': [0] * 24,  # 24 hours
            'alerts_by_day': [0] * 7,    # 7 days of week
            'recent_alerts': [],          # List of recent alerts
            'monitored_paths_status': {}  # Status of monitored paths
        }
        self.lock = threading.Lock()
    
    def analyze_logs(self, max_lines=1000):
        """Analyze log file to extract dashboard data"""
        if not os.path.exists(self.log_file):
            return self.stats
        
        try:
            with self.lock, open(self.log_file, 'r', encoding='utf-8') as f:
                # Read the last max_lines lines (or less if file is smaller)
                lines = f.readlines()
                if len(lines) > max_lines:
                    lines = lines[-max_lines:]
                
                # Reset stats
                self.stats['alerts_high'] = 0
                self.stats['alerts_medium'] = 0
                self.stats['alerts_low'] = 0
                self.stats['events_total'] = len(lines)
                self.stats['events_by_type'] = {}
                self.stats['alerts_by_time'] = [0] * 24
                self.stats['alerts_by_day'] = [0] * 7
                self.stats['recent_alerts'] = []
                
                # Process each line
                for line in lines:
                    self._process_log_line(line)
                
                return self.stats
        except Exception as e:
            print(f"Error analyzing logs: {str(e)}")
            return self.stats
    
    def _process_log_line(self, line):
        """Process a single log line to extract data"""
        # Parse log line
        match = re.match(r'\[(.*?)\] (\w+): (.*)', line.strip())
        if not match:
            return
        
        timestamp, level, message = match.groups()
        
        # Update event type stats
        if level in self.stats['events_by_type']:
            self.stats['events_by_type'][level] += 1
        else:
            self.stats['events_by_type'][level] = 1
        
        # Check for alerts
        if 'ALERT' in level or '[ALERT' in message:
            alert_match = re.search(r'\[ALERT-(\w+)\] (.*)', message)
            if alert_match:
                severity, alert_msg = alert_match.groups()
                self._process_alert(severity, alert_msg, timestamp)
        
        # Check for monitored paths
        if "Watching" in message:
            path_match = re.search(r"Watching (.+)$", message)
            if path_match:
                path = path_match.group(1)
                self.stats['monitored_paths_status'][path] = "Active"
        
        if "Skipping invalid path" in message:
            path_match = re.search(r"Skipping invalid path: (.+)$", message)
            if path_match:
                path = path_match.group(1)
                self.stats['monitored_paths_status'][path] = "Invalid"
    
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
            dt = datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S")
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