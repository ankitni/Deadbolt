"""
Deadbolt Ransomware Defender - Threat Detector
Advanced behavior-based detection engine that analyzes suspicious activities and coordinates response.
"""

import os
import time
import logging
import threading
import psutil
from datetime import datetime, timedelta
from collections import defaultdict
from win10toast import ToastNotifier
import config

class ThreatDetector:
    """Advanced threat detection engine with behavior analysis."""
    
    def __init__(self, responder_callback):
        self.responder_callback = responder_callback
        self.threat_history = defaultdict(list)
        self.process_suspicion_scores = defaultdict(int)
        self.lock = threading.Lock()
        self.toaster = ToastNotifier()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        handler = logging.FileHandler(os.path.join('logs', 'detector.log'))
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        self.logger.info("Threat Detector initialized")
        
        # Threat scoring weights - FOCUSED ON FILE SYSTEM ONLY
        self.threat_weights = {
            'mass_delete': 10,
            'mass_rename': 8,
            'mass_modification': 12,
            'suspicious_extension': 6,
            'suspicious_filename': 9
            # 'process_behavior': COMPLETELY DISABLED
        }
        
        # Notification cooldown to prevent spam
        self.last_notification_time = 0
        self.notification_cooldown = 30  # 30 seconds between notifications
        
        # Process behavior monitoring
        self.process_monitor_thread = None
        self.monitoring_active = False
        
    def start_monitoring(self):
        """Start the threat detection monitoring."""
        self.monitoring_active = True
        # COMPLETELY DISABLED: Process behavior monitoring to prevent false positives
        # Process monitoring is disabled to focus on file system behavior only
        self.logger.info("Threat detection monitoring started (file system only)")
        
    def stop_monitoring(self):
        """Stop the threat detection monitoring."""
        self.monitoring_active = False
        if self.process_monitor_thread:
            self.process_monitor_thread.join(timeout=5)
        self.logger.info("Threat detection monitoring stopped")
        
    def analyze_threat(self, threat_info):
        """Analyze incoming threat information and determine response level."""
        with self.lock:
            current_time = datetime.now()
            threat_type = threat_info.get('type', 'unknown')
            
            # Log the threat
            self.logger.warning(f"Analyzing threat: {threat_type} - {threat_info.get('description', 'No description')}")
            
            # Add to threat history
            self.threat_history[threat_type].append({
                'time': current_time,
                'info': threat_info
            })
            
            # Clean old threat history (keep last 30 minutes)
            cutoff_time = current_time - timedelta(minutes=30)
            for threat_list in self.threat_history.values():
                self.threat_history[threat_type] = [
                    t for t in threat_list if t['time'] >= cutoff_time
                ]
            
            # Calculate threat score
            threat_score = self._calculate_threat_score(threat_info, current_time)
            
            # Update process suspicion scores
            self._update_process_scores(threat_info, threat_score)
            
            # Determine response level
            response_level = self._determine_response_level(threat_score, threat_type)
            
            # Log analysis results
            self.logger.info(f"Threat analysis complete - Score: {threat_score}, Response: {response_level}")
            
            # Send notification
            self._send_notification(threat_info, threat_score, response_level)
            
            # Trigger response if necessary
            if response_level in ['HIGH', 'CRITICAL']:
                self._trigger_response(threat_info, response_level)
                
    def _calculate_threat_score(self, threat_info, current_time):
        """Calculate comprehensive threat score based on multiple factors."""
        base_score = self.threat_weights.get(threat_info.get('type', 'unknown'), 5)
        
        # Factor in severity
        severity_multiplier = {
            'LOW': 1.0,
            'MEDIUM': 1.5,
            'HIGH': 2.0,
            'CRITICAL': 3.0
        }
        score = base_score * severity_multiplier.get(threat_info.get('severity', 'MEDIUM'), 1.5)
        
        # Factor in recent threat frequency
        threat_type = threat_info.get('type', 'unknown')
        recent_threats = [
            t for t in self.threat_history[threat_type]
            if (current_time - t['time']).total_seconds() < 300  # Last 5 minutes
        ]
        
        if len(recent_threats) > 1:
            score *= (1 + len(recent_threats) * 0.3)  # Escalate for repeated threats
            
        # Factor in process behavior
        process_info = threat_info.get('process_info', [])
        if process_info:
            for pid, process_name in process_info:
                process_score = self.process_suspicion_scores.get(pid, 0)
                if process_score > 10:
                    score *= 1.5  # Escalate if process already suspicious
                    
        # Factor in file count for mass operations
        if 'count' in threat_info:
            count = threat_info['count']
            if count > 20:
                score *= 1.5
            elif count > 50:
                score *= 2.0
                
        return min(score, 100)  # Cap at 100
        
    def _update_process_scores(self, threat_info, threat_score):
        """Update suspicion scores for involved processes."""
        process_info = threat_info.get('process_info', [])
        
        for pid, process_name in process_info:
            # Add to suspicion score
            score_increment = max(1, int(threat_score / 10))
            self.process_suspicion_scores[pid] += score_increment
            
            # Log highly suspicious processes
            if self.process_suspicion_scores[pid] > 15:
                self.logger.critical(f"Highly suspicious process detected: {process_name} (PID: {pid}) - Score: {self.process_suspicion_scores[pid]}")
                
    def _determine_response_level(self, threat_score, threat_type):
        """Determine the appropriate response level based on threat score and type."""
        # Critical threats requiring immediate action
        if (threat_score >= 30 or 
            threat_type in ['mass_modification', 'suspicious_filename'] or
            any(score > 20 for score in self.process_suspicion_scores.values())):
            return 'CRITICAL'
        
        # High threats requiring rapid response
        elif (threat_score >= 20 or 
              threat_type in ['mass_delete', 'mass_rename']):
            return 'HIGH'
        
        # Medium threats requiring monitoring
        elif threat_score >= 10:
            return 'MEDIUM'
        
        # Low level threats for logging
        else:
            return 'LOW'
            
    def _send_notification(self, threat_info, threat_score, response_level):
        """Send Windows notification with cooldown to prevent spam."""
        try:
            current_time = time.time()
            
            # COOLDOWN: Only send notifications if enough time has passed
            if current_time - self.last_notification_time < self.notification_cooldown:
                self.logger.info(f"Notification skipped due to cooldown - Level: {response_level}, Score: {threat_score}")
                return
            
            threat_type = threat_info.get('type', 'Unknown Threat')
            
            # CRITICAL notifications only for active ransomware behavior
            if response_level == 'CRITICAL' and threat_type == 'mass_modification':
                title = "🚨 RANSOMWARE DETECTED & BLOCKED!"
                message = f"Mass file encryption stopped!\n\nFiles protected: {threat_info.get('count', 'Multiple')}\nThreat neutralized automatically."
                duration = 15
                
                # Send notification
                self.toaster.show_toast(
                    title=title,
                    msg=message,
                    duration=duration,
                    threaded=True
                )
                
                self.last_notification_time = current_time
                self.logger.info(f"Notification sent - Level: {response_level}, Score: {threat_score}")
            else:
                # Only log other notifications, don't send them
                self.logger.info(f"Non-critical notification suppressed - Level: {response_level}, Score: {threat_score}")
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
            
    def _trigger_response(self, threat_info, response_level):
        """Trigger response - SMART PROCESS FILTERING."""
        try:
            suspicious_pids = []
            process_info = threat_info.get('process_info', [])
            
            # SMART FILTERING: Only target processes that are actually suspicious
            for pid, process_name in process_info:
                # Skip system processes that should never be killed
                if self._is_system_process(process_name):
                    continue
                    
                # Only target processes with significant suspicion scores
                if self.process_suspicion_scores.get(pid, 0) > 10:
                    suspicious_pids.append(pid)
            
            # Prepare response info
            response_info = {
                'threat_info': threat_info,
                'response_level': response_level,
                'suspicious_pids': suspicious_pids,
                'timestamp': datetime.now().isoformat()
            }
            
            self.logger.critical(f"Triggering {response_level} response - Target PIDs: {suspicious_pids}")
            
            # Only call responder if we have actual targets
            if suspicious_pids:
                self.responder_callback(response_info)
            else:
                self.logger.info("No legitimate targets identified for response")
            
        except Exception as e:
            self.logger.error(f"Failed to trigger response: {e}")
            
    def _is_system_process(self, process_name):
        """Check if a process is a system process that should not be killed."""
        system_processes = {
            'taskmgr.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe', 'lsass.exe',
            'services.exe', 'svchost.exe', 'dwm.exe', 'searchprotocolhost.exe',
            'idleschedule.exe', 'idlescheduleeventaction.exe', 'backgroundtaskhost.exe',
            'searchfilterhost.exe', 'searchindexer.exe', 'qoder.exe', 'code.exe',
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'notepad.exe'
        }
        return process_name.lower() in system_processes
            
    def _monitor_processes(self):
        """DISABLED: Process monitoring completely removed to prevent false positives."""
        # This method is intentionally disabled to focus on file system behavior only
        # and prevent targeting legitimate system processes like Task Manager components
        self.logger.info("Process monitoring disabled - file system detection only")
        return
                
    def _analyze_process_behavior(self, pid, proc_info, history):
        """DISABLED: Process behavior analysis removed to prevent false positives."""
        # This method is intentionally disabled to focus on file system behavior only
        # and prevent false positive detections of legitimate processes
        return
            
    def get_suspicious_processes(self):
        """Get list of currently suspicious processes."""
        suspicious = []
        for pid, score in self.process_suspicion_scores.items():
            if score > 5:
                try:
                    proc = psutil.Process(pid)
                    suspicious.append({
                        'pid': pid,
                        'name': proc.name(),
                        'score': score
                    })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        return sorted(suspicious, key=lambda x: x['score'], reverse=True)
        
    def get_threat_summary(self):
        """Get summary of recent threats."""
        summary = {}
        current_time = datetime.now()
        
        for threat_type, threats in self.threat_history.items():
            recent = [t for t in threats if (current_time - t['time']).total_seconds() < 3600]  # Last hour
            summary[threat_type] = len(recent)
            
        return summary

def main():
    """Test the detector independently."""
    def test_responder_callback(response_info):
        print(f"RESPONSE TRIGGERED: {response_info}")
    
    detector = ThreatDetector(test_responder_callback)
    detector.start_monitoring()
    
    # Simulate some threats
    test_threats = [
        {
            'type': 'mass_delete',
            'severity': 'HIGH',
            'description': 'Test mass deletion',
            'count': 15,
            'process_info': [(1234, 'test.exe')]
        },
        {
            'type': 'suspicious_filename',
            'severity': 'CRITICAL',
            'description': 'Test ransomware note',
            'file_path': 'C:\\test\\DECRYPT_FILES.txt',
            'process_info': [(5678, 'malware.exe')]
        }
    ]
    
    try:
        print("Testing threat detector...")
        for threat in test_threats:
            detector.analyze_threat(threat)
            time.sleep(2)
        
        print("Press Ctrl+C to stop.")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping detector...")
        detector.stop_monitoring()
        print("Detector stopped.")

if __name__ == "__main__":
    main()