"""
Deadbolt Ransomware Defender - Response Handler
Handles process termination and coordinates with DeadboltKiller.cpp for advanced threat response.
"""

import os
import sys
import time
import logging
import subprocess
import threading
import psutil
from datetime import datetime
import ctypes
from ctypes import wintypes
import config

class ThreatResponder:
    """Advanced threat response system with multiple termination methods."""
    
    def __init__(self):
        self.response_history = []
        self.lock = threading.Lock()
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        handler = logging.FileHandler(os.path.join('logs', 'responder.log'))
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        self.logger.info("Threat Responder initialized")
        
        # Ensure we have admin privileges for process termination
        self.has_admin_privileges = self._check_admin_privileges()
        if not self.has_admin_privileges:
            self.logger.warning("Running without administrator privileges - some process termination may fail")
        
        # Path to C++ killer
        self.cpp_killer_path = os.path.join(os.getcwd(), "DeadboltKiller.exe")
        self._ensure_cpp_killer()
        
    def _check_admin_privileges(self):
        """Check if running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    
    def _ensure_cpp_killer(self):
        """Ensure the C++ killer is compiled and available."""
        cpp_source = "DeadboltKiller.cpp"
        
        if not os.path.exists(self.cpp_killer_path):
            if os.path.exists(cpp_source):
                self.logger.info("Compiling DeadboltKiller.cpp...")
                try:
                    # Try to compile with g++
                    result = subprocess.run([
                        "g++", "-o", "DeadboltKiller.exe", cpp_source, 
                        "-lpsapi", "-static-libgcc", "-static-libstdc++"
                    ], capture_output=True, text=True, timeout=30)
                    
                    if result.returncode == 0:
                        self.logger.info("Successfully compiled DeadboltKiller.exe")
                    else:
                        self.logger.error(f"Failed to compile DeadboltKiller.cpp: {result.stderr}")
                        
                except subprocess.TimeoutExpired:
                    self.logger.error("Compilation timed out")
                except FileNotFoundError:
                    self.logger.warning("g++ not found - C++ killer will not be available")
                except Exception as e:
                    self.logger.error(f"Error compiling C++ killer: {e}")
            else:
                self.logger.warning("DeadboltKiller.cpp not found")
    
    def respond_to_threat(self, response_info):
        """Main response handler that coordinates threat response."""
        with self.lock:
            current_time = datetime.now()
            threat_info = response_info.get('threat_info', {})
            response_level = response_info.get('response_level', 'LOW')
            suspicious_pids = response_info.get('suspicious_pids', [])
            
            self.logger.critical(f"THREAT RESPONSE INITIATED - Level: {response_level}")
            self.logger.critical(f"Threat Type: {threat_info.get('type', 'Unknown')}")
            self.logger.critical(f"Description: {threat_info.get('description', 'No description')}")
            self.logger.critical(f"Target PIDs: {suspicious_pids}")
            
            # Record response
            response_record = {
                'timestamp': current_time,
                'threat_info': threat_info,
                'response_level': response_level,
                'target_pids': suspicious_pids,
                'actions_taken': []
            }
            
            # Execute response based on level and configuration
            if config.ACTIONS.get('dry_run', False):
                self.logger.info("DRY RUN MODE - No actual process termination")
                response_record['actions_taken'].append('dry_run_mode')
            else:
                self._execute_response(response_record, response_level, suspicious_pids)
            
            # Add to history
            self.response_history.append(response_record)
            
            # Keep only last 100 responses
            if len(self.response_history) > 100:
                self.response_history.pop(0)
    
    def _execute_response(self, response_record, response_level, suspicious_pids):
        """Execute the actual threat response."""
        actions_taken = response_record['actions_taken']
        
        # Step 1: Try Python-based termination first
        if config.ACTIONS.get('kill_process', True):
            terminated_pids = self._terminate_processes_python(suspicious_pids)
            if terminated_pids:
                actions_taken.append(f'python_kill_{len(terminated_pids)}_processes')
                self.logger.info(f"Python termination successful for {len(terminated_pids)} processes")
            
            # Step 2: For critical threats or if Python termination failed, use C++ killer
            remaining_pids = [pid for pid in suspicious_pids if self._is_process_running(pid)]
            
            if (response_level == 'CRITICAL' or remaining_pids) and os.path.exists(self.cpp_killer_path):
                self._invoke_cpp_killer(remaining_pids, response_record)
                actions_taken.append('cpp_killer_invoked')
            
            # Step 3: Emergency measures for critical threats
            if response_level == 'CRITICAL':
                self._emergency_response(response_record)
        
        # Step 4: Additional protective measures
        if response_level in ['HIGH', 'CRITICAL']:
            self._implement_protective_measures(response_record)
        
        # Log final status
        final_remaining = [pid for pid in suspicious_pids if self._is_process_running(pid)]
        if final_remaining:
            self.logger.error(f"Failed to terminate {len(final_remaining)} processes: {final_remaining}")
        else:
            self.logger.info("All suspicious processes successfully terminated")
    
    def _terminate_processes_python(self, pids):
        """Attempt to terminate processes using Python/psutil."""
        terminated = []
        
        for pid in pids:
            try:
                if not self._is_process_running(pid):
                    continue
                
                proc = psutil.Process(pid)
                process_name = proc.name()
                
                self.logger.info(f"Attempting Python termination of {process_name} (PID: {pid})")
                
                # Try graceful termination first
                proc.terminate()
                
                # Wait up to 3 seconds for graceful termination
                try:
                    proc.wait(timeout=3)
                    terminated.append(pid)
                    self.logger.info(f"Successfully terminated {process_name} (PID: {pid}) gracefully")
                    continue
                except psutil.TimeoutExpired:
                    pass
                
                # Force kill if still running
                if proc.is_running():
                    proc.kill()
                    # Wait up to 2 seconds for force kill
                    try:
                        proc.wait(timeout=2)
                        terminated.append(pid)
                        self.logger.info(f"Successfully force-killed {process_name} (PID: {pid})")
                    except psutil.TimeoutExpired:
                        self.logger.error(f"Failed to kill {process_name} (PID: {pid}) - process resistant")
                
            except psutil.NoSuchProcess:
                # Process already terminated
                terminated.append(pid)
                self.logger.info(f"Process {pid} already terminated")
            except psutil.AccessDenied:
                self.logger.error(f"Access denied when trying to terminate PID {pid}")
            except Exception as e:
                self.logger.error(f"Error terminating process {pid}: {e}")
        
        return terminated
    
    def _invoke_cpp_killer(self, pids, response_record):
        """Invoke the C++ DeadboltKiller for advanced process termination."""
        if not pids:
            return
        
        try:
            current_pid = os.getpid()
            current_time = datetime.now().isoformat()
            suspicious_pids_str = ",".join(map(str, pids))
            
            cmd = [
                self.cpp_killer_path,
                "--pid", str(current_pid),
                "--time", current_time,
                "--suspicious", suspicious_pids_str
            ]
            
            self.logger.critical(f"Invoking C++ killer with command: {' '.join(cmd)}")
            
            # Run the C++ killer
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
            )
            
            if result.returncode == 0:
                self.logger.info("C++ killer executed successfully")
                response_record['actions_taken'].append('cpp_killer_success')
            else:
                self.logger.error(f"C++ killer failed with return code {result.returncode}")
                self.logger.error(f"Stderr: {result.stderr}")
                response_record['actions_taken'].append('cpp_killer_failed')
            
            if result.stdout:
                self.logger.info(f"C++ killer output: {result.stdout}")
            
        except subprocess.TimeoutExpired:
            self.logger.error("C++ killer timed out")
            response_record['actions_taken'].append('cpp_killer_timeout')
        except Exception as e:
            self.logger.error(f"Error invoking C++ killer: {e}")
            response_record['actions_taken'].append('cpp_killer_error')
    
    def _emergency_response(self, response_record):
        """Execute emergency response measures for critical threats - IMPROVED FILTERING."""
        self.logger.critical("EXECUTING EMERGENCY RESPONSE MEASURES")
        
        try:
            # Focus on actual suspicious processes, not system processes
            emergency_targets = []
            current_time = time.time()
            
            # Safe system processes that should never be killed
            protected_processes = {
                'taskmgr.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe', 'lsass.exe',
                'services.exe', 'svchost.exe', 'dwm.exe', 'searchprotocolhost.exe',
                'idleschedule.exe', 'idlescheduleeventaction.exe', 'backgroundtaskhost.exe',
                'searchfilterhost.exe', 'searchindexer.exe', 'qoder.exe', 'code.exe',
                'chrome.exe', 'firefox.exe', 'msedge.exe', 'notepad.exe', 'python.exe'
            }
            
            for proc in psutil.process_iter(['pid', 'name', 'create_time', 'cpu_percent']):
                try:
                    proc_info = proc.info
                    pid = proc_info['pid']
                    process_name = proc_info.get('name', '').lower()
                    
                    # Skip system processes and our own
                    if (pid < 1000 or 
                        pid == os.getpid() or 
                        process_name in protected_processes):
                        continue
                    
                    # Only target suspicious processes (newer, unknown executables with odd behavior)
                    process_age = current_time - proc_info.get('create_time', current_time)
                    cpu_percent = proc_info.get('cpu_percent', 0)
                    
                    # Target: Recent processes (last 2 minutes) with suspicious names/behavior
                    if (process_age < 120 and  # Last 2 minutes only
                        cpu_percent > 50 and  # High CPU usage
                        ('.exe' in process_name and 
                         process_name not in protected_processes)):
                        emergency_targets.append(pid)
                        
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            if emergency_targets:
                self.logger.critical(f"Emergency termination targets: {emergency_targets}")
                terminated = self._terminate_processes_python(emergency_targets)
                response_record['actions_taken'].append(f'emergency_kill_{len(terminated)}_processes')
            else:
                self.logger.info("No emergency targets identified - system protected")
            
        except Exception as e:
            self.logger.error(f"Error in emergency response: {e}")
    
    def _implement_protective_measures(self, response_record):
        """Implement additional protective measures."""
        try:
            # Log system state
            self.logger.info("Implementing protective measures")
            
            # Record system information
            system_info = {
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'disk_usage': {disk.device: psutil.disk_usage(disk.mountpoint).percent 
                              for disk in psutil.disk_partitions() if disk.fstype},
                'process_count': len(psutil.pids())
            }
            
            response_record['system_state'] = system_info
            response_record['actions_taken'].append('system_state_recorded')
            
            # Could add more protective measures here:
            # - Backup critical files
            # - Network isolation
            # - User notification enhancement
            
        except Exception as e:
            self.logger.error(f"Error implementing protective measures: {e}")
    
    def _is_process_running(self, pid):
        """Check if a process is still running."""
        try:
            proc = psutil.Process(pid)
            return proc.is_running()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return False
    
    def get_response_history(self, limit=10):
        """Get recent response history."""
        return self.response_history[-limit:] if self.response_history else []
    
    def get_response_stats(self):
        """Get response statistics."""
        if not self.response_history:
            return {}
        
        total_responses = len(self.response_history)
        recent_responses = [r for r in self.response_history 
                          if (datetime.now() - r['timestamp']).total_seconds() < 3600]
        
        level_counts = {}
        for response in self.response_history:
            level = response.get('response_level', 'UNKNOWN')
            level_counts[level] = level_counts.get(level, 0) + 1
        
        return {
            'total_responses': total_responses,
            'recent_responses_1h': len(recent_responses),
            'response_levels': level_counts,
            'last_response': self.response_history[-1]['timestamp'] if self.response_history else None
        }

def main():
    """Test the responder independently."""
    responder = ThreatResponder()
    
    # Test response
    test_response_info = {
        'threat_info': {
            'type': 'test_threat',
            'description': 'Test threat for responder',
            'severity': 'HIGH'
        },
        'response_level': 'HIGH',
        'suspicious_pids': [],  # Empty for testing
        'timestamp': datetime.now().isoformat()
    }
    
    print("Testing threat responder...")
    responder.respond_to_threat(test_response_info)
    
    print("Response history:")
    for response in responder.get_response_history():
        print(f"  {response['timestamp']}: {response['response_level']} - {response['actions_taken']}")
    
    print("Response stats:")
    stats = responder.get_response_stats()
    for key, value in stats.items():
        print(f"  {key}: {value}")

if __name__ == "__main__":
    main()