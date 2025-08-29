"""
Deadbolt Ransomware Defender - Main Orchestrator
Coordinates the watcher, detector, and responder components for comprehensive ransomware protection.
"""

import os
import sys
import time
import signal
import logging
import threading
import argparse
from datetime import datetime
import json

# Import our components
from watcher import FileSystemWatcher
from detector import ThreatDetector
from responder import ThreatResponder
import config

class DeadboltDefender:
    """Main class that orchestrates all ransomware defense components."""
    
    def __init__(self, debug_mode=False):
        self.debug_mode = debug_mode
        self.is_running = False
        self.shutdown_event = threading.Event()
        
        # Initialize logging
        self._setup_logging()
        
        # Initialize components
        self.responder = None
        self.detector = None
        self.watcher = None
        
        # Status tracking
        self.start_time = None
        self.stats = {
            'threats_detected': 0,
            'responses_triggered': 0,
            'files_monitored': 0,
            'uptime_seconds': 0
        }
        
        self.logger.info("Deadbolt Defender initialized")
        
    def _setup_logging(self):
        """Setup comprehensive logging system."""
        # Create logs directory if it doesn't exist
        os.makedirs('logs', exist_ok=True)
        
        # Main logger
        self.logger = logging.getLogger('deadbolt_main')
        self.logger.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(os.path.join('logs', 'main.log'))
        file_formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler for interactive mode
        if self.debug_mode:
            console_handler = logging.StreamHandler()
            console_formatter = logging.Formatter(
                '%(asctime)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        self.logger.info("Logging system initialized")
        
    def _detector_callback(self, threat_info):
        """Callback function for when the detector identifies a threat."""
        self.stats['threats_detected'] += 1
        self.logger.warning(f"Threat detected: {threat_info.get('type', 'Unknown')} - {threat_info.get('description', 'No description')}")
        
        # Log threat details
        threat_log = {
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat_info.get('type', 'Unknown'),
            'severity': threat_info.get('severity', 'Medium'),
            'description': threat_info.get('description', ''),
            'process_info': threat_info.get('process_info', [])
        }
        
        with open(os.path.join('logs', 'threats.json'), 'a') as f:
            f.write(json.dumps(threat_log) + '\n')
    
    def _responder_callback(self, response_info):
        """Callback function for when a response is triggered."""
        self.stats['responses_triggered'] += 1
        self.logger.critical(f"Response triggered: {response_info.get('response_level', 'Unknown')} level")
        
        # Log response details
        response_log = {
            'timestamp': datetime.now().isoformat(),
            'response_level': response_info.get('response_level', 'Unknown'),
            'threat_type': response_info.get('threat_info', {}).get('type', 'Unknown'),
            'target_pids': response_info.get('suspicious_pids', [])
        }
        
        with open(os.path.join('logs', 'responses.json'), 'a') as f:
            f.write(json.dumps(response_log) + '\n')
    
    def start(self):
        """Start the Deadbolt Defender system."""
        if self.is_running:
            self.logger.warning("Deadbolt Defender is already running")
            return False
        
        try:
            self.logger.info("Starting Deadbolt Ransomware Defender...")
            self.start_time = datetime.now()
            
            # Initialize components in order
            self.logger.info("Initializing responder...")
            self.responder = ThreatResponder()
            
            self.logger.info("Initializing detector...")
            self.detector = ThreatDetector(self.responder.respond_to_threat)
            
            self.logger.info("Initializing filesystem watcher...")
            self.watcher = FileSystemWatcher(self.detector.analyze_threat)
            
            # Start components
            self.logger.info("Starting detector monitoring...")
            self.detector.start_monitoring()
            
            self.logger.info("Starting filesystem monitoring...")
            self.watcher.start_monitoring()
            
            # Start status monitoring thread
            status_thread = threading.Thread(target=self._status_monitor, daemon=True)
            status_thread.start()
            
            self.is_running = True
            self.logger.info("Deadbolt Defender started successfully")
            
            # Log startup configuration
            self.logger.info(f"Monitoring directories: {config.TARGET_DIRS}")
            self.logger.info(f"Rules: {config.RULES}")
            self.logger.info(f"Actions enabled: {config.ACTIONS}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start Deadbolt Defender: {e}")
            self.stop()
            return False
    
    def stop(self):
        """Stop the Deadbolt Defender system."""
        if not self.is_running:
            self.logger.warning("Deadbolt Defender is not running")
            return
        
        self.logger.info("Stopping Deadbolt Defender...")
        self.shutdown_event.set()
        
        try:
            # Stop components in reverse order
            if self.watcher:
                self.logger.info("Stopping filesystem watcher...")
                self.watcher.stop_monitoring()
            
            if self.detector:
                self.logger.info("Stopping detector...")
                self.detector.stop_monitoring()
            
            self.is_running = False
            
            # Log final statistics
            if self.start_time:
                uptime = (datetime.now() - self.start_time).total_seconds()
                self.stats['uptime_seconds'] = uptime
                self.logger.info(f"Shutdown complete. Uptime: {uptime:.1f} seconds")
                self.logger.info(f"Final stats: {self.stats}")
            
        except Exception as e:
            self.logger.error(f"Error during shutdown: {e}")
    
    def _status_monitor(self):
        """Background thread that monitors system status."""
        self.logger.info("Status monitoring started")
        
        while not self.shutdown_event.is_set():
            try:
                # Update uptime
                if self.start_time:
                    self.stats['uptime_seconds'] = (datetime.now() - self.start_time).total_seconds()
                
                # Check component health
                watcher_healthy = self.watcher and self.watcher.is_alive()
                detector_healthy = self.detector is not None
                responder_healthy = self.responder is not None
                
                if not watcher_healthy:
                    self.logger.error("Filesystem watcher is not healthy")
                
                # Log periodic status (every 10 minutes)
                if int(self.stats['uptime_seconds']) % 600 == 0 and self.stats['uptime_seconds'] > 0:
                    self.logger.info(f"Status update - Uptime: {self.stats['uptime_seconds']:.0f}s, Threats: {self.stats['threats_detected']}, Responses: {self.stats['responses_triggered']}")
                    
                    # Get additional stats from components
                    if self.detector:
                        threat_summary = self.detector.get_threat_summary()
                        if threat_summary:
                            self.logger.info(f"Threat summary: {threat_summary}")
                        
                        suspicious_processes = self.detector.get_suspicious_processes()
                        if suspicious_processes:
                            self.logger.info(f"Suspicious processes: {len(suspicious_processes)}")
                    
                    if self.responder:
                        response_stats = self.responder.get_response_stats()
                        if response_stats:
                            self.logger.info(f"Response stats: {response_stats}")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                self.logger.error(f"Error in status monitoring: {e}")
                time.sleep(60)
    
    def get_status(self):
        """Get current system status."""
        status = {
            'running': self.is_running,
            'start_time': self.start_time.isoformat() if self.start_time else None,
            'stats': self.stats.copy(),
            'components': {
                'watcher': self.watcher.is_alive() if self.watcher else False,
                'detector': self.detector is not None,
                'responder': self.responder is not None
            }
        }
        
        # Add component-specific status
        if self.detector:
            status['suspicious_processes'] = len(self.detector.get_suspicious_processes())
            status['threat_summary'] = self.detector.get_threat_summary()
        
        if self.responder:
            status['response_stats'] = self.responder.get_response_stats()
        
        return status
    
    def run_interactive(self):
        """Run in interactive mode with user commands."""
        self.logger.info("Starting in interactive mode")
        
        if not self.start():
            print("Failed to start Deadbolt Defender")
            return
        
        print("Deadbolt Ransomware Defender is now running...")
        print("Commands: status, threats, responses, stop, help")
        
        try:
            while self.is_running:
                try:
                    command = input("> ").strip().lower()
                    
                    if command == "stop" or command == "quit" or command == "exit":
                        break
                    elif command == "status":
                        status = self.get_status()
                        print(f"Running: {status['running']}")
                        print(f"Uptime: {status['stats']['uptime_seconds']:.1f} seconds")
                        print(f"Threats detected: {status['stats']['threats_detected']}")
                        print(f"Responses triggered: {status['stats']['responses_triggered']}")
                        print(f"Components: {status['components']}")
                    elif command == "threats":
                        if self.detector:
                            suspicious = self.detector.get_suspicious_processes()
                            if suspicious:
                                print(f"Suspicious processes ({len(suspicious)}):")
                                for proc in suspicious[:5]:  # Show top 5
                                    print(f"  {proc['name']} (PID: {proc['pid']}) - Score: {proc['score']}")
                            else:
                                print("No suspicious processes detected")
                                
                            threat_summary = self.detector.get_threat_summary()
                            if threat_summary:
                                print(f"Threat summary: {threat_summary}")
                        else:
                            print("Detector not available")
                    elif command == "responses":
                        if self.responder:
                            history = self.responder.get_response_history(5)
                            if history:
                                print(f"Recent responses ({len(history)}):")
                                for response in history:
                                    print(f"  {response['timestamp']}: {response['response_level']} - {response['actions_taken']}")
                            else:
                                print("No responses triggered yet")
                        else:
                            print("Responder not available")
                    elif command == "help":
                        print("Available commands:")
                        print("  status    - Show system status")
                        print("  threats   - Show detected threats")
                        print("  responses - Show response history")
                        print("  stop      - Stop the defender")
                        print("  help      - Show this help")
                    elif command:
                        print(f"Unknown command: {command}. Type 'help' for available commands.")
                        
                except EOFError:
                    break
                except KeyboardInterrupt:
                    break
                    
        finally:
            self.stop()
            print("Deadbolt Defender stopped.")

def signal_handler(signum, frame):
    """Handle shutdown signals."""
    print(f"\nReceived signal {signum}. Shutting down...")
    global defender
    if defender:
        defender.stop()
    sys.exit(0)

def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Deadbolt Ransomware Defender')
    parser.add_argument('--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('--daemon', action='store_true', help='Run as daemon (background)')
    parser.add_argument('--interactive', action='store_true', help='Run in interactive mode')
    parser.add_argument('--status', action='store_true', help='Show status and exit')
    
    args = parser.parse_args()
    
    global defender
    defender = DeadboltDefender(debug_mode=args.debug)
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    if args.status:
        # Just show status
        if defender.start():
            status = defender.get_status()
            print(json.dumps(status, indent=2, default=str))
            defender.stop()
        return
    
    if args.interactive:
        # Interactive mode
        defender.run_interactive()
        return
    
    # Default: daemon mode
    if defender.start():
        print("Deadbolt Defender started. Press Ctrl+C to stop.")
        try:
            while defender.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            defender.stop()
    else:
        print("Failed to start Deadbolt Defender")
        sys.exit(1)

if __name__ == "__main__":
    main()