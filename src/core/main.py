"""  
Deadbolt Ransomware Defender - Main Orchestrator
Coordinates the watcher, detector, and responder components for comprehensive ransomware protection.
Supports both CLI and GUI modes.
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

# Add parent directories to path for imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

# Import our components
try:
    from .watcher import FileSystemWatcher
    from .detector import ThreatDetector
    from .responder import ThreatResponder
except ImportError:
    # Fallback for when running as script
    from watcher import FileSystemWatcher
    from detector import ThreatDetector
    from responder import ThreatResponder

try:
    from ..utils import config
except ImportError:
    # Fallback for when running as script
    utils_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'utils')
    sys.path.append(utils_path)
    import config

# Try to import GUI components
try:
    from ..ui.main_gui import DeadboltMainWindow
    from PyQt5.QtWidgets import QApplication
    GUI_AVAILABLE = True
except ImportError:
    try:
        # Fallback for when running as script - use absolute path approach
        import sys
        import os
        
        # Get the project root directory (3 levels up from this file)
        current_file_dir = os.path.dirname(os.path.abspath(__file__))
        src_dir = os.path.dirname(current_file_dir)
        project_root = os.path.dirname(src_dir)
        ui_path = os.path.join(src_dir, 'ui')
        
        # Add UI path to sys.path if not already there
        if ui_path not in sys.path:
            sys.path.insert(0, ui_path)
        
        # Import GUI components using absolute import
        import main_gui
        from main_gui import DeadboltMainWindow
        from PyQt5.QtWidgets import QApplication
        GUI_AVAILABLE = True
        
    except ImportError as e:
        print(f"GUI components not available: {e}")
        print("Running in CLI mode only.")
        GUI_AVAILABLE = False

class DeadboltDefender:
    """Main class that orchestrates all ransomware defense components."""
    
    def __init__(self, debug_mode=False):
        self.debug_mode = debug_mode
        self.is_running = False
        self.shutdown_event = threading.Event()
        
        # Set up project paths
        self.project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.logs_dir = os.path.join(self.project_root, 'logs')
        
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
        os.makedirs(self.logs_dir, exist_ok=True)
        
        # Main logger
        self.logger = logging.getLogger('deadbolt_main')
        self.logger.setLevel(logging.DEBUG if self.debug_mode else logging.INFO)
        
        # File handler
        file_handler = logging.FileHandler(os.path.join(self.logs_dir, 'main.log'))
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
        
        with open(os.path.join(self.logs_dir, 'threats.json'), 'a') as f:
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
        
        with open(os.path.join(self.logs_dir, 'responses.json'), 'a') as f:
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
            
            # Log ML enhancement status
            if hasattr(self.detector, 'ml_model') and self.detector.ml_model is not None:
                self.logger.info("ML-Enhanced Detection: Active")
                self.logger.info(f"ML Model Features: {len(self.detector.ml_features)}")
                print("ML-Enhanced Detection: Active - Reduced false positives expected")
            else:
                self.logger.info("ML Model: Not available - Using rule-based detection")
                print("WARNING: ML Model: Not available - Using aggressive rule-based detection")
            
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
    
    def run_daemon(self):
        """Run in daemon mode - continuous background protection."""
        self.logger.info("Starting in daemon mode (continuous background protection)")
        
        if not self.start():
            print("Failed to start Deadbolt Defender")
            return False
        
        print("Deadbolt Ransomware Defender is now running in background...")
        print("Protection is ACTIVE - monitoring for ransomware threats")
        print("Press Ctrl+C to stop.")
        print("")
        print("🛡️ Status: PROTECTED")
        print(f"📁 Monitoring: {len(getattr(config, 'TARGET_DIRS', []))} directories")
        print(f"🤖 ML Enhanced: {'Yes' if hasattr(self.detector, 'ml_model') and self.detector.ml_model else 'No'}")
        print(f"⚡ Real-time Protection: ACTIVE")
        print("")
        
        try:
            # Continuous monitoring loop - never exit unless interrupted
            while self.is_running:
                # Keep the system alive and responsive
                self.shutdown_event.wait(timeout=5.0)  # Check every 5 seconds
                
                if self.shutdown_event.is_set():
                    break
                    
                # Verify components are still healthy
                if not self._health_check():
                    self.logger.error("Component health check failed - restarting components")
                    self._restart_failed_components()
                    
        except KeyboardInterrupt:
            print("\n🛑 Shutdown signal received...")
        except Exception as e:
            self.logger.error(f"Error in daemon loop: {e}")
        finally:
            self.stop()
            print("🛡️ Deadbolt Defender stopped.")
            
        return True
        
    def _health_check(self):
        """Check if all components are healthy."""
        try:
            watcher_ok = self.watcher and self.watcher.is_alive()
            detector_ok = self.detector is not None
            responder_ok = self.responder is not None
            
            if not watcher_ok:
                self.logger.warning("File system watcher is not responding")
                return False
                
            return True
        except Exception as e:
            self.logger.error(f"Health check failed: {e}")
            return False
    
    def _restart_failed_components(self):
        """Restart failed components to maintain protection."""
        try:
            self.logger.info("Attempting to restart failed components")
            
            # Restart watcher if needed
            if not (self.watcher and self.watcher.is_alive()):
                self.logger.info("Restarting file system watcher")
                if self.watcher:
                    try:
                        self.watcher.stop_monitoring()
                    except:
                        pass
                
                from .watcher import FileSystemWatcher
                self.watcher = FileSystemWatcher(self.detector.analyze_threat)
                self.watcher.start_monitoring()
                
            return True
        except Exception as e:
            self.logger.error(f"Failed to restart components: {e}")
            return False

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
    parser.add_argument('--gui', action='store_true', help='Run with graphical interface')
    parser.add_argument('--status', action='store_true', help='Show status and exit')
    
    args = parser.parse_args()
    
    # If no specific mode is chosen, default to GUI if available, otherwise daemon
    if not any([args.daemon, args.interactive, args.gui, args.status]):
        if GUI_AVAILABLE:
            args.gui = True
        else:
            args.daemon = True
    
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
    
    if args.gui and GUI_AVAILABLE:
        # GUI mode with integrated backend
        print("Starting Deadbolt Defender with GUI and Backend...")
        try:
            app = QApplication(sys.argv)
            window = DeadboltMainWindow()
            
            # Integrate the defender with the GUI
            window.defender = defender
            
            # Override GUI start/stop methods to use our defender
            original_start = getattr(window, 'start_monitoring', None)
            original_stop = getattr(window, 'stop_monitoring', None)
            
            def gui_start_monitoring():
                if defender.start():
                    if hasattr(window, 'status_label'):
                        window.status_label.setText("Status: 🛡️ MONITORING")
                        window.status_label.setStyleSheet("font-weight: bold; color: green;")
                    print("🛡️ Backend protection started with GUI")
                else:
                    if hasattr(window, 'status_label'):
                        window.status_label.setText("Status: ❌ ERROR")
                        window.status_label.setStyleSheet("font-weight: bold; color: red;")
                    print("❌ Failed to start backend protection")
            
            def gui_stop_monitoring():
                defender.stop()
                if hasattr(window, 'status_label'):
                    window.status_label.setText("Status: 🛑 STOPPED")
                    window.status_label.setStyleSheet("font-weight: bold; color: red;")
                print("🛑 Backend protection stopped")
            
            # Connect GUI methods to defender
            window.start_monitoring = gui_start_monitoring
            window.stop_monitoring = gui_stop_monitoring
            
            # Auto-start the backend when GUI launches
            print("🚀 Auto-starting backend protection...")
            if defender.start():
                print("✅ Backend protection is ACTIVE")
                if hasattr(window, 'status_label'):
                    window.status_label.setText("Status: 🛡️ PROTECTED")
                    window.status_label.setStyleSheet("font-weight: bold; color: green;")
            else:
                print("⚠️ Backend protection failed to start")
            
            # Start background status updater
            def update_gui_status():
                while defender.is_running:
                    try:
                        status = defender.get_status()
                        # Update GUI with real-time status
                        if hasattr(window, 'refresh_dashboard'):
                            try:
                                window.refresh_dashboard()
                            except:
                                pass
                        time.sleep(5)  # Update every 5 seconds
                    except:
                        time.sleep(5)
            
            status_thread = threading.Thread(target=update_gui_status, daemon=True)
            status_thread.start()
            
            window.show()
            app.exec_()
            
        except Exception as e:
            print(f"Error starting GUI: {e}")
            import traceback
            traceback.print_exc()
            print("Falling back to daemon mode...")
            args.daemon = True
        finally:
            if defender.is_running:
                print("🛡️ Stopping backend protection...")
                defender.stop()
    
    elif args.interactive:
        # Interactive mode
        defender.run_interactive()
        return
    
    else:
        # Default: daemon mode - continuous background protection
        print("Starting Deadbolt Defender in daemon mode...")
        success = defender.run_daemon()
        if not success:
            print("Failed to start Deadbolt Defender")
            sys.exit(1)

if __name__ == "__main__":
    main()