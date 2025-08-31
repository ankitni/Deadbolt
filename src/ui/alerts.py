# Enhanced alerts module for both background and desktop notifications

import os
import sys
import time
import threading

# Add parent directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import log_event, log_alert

# Try to import notification libraries
TOAST_AVAILABLE = False
PLYER_AVAILABLE = False
WIN_API_AVAILABLE = False

try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
except ImportError:
    ToastNotifier = None

try:
    from plyer import notification as plyer_notification
    PLYER_AVAILABLE = True
except ImportError:
    plyer_notification = None

try:
    import ctypes
    WIN_API_AVAILABLE = True
except ImportError:
    ctypes = None

class AlertManager:
    """Enhanced alert manager for both background operation and desktop notifications"""
    
    def __init__(self):
        self.initialized = True
        self.notification_cooldown = {}
        self.last_notification_time = 0
        self.min_notification_interval = 2  # Minimum 2 seconds between notifications
        
        # Initialize toast notifier if available
        if TOAST_AVAILABLE:
            self.toaster = ToastNotifier()
        else:
            self.toaster = None
            
        # Test notification capabilities on init
        self._test_notification_capabilities()
    
    def _test_notification_capabilities(self):
        """Test which notification methods are available"""
        self.available_methods = []
        
        if TOAST_AVAILABLE:
            self.available_methods.append('win10toast')
        if PLYER_AVAILABLE:
            self.available_methods.append('plyer')
        if WIN_API_AVAILABLE:
            self.available_methods.append('winapi')
            
        log_event("INFO", f"Alert system initialized with methods: {', '.join(self.available_methods) if self.available_methods else 'logging only'}")
    
    def initialize(self):
        """Initialize alert system"""
        log_event("INFO", "Alert system initialized (enhanced mode)")
    
    def show_alert(self, title, message, severity="medium", details=None, force_notification=False):
        """Show alerts with both logging and desktop notifications
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity ("high", "medium", "low")
            details: Optional dictionary with additional alert details
            force_notification: Force show notification regardless of cooldown
        """
        # Map severity string to standardized format
        severity_level = severity.upper() if severity.upper() in ["HIGH", "MEDIUM", "LOW"] else "MEDIUM"
        
        # Enhanced log alert with better formatting
        log_alert(severity_level, f"{title} - {message}", details)
        
        # Also log to standard event log for backward compatibility
        log_event("ALERT", f"{title} - {message} (Severity: {severity})")
        
        # Show desktop notification for all severities (not just HIGH)
        current_time = time.time()
        notification_key = f"{title}:{message}"
        
        # Check cooldown to prevent spam (unless forced)
        if (not force_notification and 
            notification_key in self.notification_cooldown and 
            current_time - self.notification_cooldown[notification_key] < self.min_notification_interval):
            log_event("INFO", "Notification skipped due to cooldown")
            return
            
        # Update cooldown
        self.notification_cooldown[notification_key] = current_time
        
        # Try to show desktop notification
        self._show_desktop_notification(title, message, severity_level)
        
        # Also try system beep for high severity
        if severity_level == "HIGH":
            self._system_beep()
    
    def _show_desktop_notification(self, title, message, severity):
        """Show desktop notification using available methods"""
        success = False
        
        # Determine duration and icon based on severity
        duration = 15 if severity == "HIGH" else 10 if severity == "MEDIUM" else 5
        icon_emoji = "🚨" if severity == "HIGH" else "⚠️" if severity == "MEDIUM" else "ℹ️"
        
        # Enhanced title with emoji and branding
        enhanced_title = f"{icon_emoji} Deadbolt AI - {title}"
        enhanced_message = f"{message}\n\nSeverity: {severity}"
        
        # Method 1: Try win10toast first (most reliable)
        if TOAST_AVAILABLE and self.toaster and not success:
            try:
                self.toaster.show_toast(
                    title=enhanced_title,
                    msg=enhanced_message,
                    duration=duration,
                    threaded=True
                )
                success = True
                log_event("INFO", "Desktop notification sent via win10toast")
            except Exception as e:
                log_event("WARNING", f"Win10toast notification failed: {e}")
        
        # Method 2: Try plyer as fallback
        if PLYER_AVAILABLE and not success:
            try:
                plyer_notification.notify(
                    title=enhanced_title,
                    message=enhanced_message,
                    timeout=duration
                )
                success = True
                log_event("INFO", "Desktop notification sent via plyer")
            except Exception as e:
                log_event("WARNING", f"Plyer notification failed: {e}")
        
        # Method 3: Try Windows API popup as last resort
        if WIN_API_AVAILABLE and not success:
            try:
                # Use MessageBox for immediate visibility
                threading.Thread(
                    target=self._show_windows_popup,
                    args=(enhanced_title, enhanced_message, severity),
                    daemon=True
                ).start()
                success = True
                log_event("INFO", "Desktop notification sent via Windows API")
            except Exception as e:
                log_event("WARNING", f"Windows API notification failed: {e}")
        
        if not success:
            log_event("WARNING", "All notification methods failed - only logging available")
    
    def _show_windows_popup(self, title, message, severity):
        """Show Windows MessageBox popup (runs in separate thread)"""
        try:
            # Determine icon type based on severity
            if severity == "HIGH":
                icon_type = 0x10  # MB_ICONERROR
            elif severity == "MEDIUM":
                icon_type = 0x30  # MB_ICONWARNING  
            else:
                icon_type = 0x40  # MB_ICONINFORMATION
                
            ctypes.windll.user32.MessageBoxW(
                0,
                message,
                title,
                icon_type
            )
        except Exception as e:
            log_event("ERROR", f"Windows popup failed: {e}")
    
    def _system_beep(self):
        """Play system beep for high severity alerts"""
        try:
            import winsound
            for _ in range(3):
                winsound.Beep(1000, 200)
                time.sleep(0.1)
        except ImportError:
            # Fallback: try Windows API beep
            try:
                if WIN_API_AVAILABLE:
                    for _ in range(3):
                        ctypes.windll.kernel32.Beep(1000, 200)
                        time.sleep(0.1)
            except Exception:
                pass
        except Exception:
            pass
    
    def show_ransomware_alert(self, threat_type, file_count, threat_score):
        """Specialized alert for ransomware detection"""
        title = "RANSOMWARE DETECTED"
        message = f"Threat: {threat_type}\nFiles affected: {file_count}\nThreat neutralized!"
        
        # Always force notification for ransomware
        self.show_alert(title, message, "HIGH", force_notification=True)
        
        # Additional console alert for immediate visibility
        alert_msg = f"\n" + "="*60 + "\n"
        alert_msg += f"🚨🚨🚨 DEADBOLT ALERT 🚨🚨🚨\n"
        alert_msg += f"TIME: {time.strftime('%H:%M:%S')}\n"
        alert_msg += f"THREAT: {threat_type.upper()}\n"
        alert_msg += f"SCORE: {threat_score}\n"
        alert_msg += f"STATUS: BLOCKED & NEUTRALIZED\n"
        alert_msg += "="*60 + "\n"
        print(alert_msg)
    
    def test_notifications(self):
        """Test all available notification methods"""
        log_event("INFO", "Testing notification capabilities...")
        
        self.show_alert(
            title="Test Alert",
            message="This is a test notification to verify the alert system is working properly.",
            severity="MEDIUM",
            force_notification=True
        )
        
        return len(self.available_methods) > 0

# Singleton instance
alert_manager = AlertManager()