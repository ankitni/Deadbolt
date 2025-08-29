# Simplified alerts module for background operation

import os
import sys

# Add parent directory to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logger import log_event, log_alert

class AlertManager:
    """Simplified alert manager for background operation"""
    
    def __init__(self):
        self.initialized = True
    
    def initialize(self):
        """Initialize alert system"""
        log_event("INFO", "Alert system initialized (background mode)")
    
    def show_alert(self, title, message, severity="medium", details=None):
        """Log alerts without displaying UI in background mode
        
        Args:
            title: Alert title
            message: Alert message
            severity: Alert severity ("high", "medium", "low")
            details: Optional dictionary with additional alert details
        """
        # Map severity string to standardized format
        severity_level = severity.upper() if severity.upper() in ["HIGH", "MEDIUM", "LOW"] else "MEDIUM"
        
        # Use the enhanced log_alert function for better alert formatting
        log_alert(severity_level, f"{title} - {message}", details)
        
        # Also log to standard event log for backward compatibility
        log_event("ALERT", f"{title} - {message} (Severity: {severity})")

# Singleton instance
alert_manager = AlertManager()