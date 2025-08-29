"""
Enhanced logging module for Deadbolt AI with alerts and notifications
"""

import os
import sys
import logging
import json
from datetime import datetime
from pathlib import Path

# Create logs directory
LOG_DIR = os.path.join(os.getcwd(), 'logs')
os.makedirs(LOG_DIR, exist_ok=True)

def get_log_path():
    """Get the path to the main log file"""
    return os.path.join(LOG_DIR, 'deadbolt.log')

# Setup main logger
logger = logging.getLogger('deadbolt')
logger.setLevel(logging.INFO)

# File handler for main log
main_log_handler = logging.FileHandler(get_log_path())
main_formatter = logging.Formatter('[%(asctime)s] %(levelname)s: %(message)s')
main_log_handler.setFormatter(main_formatter)
logger.addHandler(main_log_handler)

# Console handler
console_handler = logging.StreamHandler()
console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(console_formatter)
logger.addHandler(console_handler)

def log_event(level, message, details=None):
    """Log an event with optional details
    
    Args:
        level: Log level (INFO, WARNING, ERROR, CRITICAL)
        message: Main log message
        details: Optional dictionary with additional details
    """
    try:
        if level.upper() == 'INFO':
            logger.info(message)
        elif level.upper() == 'WARNING':
            logger.warning(message)
        elif level.upper() == 'ERROR':
            logger.error(message)
        elif level.upper() == 'CRITICAL':
            logger.critical(message)
        elif level.upper() == 'ALERT':
            logger.critical(f"[ALERT] {message}")
        else:
            logger.info(message)
        
        # If details provided, log them as JSON
        if details:
            logger.info(f"Details: {json.dumps(details, default=str)}")
            
    except Exception as e:
        print(f"Logging error: {e}")

def log_alert(severity, message, details=None):
    """Log a security alert with enhanced formatting
    
    Args:
        severity: Alert severity (HIGH, MEDIUM, LOW)
        message: Alert message
        details: Optional dictionary with additional alert details
    """
    try:
        # Format alert message
        alert_msg = f"[ALERT-{severity.upper()}] {message}"
        
        # Log with appropriate level
        if severity.upper() == 'HIGH':
            logger.critical(alert_msg)
        elif severity.upper() == 'MEDIUM':
            logger.warning(alert_msg)
        else:
            logger.info(alert_msg)
        
        # Log details if provided
        if details:
            logger.info(f"Alert details: {json.dumps(details, default=str)}")
        
        # Also try to show system notification for high severity
        if severity.upper() == 'HIGH':
            show_notification("Deadbolt Security Alert", message, severity)
            
    except Exception as e:
        print(f"Alert logging error: {e}")

def show_notification(title, message, severity="MEDIUM"):
    """Show a Windows notification
    
    Args:
        title: Notification title
        message: Notification message
        severity: Severity level for styling
    """
    try:
        # Try to use win10toast for notifications
        from win10toast import ToastNotifier
        toaster = ToastNotifier()
        
        # Determine duration based on severity
        duration = 10 if severity.upper() == 'HIGH' else 5
        
        toaster.show_toast(
            title=f"🛡️ {title}",
            msg=message,
            duration=duration,
            threaded=True
        )
    except ImportError:
        # Fallback: just log if win10toast is not available
        log_event("INFO", f"Notification: {title} - {message}")
    except Exception as e:
        # Log notification errors
        log_event("ERROR", f"Failed to show notification: {e}")

# Enhanced logging functions for backward compatibility
def info(message):
    log_event("INFO", message)

def warning(message):
    log_event("WARNING", message)

def error(message):
    log_event("ERROR", message)

def critical(message):
    log_event("CRITICAL", message)

def alert(severity, message, details=None):
    log_alert(severity, message, details)

# Module initialization
log_event("INFO", "Deadbolt logging system initialized")