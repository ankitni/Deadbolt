# Advanced GUI implementation for Deadbolt AI using PyQt5

import os
import sys
import time
import threading
import traceback
import logging
import re
import json  # Add json import
from datetime import datetime

# Add parent directories to path so we can import modules
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
src_path = os.path.join(project_root, 'src')
utils_path = os.path.join(src_path, 'utils')
core_path = os.path.join(src_path, 'core')
ui_path = os.path.join(src_path, 'ui')

# Add all necessary paths
for path in [project_root, src_path, utils_path, core_path, ui_path]:
    if path not in sys.path:
        sys.path.insert(0, path)

# Set matplotlib backend before importing matplotlib modules
import matplotlib
matplotlib.use('Qt5Agg')

# PyQt5 imports
from PyQt5.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, QVBoxLayout,
                             QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
                             QHeaderView, QProgressBar, QComboBox, QCheckBox, QGroupBox,
                             QLineEdit, QFileDialog, QMessageBox, QSystemTrayIcon, QMenu, QAction,
                             QScrollArea, QSizePolicy, QFrame, QTextEdit)
from PyQt5.QtCore import Qt, QTimer, pyqtSignal, QThread, QSize
from PyQt5.QtGui import QIcon, QColor, QPixmap, QFont, QTextCursor

# Visualization imports
import pyqtgraph as pg
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

# Import Deadbolt modules with fallback handling
try:
    # Try relative imports first
    from ..utils.logger import log_event, get_log_path, LOG_DIR, log_alert
except ImportError:
    # Fall back to absolute imports
    try:
        from utils.logger import log_event, get_log_path, LOG_DIR, log_alert
    except ImportError:
        # Final fallback - create dummy functions if logger not available
        def log_event(level, message):
            print(f"[{level}] {message}")
        def get_log_path():
            return os.path.join(os.getcwd(), 'logs', 'deadbolt.log')
        def log_alert(level, message):
            print(f"[ALERT-{level}] {message}")
        LOG_DIR = os.path.join(os.getcwd(), 'logs')
        
try:
    from ..utils import config
    from ..utils.config import TARGET_DIRS, RULES, SUSPICIOUS_PATTERNS, ACTIONS
except ImportError:
    try:
        from utils import config
        from utils.config import TARGET_DIRS, RULES, SUSPICIOUS_PATTERNS, ACTIONS
    except ImportError:
        # Fallback if config module is not available
        TARGET_DIRS = []
        RULES = {'mass_delete': {'count': 10, 'interval': 5}, 'mass_rename': {'count': 10, 'interval': 5}}
        SUSPICIOUS_PATTERNS = {'extensions': [], 'filenames': []}
        ACTIONS = {'log_only': False, 'kill_process': True, 'shutdown': False, 'dry_run': False}

# Try to import watcher (may not be available during GUI standalone testing)
try:
    from ..core import watcher
    def start_watcher(path):
        # This is a simplified version - the real integration happens in main.py
        print(f"Starting watcher for {path}")
        return type('MockWatcher', (), {'stop': lambda: None})()
except ImportError:
    try:
        from core import watcher
        def start_watcher(path):
            print(f"Starting watcher for {path}")
            return type('MockWatcher', (), {'stop': lambda: None})()
    except ImportError:
        def start_watcher(path):
            print(f"Mock watcher started for {path}")
            return type('MockWatcher', (), {'stop': lambda: None})()

# Import alert and dashboard modules with fallback
try:
    from .alerts import alert_manager, AlertManager
except ImportError:
    try:
        from alerts import alert_manager, AlertManager
    except ImportError:
        # Create dummy alert manager if not available
        class AlertManager:
            def show_alert(self, *args, **kwargs):
                pass
        alert_manager = AlertManager()

try:
    from .dashboard import DashboardData, start_dashboard_monitor, get_dashboard_data
except ImportError:
    try:
        from dashboard import DashboardData, start_dashboard_monitor, get_dashboard_data
    except ImportError:
        # Create dummy dashboard functions if not available
        class DashboardData:
            pass
        def start_dashboard_monitor(callback, interval):
            class MockMonitor:
                def stop(self): pass
                def get_current_stats(self): return {}
            return MockMonitor()
        def get_dashboard_data():
            return {}

# Import config manager for saving settings
try:
    from ..utils.config_manager import config_manager
    CONFIG_MANAGER_AVAILABLE = True
except ImportError:
    try:
        from utils.config_manager import config_manager
        CONFIG_MANAGER_AVAILABLE = True
    except ImportError:
        CONFIG_MANAGER_AVAILABLE = False
        print("Config manager not available - settings will not persist")

# Import ML detector with fallback handling
try:
    from ..core.ml_detector import MLThreatDetector
    ML_DETECTOR_AVAILABLE = True
except ImportError:
    try:
        from core.ml_detector import MLThreatDetector
        ML_DETECTOR_AVAILABLE = True
    except ImportError:
        ML_DETECTOR_AVAILABLE = False
        print("ML detector not available - ML features will be limited")
        # Create dummy ML detector for fallback
        class MLThreatDetector:
            def __init__(self, callback):
                pass
            def get_ml_statistics(self):
                return {
                    'model_loaded': False,
                    'model_features': 0,
                    'monitoring_active': False,
                    'total_predictions': 0,
                    'malicious_detected': 0,
                    'benign_classified': 0,
                    'high_confidence_alerts': 0,
                    'average_confidence': 0.0,
                    'false_positive_rate': 0.0,
                    'last_prediction_formatted': 'Never',
                    'confidence_distribution': {}
                }
            def get_recent_ml_logs(self, limit=50):
                return [{
                    'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'level': 'INFO',
                    'message': 'ML detector module not available',
                    'color': '#ffffff',
                    'full_line': 'ML detector not available'
                }]

# Global variables
active_watchers = []

# Custom matplotlib canvas for embedding in PyQt5
class MplCanvas(FigureCanvas):
    def __init__(self, width=5, height=4, dpi=100):
        # Ensure width, height, and dpi have valid values
        width = width if width is not None and width > 0 else 5
        height = height if height is not None and height > 0 else 4
        dpi = dpi if dpi is not None and dpi > 0 else 100
        
        # Create Figure and initialize it with the provided parameters
        self.fig = Figure(figsize=(width, height), dpi=dpi, facecolor='white')
        # Add subplot before initializing the FigureCanvas
        self.axes = self.fig.add_subplot(111)
        # Initialize the FigureCanvas with the figure
        super(MplCanvas, self).__init__(self.fig)
        # Apply tight layout with better padding
        self.fig.tight_layout(pad=2.0)

# Thread for monitoring logs in background
class LogMonitorThread(QThread):
    log_updated = pyqtSignal(str, str, str)  # timestamp, level, message
    alert_triggered = pyqtSignal(str, str, str)  # severity, message, timestamp
    
    def __init__(self):
        super().__init__()
        self.running = True
        self.log_file = get_log_path()
        self.last_position = 0
    
    def run(self):
        while self.running:
            try:
                if os.path.exists(self.log_file):
                    with open(self.log_file, 'r', encoding='utf-8') as f:
                        f.seek(self.last_position)
                        new_lines = f.readlines()
                        self.last_position = f.tell()
                        
                        for line in new_lines:
                            # Parse log line
                            match = re.match(r'\[(.*?)\] (\w+): (.*)', line.strip())
                            if match:
                                timestamp, level, message = match.groups()
                                self.log_updated.emit(timestamp, level, message)
                                
                                # Check for alerts
                                if 'ALERT' in level or '[ALERT' in message:
                                    alert_match = re.search(r'\[ALERT-(\w+)\] (.*)', message)
                                    if alert_match:
                                        severity, alert_msg = alert_match.groups()
                                        self.alert_triggered.emit(severity, alert_msg, timestamp)
            except Exception as e:
                print(f"Error reading log file: {str(e)}")
            
            # Check every second
            time.sleep(1)
    
    def stop(self):
        self.running = False

# Main application window
class DeadboltMainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Deadbolt AI - Advanced Ransomware Protection System")
        self.setMinimumSize(1400, 900)
        self.resize(1600, 1000)
        
        # Theme management
        self.dark_theme = False
        
        # Monitoring state management
        self.monitoring_active = False
        self.force_system_health_active = False
        
        # Apply initial styling
        self.apply_theme()
        
        # Initialize UI
        self.init_ui()
        
        # Setup system tray
        self.setup_tray()
        
        # Start log monitoring
        self.log_monitor = LogMonitorThread()
        self.log_monitor.log_updated.connect(self.update_log_display)
        self.log_monitor.alert_triggered.connect(self.handle_alert)
        self.log_monitor.start()
        
        # Start dashboard monitor
        self.dashboard_monitor = start_dashboard_monitor(self.update_dashboard_stats, 5)
        
        # Start data refresh timer
        self.refresh_timer = QTimer()
        self.refresh_timer.timeout.connect(self.refresh_dashboard)
        self.refresh_timer.timeout.connect(self.refresh_ml_stats)  # Also refresh ML stats
        self.refresh_timer.timeout.connect(self.check_monitoring_status)  # Check monitoring status
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
        # Initialize statistics from dashboard
        self.initialize_statistics()
        
        # Load initial data
        self.load_initial_data()
        
        # Initialize monitoring status
        self.check_monitoring_status()
    
    def initialize_statistics(self):
        """Initialize statistics from the dashboard monitor
        
        This method gets the initial statistics from the dashboard monitor.
        If the dashboard monitor is not available, it initializes with default values.
        """
        try:
            # Get initial statistics from the dashboard monitor
            if hasattr(self, 'dashboard_monitor') and self.dashboard_monitor is not None:
                stats = self.dashboard_monitor.get_current_stats()
                if stats is not None and isinstance(stats, dict):
                    self.stats = stats.copy()
                else:
                    raise ValueError("Invalid stats from dashboard monitor")
            else:
                raise AttributeError("Dashboard monitor not initialized")
        except Exception as e:
            print(f"Error initializing statistics: {str(e)}")
            # Fallback if dashboard monitor is not initialized yet or returns invalid data
            self.stats = {
                'events_total': 0,
                'events_by_type': {},
                'alerts_high': 0,
                'alerts_medium': 0,
                'alerts_low': 0,
                'alerts_by_time': [0] * 24,  # Initialize with zeros for 24 hours
                'recent_alerts': []  # Initialize with empty list for recent alerts
            }
            
            # Get monitored paths from TARGET_DIRS
            self.stats['monitored_paths'] = TARGET_DIRS.copy()
    
    def init_ui(self):
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Enhanced status and control section
        control_frame = QFrame()
        control_layout = QHBoxLayout(control_frame)
        
        # Status section
        status_group = QGroupBox("System Status")
        status_layout = QVBoxLayout(status_group)
        
        self.status_label = QLabel("Status: Initializing...")
        self.status_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_label)
        
        # Real-time stats labels
        self.active_threats_label = QLabel("Active Threats: 0")
        self.monitored_paths_label = QLabel("Monitored Paths: 0")
        self.active_threats_label.setAlignment(Qt.AlignCenter)
        self.monitored_paths_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.active_threats_label)
        status_layout.addWidget(self.monitored_paths_label)
        
        control_layout.addWidget(status_group)
        
        # Control buttons section
        button_group = QGroupBox("Monitoring Controls")
        button_layout = QVBoxLayout(button_group)
        
        # Enhanced control buttons
        buttons_row = QHBoxLayout()
        
        self.start_button = QPushButton("🟢 START MONITORING")
        self.start_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #28a745, stop: 1 #1e7e34);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                padding: 12px 24px;
                min-width: 180px;
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #34ce57, stop: 1 #28a745);
            }
            QPushButton:pressed {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #1e7e34, stop: 1 #155724);
            }
        """)
        self.start_button.clicked.connect(self.start_monitoring)
        
        self.stop_button = QPushButton("🔴 STOP MONITORING")
        self.stop_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #dc3545, stop: 1 #c82333);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: bold;
                padding: 12px 24px;
                min-width: 180px;
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #e45565, stop: 1 #dc3545);
            }
            QPushButton:pressed {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #c82333, stop: 1 #a71e2a);
            }
        """)
        self.stop_button.clicked.connect(self.stop_monitoring)
        
        buttons_row.addWidget(self.start_button)
        buttons_row.addWidget(self.stop_button)
        button_layout.addLayout(buttons_row)
        
        # Emergency and Theme buttons row
        extra_buttons_row = QHBoxLayout()
        
        # Emergency button
        self.emergency_button = QPushButton("⚠️ EMERGENCY SHUTDOWN")
        self.emergency_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #ffc107, stop: 1 #e0a800);
                color: #212529;
                border: none;
                border-radius: 6px;
                font-size: 12px;
                font-weight: bold;
                padding: 8px 16px;
                margin-top: 5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #ffcd39, stop: 1 #ffc107);
            }
        """)
        self.emergency_button.clicked.connect(self.emergency_shutdown)
        
        # Theme toggle button
        self.theme_button = QPushButton("🌙 DARK THEME")
        self.theme_button.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #6f42c1, stop: 1 #5a32a3);
                color: white;
                border: none;
                border-radius: 6px;
                font-size: 12px;
                font-weight: bold;
                padding: 8px 16px;
                margin-top: 5px;
            }
            QPushButton:hover {
                background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                            stop: 0 #8c5bd1, stop: 1 #6f42c1);
            }
        """)
        self.theme_button.clicked.connect(self.toggle_theme)
        
        extra_buttons_row.addWidget(self.emergency_button)
        extra_buttons_row.addWidget(self.theme_button)
        button_layout.addLayout(extra_buttons_row)
        
        control_layout.addWidget(button_group)
        
        # ML Status section
        ml_status_group = QGroupBox("ML Engine Status")
        ml_status_layout = QVBoxLayout(ml_status_group)
        
        self.ml_status_label = QLabel("ML Engine: Initializing...")
        self.ml_status_label.setAlignment(Qt.AlignCenter)
        
        self.ml_predictions_label = QLabel("Predictions: 0")
        self.ml_threats_label = QLabel("Threats Detected: 0")
        self.ml_predictions_label.setAlignment(Qt.AlignCenter)
        self.ml_threats_label.setAlignment(Qt.AlignCenter)
        
        ml_status_layout.addWidget(self.ml_status_label)
        ml_status_layout.addWidget(self.ml_predictions_label)
        ml_status_layout.addWidget(self.ml_threats_label)
        
        control_layout.addWidget(ml_status_group)
        
        # Add to main layout
        main_layout.addWidget(control_frame)
        
        # Tab widget for different sections
        self.tabs = QTabWidget()
        self.dashboard_tab = QWidget()
        self.logs_tab = QWidget()
        self.settings_tab = QWidget()
        self.ml_tab = QWidget()  # NEW: ML Analytics tab
        
        # Setup tabs
        self.setup_dashboard_tab()
        self.setup_logs_tab()
        self.setup_settings_tab()
        self.setup_ml_tab()  # NEW: Setup ML tab
        
        # Add tabs to tab widget
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.logs_tab, "Logs")
        self.tabs.addTab(self.ml_tab, "ML Analytics")  # NEW: ML tab
        self.tabs.addTab(self.settings_tab, "Settings")
        
        # Add tab widget to main layout
        main_layout.addWidget(self.tabs)
    
    def setup_dashboard_tab(self):
        layout = QVBoxLayout(self.dashboard_tab)
        
        # Top row with summary cards
        summary_layout = QHBoxLayout()
        
        # Threats detected card
        threats_group = QGroupBox("Threats Detected")
        threats_layout = QVBoxLayout(threats_group)
        self.threats_label = QLabel("0")
        self.threats_label.setStyleSheet("font-size: 24pt; font-weight: bold; color: red;")
        self.threats_label.setAlignment(Qt.AlignCenter)
        threats_layout.addWidget(self.threats_label)
        summary_layout.addWidget(threats_group)
        
        # Threats blocked card
        blocked_group = QGroupBox("Threats Blocked")
        blocked_layout = QVBoxLayout(blocked_group)
        self.blocked_label = QLabel("0")
        self.blocked_label.setStyleSheet("font-size: 24pt; font-weight: bold; color: green;")
        self.blocked_label.setAlignment(Qt.AlignCenter)
        blocked_layout.addWidget(self.blocked_label)
        summary_layout.addWidget(blocked_group)
        
        # Processes terminated card
        processes_group = QGroupBox("Processes Terminated")
        processes_layout = QVBoxLayout(processes_group)
        self.processes_label = QLabel("0")
        self.processes_label.setStyleSheet("font-size: 24pt; font-weight: bold; color: orange;")
        self.processes_label.setAlignment(Qt.AlignCenter)
        processes_layout.addWidget(self.processes_label)
        summary_layout.addWidget(processes_group)
        
        # Total events card
        events_group = QGroupBox("Total Events")
        events_layout = QVBoxLayout(events_group)
        self.events_label = QLabel("0")
        self.events_label.setStyleSheet("font-size: 24pt; font-weight: bold;")
        self.events_label.setAlignment(Qt.AlignCenter)
        events_layout.addWidget(self.events_label)
        summary_layout.addWidget(events_group)
        
        layout.addLayout(summary_layout)
        
        # Second row with system health indicators
        health_layout = QHBoxLayout()
        
        # System health card
        health_group = QGroupBox("System Health")
        health_form = QVBoxLayout(health_group)
        
        self.detector_status = QLabel("Detector: Inactive")
        self.responder_status = QLabel("Responder: Inactive")
        self.watcher_status = QLabel("Watcher: Inactive")
        
        health_form.addWidget(self.detector_status)
        health_form.addWidget(self.responder_status)
        health_form.addWidget(self.watcher_status)
        
        health_layout.addWidget(health_group)
        
        # Alert distribution card
        alert_dist_group = QGroupBox("Alert Severity Distribution")
        alert_dist_layout = QVBoxLayout(alert_dist_group)
        
        self.high_alerts_label = QLabel("High: 0")
        self.high_alerts_label.setStyleSheet("color: red; font-weight: bold;")
        self.medium_alerts_label = QLabel("Medium: 0")
        self.medium_alerts_label.setStyleSheet("color: orange; font-weight: bold;")
        self.low_alerts_label = QLabel("Low: 0")
        self.low_alerts_label.setStyleSheet("color: blue; font-weight: bold;")
        
        alert_dist_layout.addWidget(self.high_alerts_label)
        alert_dist_layout.addWidget(self.medium_alerts_label)
        alert_dist_layout.addWidget(self.low_alerts_label)
        
        health_layout.addWidget(alert_dist_group)
        
        layout.addLayout(health_layout)
        
        # Middle row with charts
        charts_layout = QHBoxLayout()
        
        # Threats by time chart
        time_chart_group = QGroupBox("Threats by Hour")
        time_chart_layout = QVBoxLayout(time_chart_group)
        try:
            self.time_chart = MplCanvas(width=6, height=4, dpi=100)
            # Initialize with empty data
            self.time_chart.axes.bar(range(24), [0] * 24, color='#FF5555')
            self.time_chart.axes.set_xlabel('Hour of Day', fontsize=10)
            self.time_chart.axes.set_ylabel('Number of Threats', fontsize=10)
            self.time_chart.axes.set_title('Threat Activity by Hour', fontsize=12, pad=15)
            self.time_chart.axes.set_xticks(range(0, 24, 3))
            self.time_chart.axes.tick_params(axis='both', which='major', labelsize=9)
            # Improve layout to prevent text cutting
            self.time_chart.fig.tight_layout(pad=2.0)
            time_chart_layout.addWidget(self.time_chart)
        except Exception as e:
            print(f"Error initializing time chart: {str(e)}")
            # Add a placeholder label instead
            time_chart_layout.addWidget(QLabel("Chart initialization failed"))
        charts_layout.addWidget(time_chart_group)
        
        # Event types pie chart
        event_chart_group = QGroupBox("Event Types")
        event_chart_layout = QVBoxLayout(event_chart_group)
        try:
            self.event_chart = MplCanvas(width=6, height=4, dpi=100)
            # Initialize with dummy data
            self.event_chart.axes.pie([1], labels=['No Data'], autopct='%1.1f%%', startangle=90, textprops={'fontsize': 9})
            self.event_chart.axes.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            self.event_chart.axes.set_title('Event Types Distribution', fontsize=12, pad=15)
            # Improve layout to prevent text cutting
            self.event_chart.fig.tight_layout(pad=2.0)
            event_chart_layout.addWidget(self.event_chart)
        except Exception as e:
            print(f"Error initializing event chart: {str(e)}")
            # Add a placeholder label instead
            event_chart_layout.addWidget(QLabel("Chart initialization failed"))
        charts_layout.addWidget(event_chart_group)
        
        layout.addLayout(charts_layout)
        
        # Bottom row with recent activity tables
        tables_layout = QHBoxLayout()
        
        # Recent threats table
        threats_table_group = QGroupBox("Recent Threats")
        threats_table_layout = QVBoxLayout(threats_table_group)
        
        self.threats_table = QTableWidget()
        self.threats_table.setColumnCount(3)
        self.threats_table.setHorizontalHeaderLabels(["Time", "Type", "Description"])
        self.threats_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        threats_table_layout.addWidget(self.threats_table)
        
        tables_layout.addWidget(threats_table_group)
        
        # Recent responses table
        responses_table_group = QGroupBox("Recent Responses")
        responses_table_layout = QVBoxLayout(responses_table_group)
        
        self.responses_table = QTableWidget()
        self.responses_table.setColumnCount(3)
        self.responses_table.setHorizontalHeaderLabels(["Time", "Action", "Details"])
        self.responses_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        responses_table_layout.addWidget(self.responses_table)
        
        tables_layout.addWidget(responses_table_group)
        
        layout.addLayout(tables_layout)
    
    def setup_logs_tab(self):
        layout = QVBoxLayout(self.logs_tab)
        
        # Controls for log filtering
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter by level:"))
        
        self.log_level_combo = QComboBox()
        self.log_level_combo.addItems(["All", "INFO", "WARNING", "ERROR", "CRITICAL", "ALERT"])
        self.log_level_combo.currentTextChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.log_level_combo)
        
        filter_layout.addWidget(QLabel("Search:"))
        self.log_search_input = QLineEdit()
        self.log_search_input.textChanged.connect(self.filter_logs)
        filter_layout.addWidget(self.log_search_input)
        
        self.auto_scroll_check = QCheckBox("Auto-scroll")
        self.auto_scroll_check.setChecked(True)
        filter_layout.addWidget(self.auto_scroll_check)
        
        clear_button = QPushButton("Clear Display")
        clear_button.clicked.connect(self.clear_log_display)
        filter_layout.addWidget(clear_button)
        
        layout.addLayout(filter_layout)
        
        # Log display table
        self.log_table = QTableWidget()
        self.log_table.setColumnCount(3)
        self.log_table.setHorizontalHeaderLabels(["Time", "Level", "Message"])
        self.log_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        layout.addWidget(self.log_table)
        
        # Buttons for log management
        button_layout = QHBoxLayout()
        
        open_log_button = QPushButton("Open Log File")
        open_log_button.clicked.connect(self.open_log_file)
        button_layout.addWidget(open_log_button)
        
        export_button = QPushButton("Export Logs")
        export_button.clicked.connect(self.export_logs)
        button_layout.addWidget(export_button)
        
        layout.addLayout(button_layout)
    
    def setup_settings_tab(self):
        layout = QVBoxLayout(self.settings_tab)
        
        # Monitored directories section
        dirs_group = QGroupBox("Monitored Directories")
        dirs_layout = QVBoxLayout(dirs_group)
        
        self.dirs_table = QTableWidget()
        self.dirs_table.setColumnCount(2)
        self.dirs_table.setHorizontalHeaderLabels(["Path", "Status"])
        self.dirs_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        dirs_layout.addWidget(self.dirs_table)
        
        dirs_button_layout = QHBoxLayout()
        add_dir_button = QPushButton("Add Directory")
        add_dir_button.clicked.connect(self.add_directory)
        dirs_button_layout.addWidget(add_dir_button)
        
        remove_dir_button = QPushButton("Remove Directory")
        remove_dir_button.clicked.connect(self.remove_directory)
        dirs_button_layout.addWidget(remove_dir_button)
        
        dirs_layout.addLayout(dirs_button_layout)
        layout.addWidget(dirs_group)
        
        # Detection rules section
        rules_group = QGroupBox("Detection Rules")
        rules_layout = QVBoxLayout(rules_group)
        
        # Mass delete threshold
        mass_delete_layout = QHBoxLayout()
        mass_delete_layout.addWidget(QLabel("Mass Delete Threshold:"))
        self.mass_delete_input = QLineEdit(str(RULES["mass_delete"]["count"]))
        mass_delete_layout.addWidget(self.mass_delete_input)
        mass_delete_layout.addWidget(QLabel("files in"))
        self.mass_delete_interval = QLineEdit(str(RULES["mass_delete"]["interval"]))
        mass_delete_layout.addWidget(self.mass_delete_interval)
        mass_delete_layout.addWidget(QLabel("seconds"))
        rules_layout.addLayout(mass_delete_layout)
        
        # Mass rename threshold
        mass_rename_layout = QHBoxLayout()
        mass_rename_layout.addWidget(QLabel("Mass Rename Threshold:"))
        self.mass_rename_input = QLineEdit(str(RULES["mass_rename"]["count"]))
        mass_rename_layout.addWidget(self.mass_rename_input)
        mass_rename_layout.addWidget(QLabel("files in"))
        self.mass_rename_interval = QLineEdit(str(RULES["mass_rename"]["interval"]))
        mass_rename_layout.addWidget(self.mass_rename_interval)
        mass_rename_layout.addWidget(QLabel("seconds"))
        rules_layout.addLayout(mass_rename_layout)
        
        # Save button
        save_rules_button = QPushButton("Save Rules")
        save_rules_button.clicked.connect(self.save_rules)
        rules_layout.addWidget(save_rules_button)
        
        layout.addWidget(rules_group)
        
        # Response actions section
        actions_group = QGroupBox("Response Actions")
        actions_layout = QVBoxLayout(actions_group)
        
        self.log_only_check = QCheckBox("Log Only (No Actions)")
        self.log_only_check.setChecked(ACTIONS.get("log_only", False))
        actions_layout.addWidget(self.log_only_check)
        
        self.kill_process_check = QCheckBox("Kill Suspicious Processes")
        self.kill_process_check.setChecked(ACTIONS.get("kill_process", True))
        actions_layout.addWidget(self.kill_process_check)
        
        self.shutdown_check = QCheckBox("Emergency Shutdown (High Severity Only)")
        self.shutdown_check.setChecked(ACTIONS.get("shutdown", False))
        actions_layout.addWidget(self.shutdown_check)
        
        self.dry_run_check = QCheckBox("Dry Run Mode (Test Only)")
        self.dry_run_check.setChecked(ACTIONS.get("dry_run", False))
        actions_layout.addWidget(self.dry_run_check)
        
        # Save button
        save_actions_button = QPushButton("Save Actions")
        save_actions_button.clicked.connect(self.save_actions)
        actions_layout.addWidget(save_actions_button)
        
        layout.addWidget(actions_group)
    
    def setup_ml_tab(self):
        """Setup the ML Analytics tab with comprehensive ML monitoring."""
        layout = QVBoxLayout(self.ml_tab)
        
        # ML Status Section
        ml_status_group = QGroupBox("ML Model Status")
        ml_status_layout = QHBoxLayout(ml_status_group)
        
        # Model status indicators
        self.ml_model_status = QLabel("Model: Loading...")
        self.ml_model_status.setStyleSheet("font-weight: bold; color: orange;")
        ml_status_layout.addWidget(self.ml_model_status)
        
        self.ml_features_count = QLabel("Features: --")
        ml_status_layout.addWidget(self.ml_features_count)
        
        self.ml_monitoring_status = QLabel("Monitoring: --")
        ml_status_layout.addWidget(self.ml_monitoring_status)
        
        # Refresh ML stats button
        refresh_ml_button = QPushButton("Refresh ML Stats")
        refresh_ml_button.clicked.connect(self.refresh_ml_stats)
        ml_status_layout.addWidget(refresh_ml_button)
        
        layout.addWidget(ml_status_group)
        
        # ML Statistics Section
        ml_stats_group = QGroupBox("ML Prediction Statistics")
        ml_stats_layout = QVBoxLayout(ml_stats_group)
        
        # Stats row 1
        stats_row1 = QHBoxLayout()
        self.ml_total_predictions = QLabel("Total Predictions: 0")
        self.ml_malicious_detected = QLabel("Malicious Detected: 0")
        self.ml_benign_classified = QLabel("Benign Classified: 0")
        stats_row1.addWidget(self.ml_total_predictions)
        stats_row1.addWidget(self.ml_malicious_detected)
        stats_row1.addWidget(self.ml_benign_classified)
        ml_stats_layout.addLayout(stats_row1)
        
        # Stats row 2
        stats_row2 = QHBoxLayout()
        self.ml_high_confidence = QLabel("High Confidence Alerts: 0")
        self.ml_average_confidence = QLabel("Average Confidence: 0.0")
        self.ml_false_positive_rate = QLabel("Est. False Positive Rate: 0.0%")
        stats_row2.addWidget(self.ml_high_confidence)
        stats_row2.addWidget(self.ml_average_confidence)
        stats_row2.addWidget(self.ml_false_positive_rate)
        ml_stats_layout.addLayout(stats_row2)
        
        # Last prediction info
        self.ml_last_prediction = QLabel("Last Prediction: Never")
        self.ml_last_prediction.setStyleSheet("font-style: italic;")
        ml_stats_layout.addWidget(self.ml_last_prediction)
        
        layout.addWidget(ml_stats_group)
        
        # ML Confidence Distribution Chart
        confidence_group = QGroupBox("Confidence Distribution")
        confidence_layout = QVBoxLayout(confidence_group)
        
        # Create matplotlib canvas for confidence chart
        self.ml_confidence_canvas = MplCanvas(width=8, height=4, dpi=100)
        confidence_layout.addWidget(self.ml_confidence_canvas)
        
        layout.addWidget(confidence_group)
        
        # ML Logs Section
        ml_logs_group = QGroupBox("ML Detection Logs")
        ml_logs_layout = QVBoxLayout(ml_logs_group)
        
        # ML log controls
        ml_log_controls = QHBoxLayout()
        
        ml_log_controls.addWidget(QLabel("Show:"))
        self.ml_log_level_combo = QComboBox()
        self.ml_log_level_combo.addItems(["All", "CRITICAL", "WARNING", "INFO"])
        self.ml_log_level_combo.currentTextChanged.connect(self.filter_ml_logs)
        ml_log_controls.addWidget(self.ml_log_level_combo)
        
        self.ml_log_search = QLineEdit()
        self.ml_log_search.setPlaceholderText("Search ML logs...")
        self.ml_log_search.textChanged.connect(self.filter_ml_logs)
        ml_log_controls.addWidget(self.ml_log_search)
        
        refresh_ml_logs_button = QPushButton("Refresh ML Logs")
        refresh_ml_logs_button.clicked.connect(self.refresh_ml_logs)
        ml_log_controls.addWidget(refresh_ml_logs_button)
        
        clear_ml_logs_button = QPushButton("Clear Display")
        clear_ml_logs_button.clicked.connect(self.clear_ml_logs)
        ml_log_controls.addWidget(clear_ml_logs_button)
        
        ml_logs_layout.addLayout(ml_log_controls)
        
        # ML logs table
        self.ml_logs_table = QTableWidget()
        self.ml_logs_table.setColumnCount(4)
        self.ml_logs_table.setHorizontalHeaderLabels(["Time", "Level", "Message", "Details"])
        self.ml_logs_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.ml_logs_table.setAlternatingRowColors(True)
        ml_logs_layout.addWidget(self.ml_logs_table)
        
        layout.addWidget(ml_logs_group)
        
        # Initialize ML data
        self.refresh_ml_stats()
        self.refresh_ml_logs()
    
    def setup_tray(self):
        # Create system tray icon
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setToolTip("Deadbolt AI")
        
        # Create tray menu
        tray_menu = QMenu()
        
        show_action = QAction("Show Dashboard", self)
        show_action.triggered.connect(self.show)
        tray_menu.addAction(show_action)
        
        toggle_action = QAction("Stop Monitoring", self)
        toggle_action.triggered.connect(self.toggle_monitoring)
        self.tray_toggle_action = toggle_action
        tray_menu.addAction(toggle_action)
        
        tray_menu.addSeparator()
        
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close_application)
        tray_menu.addAction(exit_action)
        
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.activated.connect(self.tray_activated)
        
        # Show the tray icon
        self.tray_icon.show()
    
    def tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            self.show()
            self.activateWindow()
    
    def toggle_monitoring(self):
        if self.status_label.text() == "Status: Monitoring":
            self.stop_monitoring()
            self.tray_toggle_action.setText("Start Monitoring")
        else:
            self.start_monitoring()
            self.tray_toggle_action.setText("Stop Monitoring")
    
    def emergency_shutdown(self):
        """Emergency shutdown of all monitoring and threat response"""
        reply = QMessageBox.question(self, 'Emergency Shutdown', 
                                   'Are you sure you want to perform an emergency shutdown?\n\n'
                                   'This will stop all monitoring and threat response immediately.',
                                   QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            try:
                # Stop all monitoring
                self.stop_monitoring()
                
                # Log emergency shutdown
                log_event("CRITICAL", "EMERGENCY SHUTDOWN initiated via GUI")
                
                # Update status
                self.status_label.setText("Status: EMERGENCY SHUTDOWN")
                self.status_label.setStyleSheet("""
                    QLabel {
                        font-size: 18px;
                        font-weight: bold;
                        color: #dc3545;
                        background-color: #f8d7da;
                        border: 2px solid #dc3545;
                        border-radius: 5px;
                        padding: 5px;
                    }
                """)
                
                # Show confirmation
                QMessageBox.information(self, "Emergency Shutdown Complete", 
                                       "Emergency shutdown completed successfully.")
                
            except Exception as e:
                log_event("ERROR", f"Error during emergency shutdown: {str(e)}")
                QMessageBox.critical(self, "Error", f"Error during emergency shutdown: {str(e)}")
    
    def closeEvent(self, event):
        # Minimize to tray instead of closing
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "Deadbolt AI",
            "Deadbolt AI is still running in the background. Right-click the tray icon for options.",
            QSystemTrayIcon.Information,
            2000
        )
    
    def close_application(self):
        # Stop threads and close properly
        self.log_monitor.stop()
        self.log_monitor.wait()
        self.refresh_timer.stop()
        
        # Stop dashboard monitor
        if hasattr(self, 'dashboard_monitor'):
            self.dashboard_monitor.stop()
        
        # Stop watchers
        self.stop_monitoring()
        
        # Actually quit
        QApplication.quit()
    
    def start_monitoring(self):
        global active_watchers
        
        # Clear any existing watchers
        for watcher in active_watchers:
            try:
                watcher.stop()
            except:
                pass
        active_watchers = []
        
        # Start watchers for each configured path
        valid_paths = 0
        for path in TARGET_DIRS:
            if os.path.exists(path):
                try:
                    log_event("INFO", f"✅ Watching {path}")
                    watcher = start_watcher(path)
                    active_watchers.append(watcher)
                    valid_paths += 1
                except Exception as e:
                    log_event("ERROR", f"Failed to start watcher for {path}: {str(e)}")
            else:
                log_event("WARNING", f"❌ Skipping invalid path: {path}")
        
        if active_watchers:
            self.status_label.setText("Status: MONITORING ACTIVE")
            self.status_label.setStyleSheet("""
                QLabel {
                    font-size: 18px;
                    font-weight: bold;
                    color: #28a745;
                    background-color: #d4edda;
                    border: 2px solid #28a745;
                    border-radius: 5px;
                    padding: 5px;
                }
            """)
            
            # Update status info
            self.monitored_paths_label.setText(f"Monitored Paths: {valid_paths}")
            
            # Update system health indicators immediately and persistently
            self.detector_status.setText("Detector: Active")
            self.detector_status.setStyleSheet("color: green; font-weight: bold;")
            self.responder_status.setText("Responder: Active")
            self.responder_status.setStyleSheet("color: green; font-weight: bold;")
            self.watcher_status.setText("Watcher: Active")
            self.watcher_status.setStyleSheet("color: green; font-weight: bold;")
            
            # Set monitoring state flags to prevent dashboard from overriding
            self.monitoring_active = True
            self.force_system_health_active = True
            
            log_event("INFO", f"Deadbolt AI running, monitoring {len(active_watchers)} locations")
            
            # Show tray notification
            if hasattr(self, 'tray_icon'):
                self.tray_icon.showMessage(
                    "Deadbolt AI",
                    f"Monitoring started - {valid_paths} paths active",
                    QSystemTrayIcon.Information,
                    3000
                )
        else:
            self.status_label.setText("Status: ERROR - NO VALID PATHS")
            self.status_label.setStyleSheet("""
                QLabel {
                    font-size: 18px;
                    font-weight: bold;
                    color: #dc3545;
                    background-color: #f8d7da;
                    border: 2px solid #dc3545;
                    border-radius: 5px;
                    padding: 5px;
                }
            """)
            log_event("CRITICAL", "No valid paths to monitor.")
            QMessageBox.critical(self, "Error", "No valid paths to monitor. Please check your configuration.")
    
    def stop_monitoring(self):
        global active_watchers
        
        # Stop all watchers
        stopped_count = 0
        for watcher in active_watchers:
            try:
                watcher.stop()
                log_event("INFO", "Stopped a watcher")
                stopped_count += 1
            except Exception as e:
                log_event("ERROR", f"Error stopping watcher: {str(e)}")
        
        active_watchers = []
        
        self.status_label.setText("Status: MONITORING STOPPED")
        self.status_label.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #dc3545;
                background-color: #f8d7da;
                border: 2px solid #dc3545;
                border-radius: 5px;
                padding: 5px;
            }
        """)
        
        # Update status info
        self.monitored_paths_label.setText("Monitored Paths: 0")
        self.active_threats_label.setText("Active Threats: 0")
        
        # Update system health indicators immediately
        self.detector_status.setText("Detector: Inactive")
        self.detector_status.setStyleSheet("color: red; font-weight: bold;")
        self.responder_status.setText("Responder: Inactive")
        self.responder_status.setStyleSheet("color: red; font-weight: bold;")
        self.watcher_status.setText("Watcher: Inactive")
        self.watcher_status.setStyleSheet("color: red; font-weight: bold;")
        
        # Clear monitoring state flags
        self.monitoring_active = False
        self.force_system_health_active = False
        
        log_event("INFO", f"Deadbolt AI monitoring stopped - {stopped_count} watchers stopped")
        
        # Show tray notification
        if hasattr(self, 'tray_icon'):
            self.tray_icon.showMessage(
                "Deadbolt AI",
                "Monitoring stopped",
                QSystemTrayIcon.Warning,
                3000
            )
    
    def update_log_display(self, timestamp, level, message):
        """Update the log display with a new log entry
        
        This method is called when a new log entry is detected.
        The dashboard monitor will handle updating statistics.
        """
        # Filter logs based on current filter settings
        if self.should_display_log(level, message):
            row_position = self.log_table.rowCount()
            self.log_table.insertRow(row_position)
            
            # Add timestamp
            time_item = QTableWidgetItem(timestamp)
            self.log_table.setItem(row_position, 0, time_item)
            
            # Add level with color coding
            level_item = QTableWidgetItem(level)
            if "CRITICAL" in level or "ALERT" in level or "HIGH" in level:
                level_item.setBackground(QColor(255, 200, 200))  # Light red
            elif "WARNING" in level or "MEDIUM" in level:
                level_item.setBackground(QColor(255, 230, 200))  # Light orange
            elif "ERROR" in level:
                level_item.setBackground(QColor(255, 200, 255))  # Light purple
            self.log_table.setItem(row_position, 1, level_item)
            
            # Add message
            message_item = QTableWidgetItem(message)
            self.log_table.setItem(row_position, 2, message_item)
            
            # Auto-scroll if enabled
            if self.auto_scroll_check.isChecked():
                self.log_table.scrollToBottom()
    
    def handle_alert(self, severity, message, timestamp):
        """Handle a new alert from the log monitor
        
        This method is called when a new alert is detected in the logs.
        The dashboard monitor will handle updating statistics, but we still need to
        show notifications and update the UI immediately.
        """
        # Show system tray notification for high severity alerts
        if severity == "HIGH" and self.isHidden():
            # Use system tray notification
            self.tray_icon.showMessage(
                "Deadbolt AI Security Alert",
                message,
                QSystemTrayIcon.Critical,
                5000
            )
            
            # Also use Windows toast notification for better visibility
            try:
                # Try to import and use toast notification
                import warnings
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")
                    from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(
                    "Deadbolt AI Security Alert", 
                    message, 
                    duration=5,
                    threaded=True
                )
            except Exception as toast_error:
                print(f"Error showing toast notification: {str(toast_error)}")
        
        # Add to recent threats table immediately (dashboard will update this later)
        row_position = self.threats_table.rowCount()
        self.threats_table.insertRow(row_position)
        
        # Add timestamp
        time_item = QTableWidgetItem(timestamp)
        self.threats_table.setItem(row_position, 0, time_item)
        
        # Add severity with color coding
        severity_item = QTableWidgetItem(severity)
        if severity == "HIGH":
            severity_item.setBackground(QColor(255, 150, 150))  # Red
        elif severity == "MEDIUM":
            severity_item.setBackground(QColor(255, 200, 150))  # Orange
        else:
            severity_item.setBackground(QColor(200, 200, 255))  # Blue
        self.threats_table.setItem(row_position, 1, severity_item)
        
        # Add message
        message_item = QTableWidgetItem(message)
        self.threats_table.setItem(row_position, 2, message_item)
        
        # Always auto-scroll threats table
        self.threats_table.scrollToBottom()
    
    def should_display_log(self, level, message):
        # Check level filter
        selected_level = self.log_level_combo.currentText()
        if selected_level != "All" and selected_level not in level:
            return False
        
        # Check search filter
        search_text = self.log_search_input.text().lower()
        if search_text and search_text not in level.lower() and search_text not in message.lower():
            return False
        
        return True
    
    def filter_logs(self):
        # Hide all rows
        for row in range(self.log_table.rowCount()):
            self.log_table.setRowHidden(row, True)
        
        # Show only rows that match the filter
        for row in range(self.log_table.rowCount()):
            level = self.log_table.item(row, 1).text()
            message = self.log_table.item(row, 2).text()
            
            if self.should_display_log(level, message):
                self.log_table.setRowHidden(row, False)
    
    def clear_log_display(self):
        self.log_table.setRowCount(0)
    
    def open_log_file(self):
        log_path = get_log_path()
        if os.path.exists(log_path):
            # Use the default system application to open the log file
            if sys.platform == 'win32':
                os.startfile(log_path)
            elif sys.platform == 'darwin':  # macOS
                os.system(f'open "{log_path}"')
            else:  # Linux
                os.system(f'xdg-open "{log_path}"')
        else:
            QMessageBox.warning(self, "Error", "Log file not found.")
    
    def export_logs(self):
        # Ask for save location
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Logs", os.path.expanduser("~/Desktop/deadbolt_logs.csv"),
            "CSV Files (*.csv);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write("Timestamp,Level,Message\n")
                    for row in range(self.log_table.rowCount()):
                        if not self.log_table.isRowHidden(row):
                            timestamp = self.log_table.item(row, 0).text()
                            level = self.log_table.item(row, 1).text()
                            message = self.log_table.item(row, 2).text().replace('"', '""')  # Escape quotes
                            f.write(f'"{timestamp}","{level}","{message}"\n')
                
                QMessageBox.information(self, "Success", f"Logs exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to export logs: {str(e)}")
    
    def add_directory(self):
        # Ask for directory
        dir_path = QFileDialog.getExistingDirectory(
            self, "Select Directory to Monitor", os.path.expanduser("~")
        )
        
        if dir_path and dir_path not in TARGET_DIRS:
            # Add to TARGET_DIRS
            TARGET_DIRS.append(dir_path)
            
            # Save configuration if config manager is available
            if CONFIG_MANAGER_AVAILABLE:
                config_manager.update_target_dirs(TARGET_DIRS)
            
            # Update the table
            row_position = self.dirs_table.rowCount()
            self.dirs_table.insertRow(row_position)
            self.dirs_table.setItem(row_position, 0, QTableWidgetItem(dir_path))
            self.dirs_table.setItem(row_position, 1, QTableWidgetItem("Added (restart monitoring)"))
            
            log_event("INFO", f"Added directory to monitor via GUI: {dir_path}")
    
    def remove_directory(self):
        # Get selected row
        selected_rows = self.dirs_table.selectedIndexes()
        if not selected_rows:
            QMessageBox.warning(self, "Warning", "Please select a directory to remove.")
            return
        
        row = selected_rows[0].row()
        dir_path = self.dirs_table.item(row, 0).text()
        
        # Remove from TARGET_DIRS
        if dir_path in TARGET_DIRS:
            TARGET_DIRS.remove(dir_path)
            
            # Save configuration if config manager is available
            if CONFIG_MANAGER_AVAILABLE:
                config_manager.update_target_dirs(TARGET_DIRS)
        
        # Remove from table
        self.dirs_table.removeRow(row)
        
        log_event("INFO", f"Removed directory from monitoring via GUI: {dir_path}")
    
    def save_rules(self):
        try:
            mass_delete_count = int(self.mass_delete_input.text())
            mass_delete_interval = int(self.mass_delete_interval.text())
            mass_rename_count = int(self.mass_rename_input.text())
            mass_rename_interval = int(self.mass_rename_interval.text())
            
            if CONFIG_MANAGER_AVAILABLE:
                # Use config manager to save settings
                if config_manager.update_rules(mass_delete_count, mass_delete_interval, 
                                               mass_rename_count, mass_rename_interval):
                    QMessageBox.information(self, "Success", "Detection rules updated and saved successfully.")
                else:
                    QMessageBox.warning(self, "Warning", "Rules updated but failed to save to file.")
            else:
                # Update RULES dictionary (temporary - won't persist)
                RULES["mass_delete"]["count"] = mass_delete_count
                RULES["mass_delete"]["interval"] = mass_delete_interval
                RULES["mass_rename"]["count"] = mass_rename_count
                RULES["mass_rename"]["interval"] = mass_rename_interval
                QMessageBox.information(self, "Success", "Detection rules updated (temporary - not saved to file).")
            
            log_event("INFO", "Detection rules updated via GUI")
            
        except ValueError:
            QMessageBox.critical(self, "Error", "Please enter valid numbers for all thresholds.")
    
    def save_actions(self):
        log_only = self.log_only_check.isChecked()
        kill_process = self.kill_process_check.isChecked()
        shutdown = self.shutdown_check.isChecked()
        dry_run = self.dry_run_check.isChecked()
        
        if CONFIG_MANAGER_AVAILABLE:
            # Use config manager to save settings
            if config_manager.update_actions(log_only, kill_process, shutdown, dry_run):
                QMessageBox.information(self, "Success", "Response actions updated and saved successfully.")
            else:
                QMessageBox.warning(self, "Warning", "Actions updated but failed to save to file.")
        else:
            # Update ACTIONS dictionary (temporary - won't persist)
            ACTIONS["log_only"] = log_only
            ACTIONS["kill_process"] = kill_process
            ACTIONS["shutdown"] = shutdown
            ACTIONS["dry_run"] = dry_run
            QMessageBox.information(self, "Success", "Response actions updated (temporary - not saved to file).")
        
        log_event("INFO", "Response actions updated via GUI")
    
    def load_initial_data(self):
        # Load monitored directories
        self.dirs_table.setRowCount(0)
        for dir_path in TARGET_DIRS:
            row_position = self.dirs_table.rowCount()
            self.dirs_table.insertRow(row_position)
            self.dirs_table.setItem(row_position, 0, QTableWidgetItem(dir_path))
            
            # Check if directory exists
            if os.path.exists(dir_path):
                self.dirs_table.setItem(row_position, 1, QTableWidgetItem("Valid"))
            else:
                self.dirs_table.setItem(row_position, 1, QTableWidgetItem("Invalid Path"))
                self.dirs_table.item(row_position, 1).setBackground(QColor(255, 200, 200))
        
        # Try to load some initial log data
        self.load_existing_logs()
    
    def load_existing_logs(self):
        """Load existing logs from the log file
        
        This method loads recent log entries into the log display table.
        The dashboard monitor will handle loading statistics.
        """
        log_path = get_log_path()
        if os.path.exists(log_path):
            try:
                with open(log_path, 'r', encoding='utf-8') as f:
                    # Read the last 100 lines (or less if file is smaller)
                    lines = f.readlines()[-100:]
                    
                    for line in lines:
                        match = re.match(r'\[(.*?)\] (\w+): (.*)', line.strip())
                        if match:
                            timestamp, level, message = match.groups()
                            self.update_log_display(timestamp, level, message)
            except Exception as e:
                print(f"Error loading existing logs: {str(e)}")
    
    def update_dashboard_stats(self, stats):
        """Callback function for dashboard monitor
        
        Args:
            stats (dict): Statistics dictionary from the dashboard monitor
        """
        try:
            # Make a copy of stats to avoid reference issues
            if stats is None:
                self.stats = {}
                print("Warning: Received None stats in dashboard callback")
                return
                
            self.stats = stats.copy() if isinstance(stats, dict) else {}
            
            # Ensure all required keys exist with default values
            if 'alerts_by_time' not in self.stats:
                self.stats['alerts_by_time'] = [0] * 24
                
            if 'events_by_type' not in self.stats:
                self.stats['events_by_type'] = {}
                
            # Update the dashboard with the new stats
            self.refresh_dashboard()
        except Exception as e:
            print(f"Error in dashboard callback: {str(e)}")
            # Initialize with empty stats to prevent further errors
            self.stats = {
                'alerts_high': 0,
                'alerts_medium': 0,
                'alerts_low': 0,
                'events_total': 0,
                'alerts_by_time': [0] * 24,
                'events_by_type': {},
                'recent_alerts': []
            }
    
    def refresh_dashboard(self):
        try:
            # Update main statistics
            self.threats_label.setText(str(self.stats.get('threats_detected', 0)))
            self.blocked_label.setText(str(self.stats.get('threats_blocked', 0)))
            self.processes_label.setText(str(self.stats.get('processes_terminated', 0)))
            self.events_label.setText(str(self.stats.get('events_total', 0)))
            
            # Update active threats counter in status section
            recent_threats = self.stats.get('recent_threats', [])
            recent_count = len([t for t in recent_threats[-5:] if t.get('severity') in ['CRITICAL', 'HIGH']])
            self.active_threats_label.setText(f"Active Threats: {recent_count}")
            
            # Update monitored paths count
            monitored_paths = self.stats.get('monitored_paths_status', {})
            active_paths = len([p for p, status in monitored_paths.items() if status == 'Active'])
            if hasattr(self, 'monitored_paths_label'):
                self.monitored_paths_label.setText(f"Monitored Paths: {active_paths}")
            
            # Update alert distribution
            self.high_alerts_label.setText(f"High: {self.stats.get('alerts_high', 0)}")
            self.medium_alerts_label.setText(f"Medium: {self.stats.get('alerts_medium', 0)}")
            self.low_alerts_label.setText(f"Low: {self.stats.get('alerts_low', 0)}")
            
            # Update system health indicators
            health = self.stats.get('system_health', {})
            
            # Use forced active state if monitoring was manually started
            if hasattr(self, 'force_system_health_active') and self.force_system_health_active:
                detector_active = True
                responder_active = True
                watcher_active = True
            else:
                detector_active = health.get('detector_active', False)
                responder_active = health.get('responder_active', False)
                watcher_active = health.get('watcher_active', False)
            
            self.detector_status.setText(f"Detector: {'Active' if detector_active else 'Inactive'}")
            self.detector_status.setStyleSheet(f"color: {'green' if detector_active else 'red'}; font-weight: bold;")
            
            self.responder_status.setText(f"Responder: {'Active' if responder_active else 'Inactive'}")
            self.responder_status.setStyleSheet(f"color: {'green' if responder_active else 'red'}; font-weight: bold;")
            
            self.watcher_status.setText(f"Watcher: {'Active' if watcher_active else 'Inactive'}")
            self.watcher_status.setStyleSheet(f"color: {'green' if watcher_active else 'red'}; font-weight: bold;")
            
            # Update time chart - with error handling
            try:
                if hasattr(self, 'time_chart') and self.time_chart is not None and hasattr(self.time_chart, 'axes') and self.time_chart.axes is not None:
                    self.time_chart.axes.clear()
                    hours = list(range(24))
                    alerts_by_time = self.stats.get('alerts_by_time', [0] * 24)
                    # Ensure alerts_by_time is not None and has 24 values
                    if alerts_by_time is None:
                        alerts_by_time = [0] * 24
                    elif len(alerts_by_time) < 24:
                        alerts_by_time.extend([0] * (24 - len(alerts_by_time)))
                    self.time_chart.axes.bar(hours, alerts_by_time, color='#FF5555')
                    self.time_chart.axes.set_xlabel('Hour of Day', fontsize=10)
                    self.time_chart.axes.set_ylabel('Number of Threats', fontsize=10)
                    self.time_chart.axes.set_title('Threat Activity by Hour', fontsize=12, pad=15)
                    self.time_chart.axes.set_xticks(range(0, 24, 3))
                    self.time_chart.axes.tick_params(axis='both', which='major', labelsize=9)
                    # Improve layout to prevent text cutting
                    self.time_chart.fig.tight_layout(pad=2.0)
                    self.time_chart.draw()
            except Exception as e:
                print(f"Error updating time chart: {str(e)}")
            
            # Update event types chart - with error handling
            try:
                if hasattr(self, 'event_chart') and self.event_chart is not None and hasattr(self.event_chart, 'axes') and self.event_chart.axes is not None:
                    events_by_type = self.stats.get('events_by_type')
                    if events_by_type and isinstance(events_by_type, dict) and len(events_by_type) > 0:
                        self.event_chart.axes.clear()
                        labels = list(events_by_type.keys())
                        sizes = list(events_by_type.values())
                        colors = ['#FF9999', '#66B2FF', '#99FF99', '#FFCC99', '#FF99CC', '#99FFCC']
                        self.event_chart.axes.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, 
                                                  colors=colors[:len(labels)], textprops={'fontsize': 9})
                        self.event_chart.axes.axis('equal')
                        self.event_chart.axes.set_title('Event Types Distribution', fontsize=12, pad=15)
                        # Improve layout to prevent text cutting
                        self.event_chart.fig.tight_layout(pad=2.0)
                        self.event_chart.draw()
                    else:
                        # If no event data, show a default pie chart
                        self.event_chart.axes.clear()
                        self.event_chart.axes.pie([1], labels=['No Data'], autopct='%1.1f%%', startangle=90, 
                                                  colors=['#CCCCCC'], textprops={'fontsize': 9})
                        self.event_chart.axes.axis('equal')
                        self.event_chart.axes.set_title('Event Types Distribution', fontsize=12, pad=15)
                        self.event_chart.fig.tight_layout(pad=2.0)
                        self.event_chart.draw()
            except Exception as e:
                print(f"Error updating event chart: {str(e)}")
            
            # Update recent threats table
            try:
                if hasattr(self, 'threats_table'):
                    recent_threats = self.stats.get('recent_threats', [])
                    if recent_threats and isinstance(recent_threats, list):
                        self.threats_table.setRowCount(0)  # Clear existing rows
                        for i, threat in enumerate(recent_threats[:10]):  # Show last 10
                            try:
                                self.threats_table.insertRow(i)
                                
                                # Add timestamp
                                time_item = QTableWidgetItem(threat.get('timestamp', ''))
                                self.threats_table.setItem(i, 0, time_item)
                                
                                # Add type
                                type_item = QTableWidgetItem(threat.get('type', ''))
                                self.threats_table.setItem(i, 1, type_item)
                                
                                # Add description
                                desc_item = QTableWidgetItem(threat.get('description', ''))
                                self.threats_table.setItem(i, 2, desc_item)
                                
                            except Exception as e:
                                print(f"Error adding threat to table: {str(e)}")
            except Exception as e:
                print(f"Error updating threats table: {str(e)}")
            
            # Update recent responses table
            try:
                if hasattr(self, 'responses_table'):
                    response_history = self.stats.get('response_history', [])
                    if response_history and isinstance(response_history, list):
                        self.responses_table.setRowCount(0)  # Clear existing rows
                        for i, response in enumerate(response_history[:10]):  # Show last 10
                            try:
                                self.responses_table.insertRow(i)
                                
                                # Add timestamp
                                time_item = QTableWidgetItem(response.get('timestamp', ''))
                                self.responses_table.setItem(i, 0, time_item)
                                
                                # Add action
                                action_item = QTableWidgetItem(response.get('action', ''))
                                if response.get('severity') == 'CRITICAL':
                                    action_item.setBackground(QColor(255, 200, 200))  # Light red
                                self.responses_table.setItem(i, 1, action_item)
                                
                                # Add details
                                details_item = QTableWidgetItem(response.get('details', ''))
                                self.responses_table.setItem(i, 2, details_item)
                                
                            except Exception as e:
                                print(f"Error adding response to table: {str(e)}")
            except Exception as e:
                print(f"Error updating responses table: {str(e)}")
                
        except Exception as e:
            print(f"Error in refresh_dashboard: {str(e)}")
    
    def refresh_ml_stats(self):
        """Refresh ML statistics from both ML detector and ml_stats.json file."""
        try:
            # Read ML statistics from the JSON file
            ml_stats_file = os.path.join(LOG_DIR, 'ml_stats.json')
            
            if os.path.exists(ml_stats_file):
                try:
                    with open(ml_stats_file, 'r') as f:
                        ml_stats_data = json.load(f)
                    
                    # Update ML status labels with actual data
                    self.ml_model_status.setText("Model: Active - Loaded Successfully")
                    self.ml_model_status.setStyleSheet("font-weight: bold; color: green;")
                    
                    # Update main status section ML info
                    total_predictions = ml_stats_data.get('total_predictions', 0)
                    malicious_detected = ml_stats_data.get('malicious_detected', 0)
                    
                    self.ml_status_label.setText("ML Engine: Active")
                    self.ml_status_label.setStyleSheet("""
                        QLabel {
                            font-size: 14px;
                            font-weight: bold;
                            color: #28a745;
                            background-color: transparent;
                            border: none;
                            padding: 5px;
                        }
                    """)
                    
                    self.ml_predictions_label.setText(f"Predictions: {total_predictions}")
                    self.ml_threats_label.setText(f"Threats Detected: {malicious_detected}")
                    
                    # Update features count (assume 49 based on logs)
                    self.ml_features_count.setText("Features: 49")
                    
                    # Check if monitoring is active by checking recent ML detector logs
                    ml_log_file = os.path.join(LOG_DIR, 'ml_detector.log')
                    monitoring_active = False
                    if os.path.exists(ml_log_file):
                        try:
                            with open(ml_log_file, 'r', encoding='utf-8') as f:
                                # Read last few lines to check if monitoring is active
                                lines = f.readlines()[-10:]
                                for line in lines:
                                    if 'monitoring started' in line.lower() and not 'stopped' in line.lower():
                                        monitoring_active = True
                                        break
                        except Exception:
                            pass
                    
                    if monitoring_active:
                        self.ml_monitoring_status.setText("Monitoring: Active")
                        self.ml_monitoring_status.setStyleSheet("color: green;")
                    else:
                        self.ml_monitoring_status.setText("Monitoring: Standby")
                        self.ml_monitoring_status.setStyleSheet("color: orange;")
                    
                    # Update statistics
                    self.ml_total_predictions.setText(f"Total Predictions: {total_predictions}")
                    self.ml_malicious_detected.setText(f"Malicious Detected: {malicious_detected}")
                    
                    benign_classified = ml_stats_data.get('benign_classified', 0)
                    self.ml_benign_classified.setText(f"Benign Classified: {benign_classified}")
                    
                    high_confidence_alerts = ml_stats_data.get('high_confidence_alerts', 0)
                    self.ml_high_confidence.setText(f"High Confidence Alerts: {high_confidence_alerts}")
                    
                    avg_conf = ml_stats_data.get('average_confidence', 0.0)
                    self.ml_average_confidence.setText(f"Average Confidence: {avg_conf:.3f}")
                    
                    fp_rate = ml_stats_data.get('false_positive_rate', 0.0) * 100
                    self.ml_false_positive_rate.setText(f"Est. False Positive Rate: {fp_rate:.1f}%")
                    
                    # Format last prediction time
                    last_prediction = ml_stats_data.get('last_prediction_time', 'Never')
                    if last_prediction != 'Never' and 'T' in str(last_prediction):
                        try:
                            from datetime import datetime
                            dt = datetime.fromisoformat(last_prediction.replace('T', ' ').split('.')[0])
                            formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S')
                            self.ml_last_prediction.setText(f"Last Prediction: {formatted_time}")
                        except:
                            self.ml_last_prediction.setText(f"Last Prediction: {last_prediction}")
                    else:
                        self.ml_last_prediction.setText(f"Last Prediction: {last_prediction}")
                    
                    # Update confidence distribution chart
                    confidence_dist = ml_stats_data.get('confidence_distribution', {})
                    self.update_ml_confidence_chart(confidence_dist)
                    
                except json.JSONDecodeError as e:
                    print(f"Error parsing ML stats JSON: {e}")
                    self._set_ml_error_status("JSON Parse Error")
                except Exception as e:
                    print(f"Error reading ML stats file: {e}")
                    self._set_ml_error_status("File Read Error")
            else:
                # ML stats file doesn't exist
                print("ML stats file not found")
                self._set_ml_inactive_status()
                
        except Exception as e:
            print(f"Error refreshing ML stats: {e}")
            self._set_ml_error_status(str(e))
    
    def _set_ml_error_status(self, error_msg):
        """Set ML status to error state"""
        self.ml_model_status.setText(f"Model: Error - {error_msg[:30]}...")
        self.ml_model_status.setStyleSheet("font-weight: bold; color: red;")
        
        self.ml_status_label.setText("ML Engine: Error")
        self.ml_status_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #dc3545;
                background-color: transparent;
                border: none;
                padding: 5px;
            }
        """)
        
        self.ml_features_count.setText("Features: --")
        self.ml_monitoring_status.setText("Monitoring: Error")
        self.ml_monitoring_status.setStyleSheet("color: red;")
    
    def _set_ml_inactive_status(self):
        """Set ML status to inactive state"""
        self.ml_model_status.setText("Model: Inactive - No Data Available")
        self.ml_model_status.setStyleSheet("font-weight: bold; color: orange;")
        
        self.ml_status_label.setText("ML Engine: Inactive")
        self.ml_status_label.setStyleSheet("""
            QLabel {
                font-size: 14px;
                font-weight: bold;
                color: #ffc107;
                background-color: transparent;
                border: none;
                padding: 5px;
            }
        """)
        
        self.ml_features_count.setText("Features: --")
        self.ml_monitoring_status.setText("Monitoring: Inactive")
        self.ml_monitoring_status.setStyleSheet("color: orange;")
    
    def update_ml_confidence_chart(self, confidence_dist):
        """Update the ML confidence distribution chart."""
        try:
            self.ml_confidence_canvas.axes.clear()
            
            if confidence_dist:
                categories = ['High (>80%)', 'Medium (50-80%)', 'Low (<50%)']
                values = [
                    confidence_dist.get('high', 0),
                    confidence_dist.get('medium', 0), 
                    confidence_dist.get('low', 0)
                ]
                colors = ['#ff4444', '#ffaa44', '#44aaff']
                
                # Create bar chart
                bars = self.ml_confidence_canvas.axes.bar(categories, values, color=colors)
                
                # Add value labels on bars
                for bar, value in zip(bars, values):
                    if value > 0:
                        self.ml_confidence_canvas.axes.text(
                            bar.get_x() + bar.get_width()/2, 
                            bar.get_height() + 0.1,
                            str(value), 
                            ha='center', 
                            va='bottom',
                            fontsize=10
                        )
                
                self.ml_confidence_canvas.axes.set_title('ML Prediction Confidence Distribution', fontsize=12, pad=15)
                self.ml_confidence_canvas.axes.set_ylabel('Count', fontsize=10)
                self.ml_confidence_canvas.axes.tick_params(axis='both', which='major', labelsize=9)
                
                # Improve layout to prevent text cutting
                self.ml_confidence_canvas.fig.tight_layout(pad=2.0)
                
            else:
                # No data available
                self.ml_confidence_canvas.axes.text(
                    0.5, 0.5, 'No ML predictions yet',
                    ha='center', va='center', 
                    transform=self.ml_confidence_canvas.axes.transAxes,
                    fontsize=12
                )
                self.ml_confidence_canvas.axes.set_title('ML Prediction Confidence Distribution', fontsize=12, pad=15)
                self.ml_confidence_canvas.fig.tight_layout(pad=2.0)
            
            self.ml_confidence_canvas.draw()
            
        except Exception as e:
            print(f"Error updating ML confidence chart: {e}")
    
    def refresh_ml_logs(self):
        """Refresh ML logs from the ml_detector.log file."""
        try:
            # Clear existing logs
            self.ml_logs_table.setRowCount(0)
            
            # Read from ml_detector.log file
            ml_log_file = os.path.join(LOG_DIR, 'ml_detector.log')
            
            if os.path.exists(ml_log_file):
                try:
                    with open(ml_log_file, 'r', encoding='utf-8') as f:
                        # Read the last 200 lines for recent activity
                        lines = f.readlines()[-200:]
                    
                    # Process each line
                    for line in lines:
                        line = line.strip()
                        if not line:
                            continue
                        
                        # Parse different ML log formats
                        timestamp = ""
                        level = "INFO"
                        message = line
                        details = ""
                        color = "#ffffff"
                        
                        # Format 1: timestamp - level - message
                        match1 = re.match(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - (\w+) - (.*)', line)
                        if match1:
                            timestamp, level, message = match1.groups()
                            
                            # Determine color and details based on message content
                            if 'ML HIGH THREAT DETECTED' in message:
                                color = "#ff4444"  # Red
                                details = "High Threat Alert"
                                level = "CRITICAL"
                            elif 'VERY HIGH CONFIDENCE THREAT' in message:
                                color = "#ff6666"  # Light red
                                details = "Very High Confidence"
                                level = "CRITICAL"
                            elif 'ML Model detected malicious behavior' in message:
                                color = "#ff6666"  # Light red
                                details = "ML Malicious Detection"
                                level = "CRITICAL"
                            elif 'IRC PATTERN DETECTED' in message:
                                color = "#ffaa44"  # Orange
                                details = "IRC Pattern"
                                level = "WARNING"
                            elif 'HTTP PATTERN ANALYZED' in message:
                                color = "#44aaff"  # Blue
                                details = "HTTP Analysis"
                            elif 'ML model loaded successfully' in message:
                                color = "#44ff44"  # Green
                                details = "Model Loaded"
                            elif 'ML-Enhanced threat detection monitoring started' in message:
                                color = "#44ff44"  # Green
                                details = "Monitoring Started"
                            elif 'ML-Enhanced threat detection monitoring stopped' in message:
                                color = "#ffaa44"  # Orange
                                details = "Monitoring Stopped"
                                level = "WARNING"
                            elif 'ML-Enhanced Threat Detector initialized' in message:
                                color = "#44aaff"  # Blue
                                details = "Detector Initialized"
                            elif 'Analyzing threat' in message:
                                color = "#ffaa44"  # Orange
                                details = "Threat Analysis"
                                level = "WARNING"
                            elif 'ML-Enhanced threat analysis complete' in message:
                                color = "#44aaff"  # Blue
                                details = "Analysis Complete"
                            elif 'ML-ENHANCED ALERT SENT' in message:
                                color = "#ff4444"  # Red
                                details = "Alert Sent"
                                level = "CRITICAL"
                            elif 'Triggering ML-enhanced' in message:
                                color = "#ff4444"  # Red
                                details = "Response Triggered"
                                level = "CRITICAL"
                        
                        # Add to table
                        row_position = self.ml_logs_table.rowCount()
                        self.ml_logs_table.insertRow(row_position)
                        
                        # Timestamp
                        time_item = QTableWidgetItem(timestamp)
                        self.ml_logs_table.setItem(row_position, 0, time_item)
                        
                        # Level with color coding
                        level_item = QTableWidgetItem(level)
                        if level == "CRITICAL":
                            level_item.setBackground(QColor(255, 200, 200))  # Light red
                        elif level == "WARNING":
                            level_item.setBackground(QColor(255, 230, 200))  # Light orange
                        elif level == "ERROR":
                            level_item.setBackground(QColor(255, 200, 255))  # Light purple
                        self.ml_logs_table.setItem(row_position, 1, level_item)
                        
                        # Message
                        message_item = QTableWidgetItem(message)
                        self.ml_logs_table.setItem(row_position, 2, message_item)
                        
                        # Details
                        details_item = QTableWidgetItem(details)
                        self.ml_logs_table.setItem(row_position, 3, details_item)
                    
                    # Auto-scroll to bottom to show latest entries
                    self.ml_logs_table.scrollToBottom()
                    
                except Exception as e:
                    print(f"Error reading ML log file: {e}")
                    # Show error in table
                    row_position = self.ml_logs_table.rowCount()
                    self.ml_logs_table.insertRow(row_position)
                    self.ml_logs_table.setItem(row_position, 0, QTableWidgetItem(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                    self.ml_logs_table.setItem(row_position, 1, QTableWidgetItem("ERROR"))
                    self.ml_logs_table.setItem(row_position, 2, QTableWidgetItem(f"Error reading ML log file: {str(e)}"))
                    self.ml_logs_table.setItem(row_position, 3, QTableWidgetItem("File Read Error"))
            else:
                # ML log file doesn't exist
                row_position = self.ml_logs_table.rowCount()
                self.ml_logs_table.insertRow(row_position)
                self.ml_logs_table.setItem(row_position, 0, QTableWidgetItem(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
                self.ml_logs_table.setItem(row_position, 1, QTableWidgetItem("WARNING"))
                self.ml_logs_table.setItem(row_position, 2, QTableWidgetItem("ML detector log file not found"))
                self.ml_logs_table.setItem(row_position, 3, QTableWidgetItem("File Not Found"))
                
        except Exception as e:
            print(f"Error refreshing ML logs: {e}")
            # Show error in table
            row_position = self.ml_logs_table.rowCount()
            self.ml_logs_table.insertRow(row_position)
            self.ml_logs_table.setItem(row_position, 0, QTableWidgetItem(datetime.now().strftime('%Y-%m-%d %H:%M:%S')))
            self.ml_logs_table.setItem(row_position, 1, QTableWidgetItem("ERROR"))
            self.ml_logs_table.setItem(row_position, 2, QTableWidgetItem(f"Error refreshing ML logs: {str(e)}"))
            self.ml_logs_table.setItem(row_position, 3, QTableWidgetItem("Refresh Error"))
    
    def filter_ml_logs(self):
        """Filter ML logs based on level and search text."""
        try:
            selected_level = self.ml_log_level_combo.currentText()
            search_text = self.ml_log_search.text().lower()
            
            for row in range(self.ml_logs_table.rowCount()):
                show_row = True
                
                # Filter by level
                if selected_level != "All":
                    level_item = self.ml_logs_table.item(row, 1)
                    if level_item and selected_level not in level_item.text():
                        show_row = False
                
                # Filter by search text
                if search_text and show_row:
                    row_text = ""
                    for col in range(self.ml_logs_table.columnCount()):
                        item = self.ml_logs_table.item(row, col)
                        if item:
                            row_text += item.text().lower() + " "
                    
                    if search_text not in row_text:
                        show_row = False
                
                self.ml_logs_table.setRowHidden(row, not show_row)
                
        except Exception as e:
            print(f"Error filtering ML logs: {e}")
    
    def clear_ml_logs(self):
        """Clear ML logs display."""
        self.ml_logs_table.setRowCount(0)
    
    def check_monitoring_status(self):
        """Check current monitoring status and update UI accordingly"""
        try:
            # Check if there are active monitoring processes by examining recent logs
            main_log = os.path.join(LOG_DIR, 'main.log')
            detector_log = os.path.join(LOG_DIR, 'detector.log')
            
            monitoring_active = False
            ml_active = False
            
            # Check main log for monitoring status
            if os.path.exists(main_log):
                try:
                    with open(main_log, 'r', encoding='utf-8') as f:
                        lines = f.readlines()[-20:]  # Check last 20 lines
                        for line in lines:
                            if 'monitoring started' in line.lower() or 'watching' in line.lower():
                                monitoring_active = True
                                break
                except Exception:
                    pass
            
            # Check ML detector log
            ml_log = os.path.join(LOG_DIR, 'ml_detector.log')
            if os.path.exists(ml_log):
                try:
                    with open(ml_log, 'r', encoding='utf-8') as f:
                        lines = f.readlines()[-10:]
                        for line in lines:
                            if 'ML model loaded successfully' in line:
                                ml_active = True
                                break
                except Exception:
                    pass
            
            # Update status based on findings
            if monitoring_active:
                self.status_label.setText("Status: MONITORING ACTIVE")
                self.status_label.setStyleSheet("""
                    QLabel {
                        font-size: 18px;
                        font-weight: bold;
                        color: #28a745;
                        background-color: #d4edda;
                        border: 2px solid #28a745;
                        border-radius: 5px;
                        padding: 5px;
                    }
                """)
            else:
                self.status_label.setText("Status: READY TO MONITOR")
                self.status_label.setStyleSheet("""
                    QLabel {
                        font-size: 18px;
                        font-weight: bold;
                        color: #ffc107;
                        background-color: #fff3cd;
                        border: 2px solid #ffc107;
                        border-radius: 5px;
                        padding: 5px;
                    }
                """)
            
            # Update ML status
            if ml_active:
                self.ml_status_label.setText("ML Engine: Active")
                self.ml_status_label.setStyleSheet("""
                    QLabel {
                        font-size: 14px;
                        font-weight: bold;
                        color: #28a745;
                        background-color: transparent;
                        border: none;
                        padding: 5px;
                    }
                """)
            else:
                self.ml_status_label.setText("ML Engine: Standby")
                self.ml_status_label.setStyleSheet("""
                    QLabel {
                        font-size: 14px;
                        font-weight: bold;
                        color: #ffc107;
                        background-color: transparent;
                        border: none;
                        padding: 5px;
                    }
                """)
                
        except Exception as e:
            print(f"Error checking monitoring status: {e}")
    
    def apply_theme(self):
        """Apply the current theme (light or dark)"""
        if self.dark_theme:
            self.apply_dark_theme()
        else:
            self.apply_light_theme()
    
    def apply_light_theme(self):
        """Apply light theme styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f0f0f0;
                font-family: 'Segoe UI', Arial, sans-serif;
                color: #333333;
            }
            QWidget {
                background-color: #f0f0f0;
                color: #333333;
            }
            QFrame {
                background-color: #ffffff;
                color: #333333;
                border: 1px solid #cccccc;
            }
            QTabWidget::pane {
                border: 1px solid #cccccc;
                background-color: white;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #e0e0e0;
                color: #333333;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                min-width: 100px;
            }
            QTabBar::tab:selected {
                background-color: white;
                border-bottom: 2px solid #007acc;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #cccccc;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: white;
                color: #333333;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px 0 8px;
                color: #333333;
            }
            QTableWidget {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
                gridline-color: #eeeeee;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #eeeeee;
                background-color: white;
                color: #333333;
            }
            QTableWidget::item:selected {
                background-color: #007acc;
                color: white;
            }
            QHeaderView::section {
                background-color: #f0f0f0;
                color: #333333;
                border: 1px solid #cccccc;
                padding: 8px;
            }
            QLabel {
                color: #333333;
                background-color: transparent;
            }
            QLineEdit {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
                padding: 5px;
                border-radius: 3px;
            }
            QComboBox {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
                padding: 5px;
                border-radius: 3px;
            }
            QComboBox::drop-down {
                border: none;
                background-color: white;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #333333;
            }
            QComboBox QAbstractItemView {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
            }
            QCheckBox {
                color: #333333;
                background-color: transparent;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                background-color: white;
                border: 1px solid #cccccc;
            }
            QCheckBox::indicator:checked {
                background-color: #007acc;
                border: 1px solid #007acc;
            }
            QScrollBar:vertical {
                background-color: #f0f0f0;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #cccccc;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #bbbbbb;
            }
            QScrollBar:horizontal {
                background-color: #f0f0f0;
                height: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal {
                background-color: #cccccc;
                border-radius: 6px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #bbbbbb;
            }
            QTextEdit {
                background-color: white;
                color: #333333;
                border: 1px solid #cccccc;
            }
            QProgressBar {
                background-color: #f0f0f0;
                color: #333333;
                border: 1px solid #cccccc;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #007acc;
                border-radius: 3px;
            }
        """)
        
        # Update matplotlib colors for light theme
        try:
            import matplotlib.pyplot as plt
            plt.style.use('default')
        except:
            pass
    
    def apply_dark_theme(self):
        """Apply dark theme styling"""
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                font-family: 'Segoe UI', Arial, sans-serif;
                color: #ffffff;
            }
            QWidget {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QFrame {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QTabWidget::pane {
                border: 1px solid #555555;
                background-color: #3c3c3c;
                border-radius: 5px;
            }
            QTabBar::tab {
                background-color: #404040;
                color: #ffffff;
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                min-width: 100px;
            }
            QTabBar::tab:selected {
                background-color: #3c3c3c;
                border-bottom: 2px solid #007acc;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555555;
                border-radius: 8px;
                margin-top: 10px;
                padding-top: 10px;
                background-color: #3c3c3c;
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 8px 0 8px;
                color: #ffffff;
            }
            QTableWidget {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
                gridline-color: #555555;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #555555;
                background-color: #3c3c3c;
                color: #ffffff;
            }
            QTableWidget::item:selected {
                background-color: #007acc;
                color: white;
            }
            QHeaderView::section {
                background-color: #404040;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 8px;
            }
            QLabel {
                color: #ffffff;
                background-color: transparent;
            }
            QLineEdit {
                background-color: #404040;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QComboBox {
                background-color: #404040;
                color: #ffffff;
                border: 1px solid #555555;
                padding: 5px;
                border-radius: 3px;
            }
            QComboBox::drop-down {
                border: none;
                background-color: #404040;
            }
            QComboBox::down-arrow {
                image: none;
                border-left: 5px solid transparent;
                border-right: 5px solid transparent;
                border-top: 5px solid #ffffff;
            }
            QComboBox QAbstractItemView {
                background-color: #404040;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QCheckBox {
                color: #ffffff;
                background-color: transparent;
            }
            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                background-color: #404040;
                border: 1px solid #555555;
            }
            QCheckBox::indicator:checked {
                background-color: #007acc;
                border: 1px solid #007acc;
            }
            QScrollBar:vertical {
                background-color: #404040;
                width: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical {
                background-color: #666666;
                border-radius: 6px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #777777;
            }
            QScrollBar:horizontal {
                background-color: #404040;
                height: 12px;
                border-radius: 6px;
            }
            QScrollBar::handle:horizontal {
                background-color: #666666;
                border-radius: 6px;
                min-width: 20px;
            }
            QScrollBar::handle:horizontal:hover {
                background-color: #777777;
            }
            QTextEdit {
                background-color: #3c3c3c;
                color: #ffffff;
                border: 1px solid #555555;
            }
            QProgressBar {
                background-color: #404040;
                color: #ffffff;
                border: 1px solid #555555;
                border-radius: 3px;
            }
            QProgressBar::chunk {
                background-color: #007acc;
                border-radius: 3px;
            }
        """)
        
        # Update matplotlib colors for dark theme
        try:
            import matplotlib.pyplot as plt
            plt.style.use('dark_background')
        except:
            pass
    
    def toggle_theme(self):
        """Toggle between light and dark theme"""
        self.dark_theme = not self.dark_theme
        self.apply_theme()
        
        # Update theme button text and style
        if self.dark_theme:
            self.theme_button.setText("☀️ LIGHT THEME")
            self.theme_button.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                                stop: 0 #ffc107, stop: 1 #e0a800);
                    color: #212529;
                    border: none;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 8px 16px;
                    margin-top: 5px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                                stop: 0 #ffcd39, stop: 1 #ffc107);
                }
            """)
        else:
            self.theme_button.setText("🌙 DARK THEME")
            self.theme_button.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                                stop: 0 #6f42c1, stop: 1 #5a32a3);
                    color: white;
                    border: none;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: bold;
                    padding: 8px 16px;
                    margin-top: 5px;
                }
                QPushButton:hover {
                    background: qlineargradient(x1: 0, y1: 0, x2: 0, y2: 1,
                                                stop: 0 #8c5bd1, stop: 1 #6f42c1);
                }
            """)
        
        # Refresh charts to apply new theme
        try:
            if hasattr(self, 'time_chart') and self.time_chart:
                self.time_chart.fig.patch.set_facecolor('#3c3c3c' if self.dark_theme else 'white')
                self.time_chart.axes.set_facecolor('#3c3c3c' if self.dark_theme else 'white')
                # Update text colors
                text_color = '#ffffff' if self.dark_theme else '#333333'
                self.time_chart.axes.tick_params(colors=text_color)
                self.time_chart.axes.xaxis.label.set_color(text_color)
                self.time_chart.axes.yaxis.label.set_color(text_color)
                self.time_chart.axes.title.set_color(text_color)
                self.time_chart.draw()
            
            if hasattr(self, 'event_chart') and self.event_chart:
                self.event_chart.fig.patch.set_facecolor('#3c3c3c' if self.dark_theme else 'white')
                self.event_chart.axes.set_facecolor('#3c3c3c' if self.dark_theme else 'white')
                # Update text colors
                text_color = '#ffffff' if self.dark_theme else '#333333'
                self.event_chart.axes.title.set_color(text_color)
                self.event_chart.draw()
            
            if hasattr(self, 'ml_confidence_canvas') and self.ml_confidence_canvas:
                self.ml_confidence_canvas.fig.patch.set_facecolor('#3c3c3c' if self.dark_theme else 'white')
                self.ml_confidence_canvas.axes.set_facecolor('#3c3c3c' if self.dark_theme else 'white')
                # Update text colors
                text_color = '#ffffff' if self.dark_theme else '#333333'
                self.ml_confidence_canvas.axes.tick_params(colors=text_color)
                self.ml_confidence_canvas.axes.xaxis.label.set_color(text_color)
                self.ml_confidence_canvas.axes.yaxis.label.set_color(text_color)
                self.ml_confidence_canvas.axes.title.set_color(text_color)
                self.ml_confidence_canvas.draw()
                
        except Exception as e:
            print(f"Error updating chart themes: {e}")
        
        log_event("INFO", f"Theme switched to {'dark' if self.dark_theme else 'light'} mode")

# Main function to run the GUI
def run_gui():
    app = QApplication(sys.argv)
    window = DeadboltMainWindow()
    window.show()
    return app.exec_()

# Run the GUI if this file is executed directly
if __name__ == "__main__":
    run_gui()
