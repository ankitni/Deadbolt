# Advanced GUI implementation for Deadbolt AI using PyQt5

import os
import sys
import time
import threading
import traceback
import logging
import re
from datetime import datetime

# Add parent directories to path so we can import modules
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

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

# Import Deadbolt modules
from ..utils.logger import log_event, get_log_path, LOG_DIR, log_alert
try:
    from ..utils import config
    from ..utils.config import TARGET_DIRS, RULES, SUSPICIOUS_PATTERNS, ACTIONS
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
    def start_watcher(path):
        print(f"Mock watcher started for {path}")
        return type('MockWatcher', (), {'stop': lambda: None})()

from .alerts import alert_manager, AlertManager
from .dashboard import DashboardData, start_dashboard_monitor, get_dashboard_data

# Import config manager for saving settings
try:
    from ..utils.config_manager import config_manager
    CONFIG_MANAGER_AVAILABLE = True
except ImportError:
    CONFIG_MANAGER_AVAILABLE = False
    print("Config manager not available - settings will not persist")

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
        self.fig = Figure(figsize=(width, height), dpi=dpi)
        # Add subplot before initializing the FigureCanvas
        self.axes = self.fig.add_subplot(111)
        # Initialize the FigureCanvas with the figure
        super(MplCanvas, self).__init__(self.fig)
        # Apply tight layout
        self.fig.tight_layout()

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
        self.setWindowTitle("Deadbolt AI - Ransomware Protection")
        self.setMinimumSize(900, 600)
        
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
        self.refresh_timer.start(5000)  # Refresh every 5 seconds
        
        # Initialize statistics from dashboard
        self.initialize_statistics()
        
        # Load initial data
        self.load_initial_data()
    
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
        
        # Status bar at the top
        status_layout = QHBoxLayout()
        self.status_label = QLabel("Status: Monitoring")
        self.status_label.setStyleSheet("font-weight: bold; color: green;")
        status_layout.addWidget(self.status_label)
        
        # Add control buttons
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.start_monitoring)
        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        status_layout.addWidget(self.start_button)
        status_layout.addWidget(self.stop_button)
        
        # Add to main layout
        main_layout.addLayout(status_layout)
        
        # Tab widget for different sections
        self.tabs = QTabWidget()
        self.dashboard_tab = QWidget()
        self.logs_tab = QWidget()
        self.settings_tab = QWidget()
        
        # Setup tabs
        self.setup_dashboard_tab()
        self.setup_logs_tab()
        self.setup_settings_tab()
        
        # Add tabs to tab widget
        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.logs_tab, "Logs")
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
            self.time_chart = MplCanvas(width=5, height=4, dpi=100)
            # Initialize with empty data
            self.time_chart.axes.bar(range(24), [0] * 24, color='#FF5555')
            self.time_chart.axes.set_xlabel('Hour of Day')
            self.time_chart.axes.set_ylabel('Number of Threats')
            self.time_chart.axes.set_xticks(range(0, 24, 3))
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
            self.event_chart = MplCanvas(width=5, height=4, dpi=100)
            # Initialize with dummy data
            self.event_chart.axes.pie([1], labels=['No Data'], autopct='%1.1f%%', startangle=90)
            self.event_chart.axes.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
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
        for path in TARGET_DIRS:
            if os.path.exists(path):
                try:
                    log_event("INFO", f"✅ Watching {path}")
                    watcher = start_watcher(path)
                    active_watchers.append(watcher)
                except Exception as e:
                    log_event("ERROR", f"Failed to start watcher for {path}: {str(e)}")
            else:
                log_event("WARNING", f"❌ Skipping invalid path: {path}")
        
        if active_watchers:
            self.status_label.setText("Status: Monitoring")
            self.status_label.setStyleSheet("font-weight: bold; color: green;")
            log_event("INFO", f"Deadbolt AI running, monitoring {len(active_watchers)} locations")
        else:
            self.status_label.setText("Status: Error - No valid paths")
            self.status_label.setStyleSheet("font-weight: bold; color: red;")
            log_event("CRITICAL", "No valid paths to monitor.")
    
    def stop_monitoring(self):
        global active_watchers
        
        # Stop all watchers
        for watcher in active_watchers:
            try:
                watcher.stop()
                log_event("INFO", "Stopped a watcher")
            except Exception as e:
                log_event("ERROR", f"Error stopping watcher: {str(e)}")
        
        active_watchers = []
        self.status_label.setText("Status: Stopped")
        self.status_label.setStyleSheet("font-weight: bold; color: red;")
        log_event("INFO", "Deadbolt AI monitoring stopped")
    
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
                # Import here to avoid circular imports
                from logger import show_notification
                show_notification(
                    "Deadbolt AI Security Alert", 
                    message, 
                    severity=severity
                )
            except Exception as toast_error:
                print(f"Error showing toast notification: {str(toast_error)}")
        
        # Add to recent alerts table immediately (dashboard will update this later)
        row_position = self.alerts_table.rowCount()
        self.alerts_table.insertRow(row_position)
        
        # Add timestamp
        time_item = QTableWidgetItem(timestamp)
        self.alerts_table.setItem(row_position, 0, time_item)
        
        # Add severity with color coding
        severity_item = QTableWidgetItem(severity)
        if severity == "HIGH":
            severity_item.setBackground(QColor(255, 150, 150))  # Red
        elif severity == "MEDIUM":
            severity_item.setBackground(QColor(255, 200, 150))  # Orange
        else:
            severity_item.setBackground(QColor(200, 200, 255))  # Blue
        self.alerts_table.setItem(row_position, 1, severity_item)
        
        # Add message
        message_item = QTableWidgetItem(message)
        self.alerts_table.setItem(row_position, 2, message_item)
        
        # Always auto-scroll alerts table
        self.alerts_table.scrollToBottom()
    
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
            
            # Update alert distribution
            self.high_alerts_label.setText(f"High: {self.stats.get('alerts_high', 0)}")
            self.medium_alerts_label.setText(f"Medium: {self.stats.get('alerts_medium', 0)}")
            self.low_alerts_label.setText(f"Low: {self.stats.get('alerts_low', 0)}")
            
            # Update system health indicators
            health = self.stats.get('system_health', {})
            
            detector_active = health.get('detector_active', False)
            self.detector_status.setText(f"Detector: {'Active' if detector_active else 'Inactive'}")
            self.detector_status.setStyleSheet(f"color: {'green' if detector_active else 'red'}; font-weight: bold;")
            
            responder_active = health.get('responder_active', False)
            self.responder_status.setText(f"Responder: {'Active' if responder_active else 'Inactive'}")
            self.responder_status.setStyleSheet(f"color: {'green' if responder_active else 'red'}; font-weight: bold;")
            
            watcher_active = health.get('watcher_active', False)
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
                    self.time_chart.axes.set_xlabel('Hour of Day')
                    self.time_chart.axes.set_ylabel('Number of Threats')
                    self.time_chart.axes.set_xticks(range(0, 24, 3))
                    self.time_chart.axes.set_title('Threat Activity by Hour')
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
                        self.event_chart.axes.pie(sizes, labels=labels, autopct='%1.1f%%', startangle=90, colors=colors[:len(labels)])
                        self.event_chart.axes.axis('equal')
                        self.event_chart.axes.set_title('Event Types Distribution')
                        self.event_chart.draw()
                    else:
                        # If no event data, show a default pie chart
                        self.event_chart.axes.clear()
                        self.event_chart.axes.pie([1], labels=['No Data'], autopct='%1.1f%%', startangle=90, colors=['#CCCCCC'])
                        self.event_chart.axes.axis('equal')
                        self.event_chart.axes.set_title('Event Types Distribution')
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

# Main function to run the GUI
def run_gui():
    app = QApplication(sys.argv)
    window = DeadboltMainWindow()
    window.show()
    return app.exec_()

# Run the GUI if this file is executed directly
if __name__ == "__main__":
    run_gui()
