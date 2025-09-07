"""
Deadbolt Ransomware Defender - ML-Enhanced Threat Detector
Advanced behavior-based detection engine with machine learning integration.
"""

import os
import sys
import time
import logging
import threading
import psutil
import joblib
import pandas as pd
import numpy as np
import json
from datetime import datetime, timedelta
from collections import defaultdict

# Try win10toast first, fall back to alternative notification methods
try:
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        from win10toast import ToastNotifier
    TOAST_AVAILABLE = True
except ImportError:
    TOAST_AVAILABLE = False
    ToastNotifier = None

# Try relative import first, fallback to direct import
try:
    from ..utils import config
    from ..ui.alerts import alert_manager
except ImportError:
    import sys
    utils_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'utils')
    sys.path.append(utils_path)
    import config
    try:
        from ui.alerts import alert_manager
    except ImportError:
        # Create fallback alert manager if not available
        class FallbackAlertManager:
            def show_alert(self, *args, **kwargs):
                pass
            def show_ransomware_alert(self, *args, **kwargs):
                pass
        alert_manager = FallbackAlertManager()

class MLThreatDetector:
    """ML-Enhanced threat detection engine with behavior analysis."""
    
    def __init__(self, responder_callback):
        self.responder_callback = responder_callback
        self.threat_history = defaultdict(list)
        self.process_suspicion_scores = defaultdict(int)
        self.lock = threading.Lock()
        
        # Initialize toast notifier if available
        if TOAST_AVAILABLE:
            self.toaster = ToastNotifier()
        else:
            self.toaster = None
        
        # Initialize logging
        self.logger = logging.getLogger(__name__)
        
        # Set up project paths
        project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        logs_dir = os.path.join(project_root, 'logs')
        os.makedirs(logs_dir, exist_ok=True)
        
        # Store project root for later use
        self.project_root = project_root
        
        handler = logging.FileHandler(os.path.join(logs_dir, 'ml_detector.log'))
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)
        self.logger.setLevel(logging.INFO)
        
        # Initialize ML statistics tracking - Load persistent stats first
        self.ml_stats = self._load_persistent_stats()
        
        # Ensure all required keys exist with defaults
        default_stats = {
            'total_predictions': 0,
            'malicious_detected': 0,
            'benign_classified': 0,
            'high_confidence_alerts': 0,
            'network_patterns_analyzed': 0,
            'model_accuracy_score': 0.0,
            'last_prediction_time': None,
            'prediction_history': [],
            'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0},
            'threat_types_detected': {},
            'false_positive_rate': 0.0,
            'average_confidence': 0.0
        }
        
        # Merge loaded stats with defaults (loaded stats take precedence)
        for key, default_value in default_stats.items():
            if key not in self.ml_stats:
                self.ml_stats[key] = default_value
        
        # Initialize ML components
        self.ml_model = None
        self.ml_scaler = None
        self.ml_features = None
        self._load_ml_model()
        
        self.logger.info("ML-Enhanced Threat Detector initialized")
        
        # Threat scoring weights - AGGRESSIVE + ML-enhanced
        self.threat_weights = {
            'mass_delete': 15,
            'mass_rename': 12,
            'mass_modification': 20,
            'ml_malicious': 25,  # NEW: ML-detected malicious behavior
            'network_anomaly': 18  # NEW: Network-based detection
        }
        
        # Notification cooldown
        self.last_notification_time = 0
        self.notification_cooldown = 3
        
        # Process behavior monitoring
        self.process_monitor_thread = None
        self.monitoring_active = False
        
    def _load_persistent_stats(self):
        """Load persistent ML statistics from file."""
        try:
            stats_file = os.path.join(self.project_root, 'logs', 'ml_stats.json')
            
            if os.path.exists(stats_file):
                with open(stats_file, 'r') as f:
                    return json.load(f)
            else:
                # Return default stats
                return {
                    'total_predictions': 0,
                    'malicious_detected': 0,
                    'benign_classified': 0,
                    'high_confidence_alerts': 0,
                    'network_patterns_analyzed': 0,
                    'model_accuracy_score': 0.0,
                    'last_prediction_time': None,
                    'prediction_history': [],
                    'confidence_distribution': {'high': 0, 'medium': 0, 'low': 0},
                    'threat_types_detected': {},
                    'false_positive_rate': 0.0,
                    'average_confidence': 0.0
                }
        except Exception as e:
            self.logger.error(f"Error loading persistent stats: {e}")
            return {}
        
    def _load_ml_model(self):
        """Load the trained ML model components with enhanced logistic regression support."""
        try:
            # Get ML model paths
            ml_dir = os.path.join(self.project_root, 'ml')
            
            # Primary: Enhanced Logistic Regression Model
            lr_model_path = os.path.join(ml_dir, 'models', 'ransomware_detection_model.joblib')
            lr_scaler_path = os.path.join(ml_dir, 'models', 'feature_scaler.joblib') 
            lr_features_path = os.path.join(ml_dir, 'models', 'feature_names.joblib')
            lr_metadata_path = os.path.join(ml_dir, 'models', 'model_metadata.json')
            
            # Fallback: IoT XGBoost Model
            xgb_model_path = os.path.join(ml_dir, 'best_iot_ransomware_model.joblib')
            xgb_scaler_path = os.path.join(ml_dir, 'iot_ransomware_scaler.joblib')
            xgb_features_path = os.path.join(ml_dir, 'iot_ransomware_features.joblib')
            
            # Try enhanced logistic regression first
            if (os.path.exists(lr_model_path) and os.path.exists(lr_scaler_path) 
                and os.path.exists(lr_features_path)):
                
                self.ml_model = joblib.load(lr_model_path)
                self.ml_scaler = joblib.load(lr_scaler_path)
                self.ml_features = joblib.load(lr_features_path)
                
                # Load metadata if available
                self.ml_metadata = None
                if os.path.exists(lr_metadata_path):
                    try:
                        import json
                        with open(lr_metadata_path, 'r') as f:
                            self.ml_metadata = json.load(f)
                    except Exception:
                        pass
                
                model_type = "Enhanced Logistic Regression"
                self.logger.info(f"Enhanced Logistic Regression model loaded - Features: {len(self.ml_features)}")
                print(f"🤖 ML-Enhanced Detection: {model_type} loaded with {len(self.ml_features)} features")
                
                # Log model capabilities
                if self.ml_metadata:
                    performance = self.ml_metadata.get('performance', {})
                    print(f"   📊 Model Performance: Accuracy {performance.get('mean_accuracy', 'N/A'):.3f}")
                    print(f"   🔧 Model Stability: {performance.get('model_stability', 'Unknown')}")
                
            # Fallback to XGBoost IoT model if available
            elif (os.path.exists(xgb_model_path) and os.path.exists(xgb_scaler_path) 
                  and os.path.exists(xgb_features_path)):
                
                self.ml_model = joblib.load(xgb_model_path)
                self.ml_scaler = joblib.load(xgb_scaler_path)
                self.ml_features = joblib.load(xgb_features_path)
                self.ml_metadata = None
                
                model_type = "XGBoost IoT"
                self.logger.info(f"XGBoost IoT model loaded (fallback) - Features: {len(self.ml_features)}")
                print(f"🤖 ML-Enhanced Detection: {model_type} (fallback) loaded with {len(self.ml_features)} features")
            
            else:
                self.logger.warning("No ML models found - using rule-based detection only")
                print("WARNING: No ML models found")
                print("   To train Enhanced Logistic Regression: python ml/logistic_regression_ransomware_detection.py")
                print("   To train XGBoost IoT model: python ml/simple_iot_detection.py")
                
        except Exception as e:
            self.logger.error(f"Failed to load ML model: {e}")
            print(f"ERROR: ML model loading failed: {e}")
            
    def start_monitoring(self):
        """Start the threat detection monitoring."""
        self.monitoring_active = True
        self.logger.info("ML-Enhanced threat detection monitoring started")
        if self.ml_model:
            print("ML-Enhanced Detection: Active")
        else:
            print("Rule-Based Detection: Active")
        
    def stop_monitoring(self):
        """Stop the threat detection monitoring."""
        self.monitoring_active = False
        if self.process_monitor_thread:
            self.process_monitor_thread.join(timeout=5)
        self.logger.info("ML-Enhanced threat detection monitoring stopped")
        
    def analyze_threat(self, threat_info):
        """Analyze incoming threat with ML enhancement."""
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
            
            # Calculate threat score with ML enhancement
            threat_score = self._calculate_ml_enhanced_threat_score(threat_info, current_time)
            
            # Update process suspicion scores
            self._update_process_scores(threat_info, threat_score)
            
            # Determine response level
            response_level = self._determine_response_level(threat_score, threat_type)
            
            # Log analysis results
            self.logger.info(f"ML-Enhanced threat analysis complete - Score: {threat_score}, Response: {response_level}")
            
            # Send notification
            self._send_notification(threat_info, threat_score, response_level)
            
            # Trigger response if necessary
            if response_level in ['HIGH', 'CRITICAL']:
                self._trigger_response(threat_info, response_level)
                
    def _calculate_ml_enhanced_threat_score(self, threat_info, current_time):
        """Calculate threat score with ML model enhancement."""
        # Start with rule-based score
        base_score = self.threat_weights.get(threat_info.get('type', 'unknown'), 5)
        
        # Factor in severity
        severity_multiplier = {
            'LOW': 1.0,
            'MEDIUM': 1.5,
            'HIGH': 2.0,
            'CRITICAL': 3.0
        }
        score = base_score * severity_multiplier.get(threat_info.get('severity', 'MEDIUM'), 1.5)
        
        # ML Enhancement: Analyze network patterns if ML model is available
        if self.ml_model and 'network_info' in threat_info:
            ml_score = self._get_ml_threat_score(threat_info['network_info'])
            if ml_score > 0.7:  # High confidence malicious
                score *= 2.5  # Significantly increase score
                self.logger.critical(f"ML Model detected malicious behavior - Confidence: {ml_score:.3f}")
                print(f"ALERT: ML DETECTION: Malicious confidence {ml_score:.3f}")
            elif ml_score > 0.5:  # Moderate confidence
                score *= 1.5
                self.logger.warning(f"ML Model detected suspicious behavior - Confidence: {ml_score:.3f}")
        
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
        
    def _get_ml_threat_score(self, network_info):
        """Get ML-based threat score with enhanced logistic regression support."""
        try:
            if not self.ml_model:
                self.logger.debug("ML model not available, returning 0.0 score")
                return 0.0
            
            # Determine model type and prepare data accordingly
            if hasattr(self, 'ml_metadata') and self.ml_metadata:
                model_type = self.ml_metadata.get('model_type', 'Unknown')
                if 'Logistic Regression' in model_type:
                    data = self._prepare_logistic_regression_data(network_info)
                else:
                    data = self._prepare_network_data(network_info)
            else:
                # Try logistic regression format first, fallback to IoT format
                try:
                    data = self._prepare_logistic_regression_data(network_info)
                    if data is None:
                        data = self._prepare_network_data(network_info)
                except Exception:
                    data = self._prepare_network_data(network_info)
            
            if data is not None:
                # Predict with ML model
                prediction_proba = self.ml_model.predict_proba(data)
                malicious_probability = prediction_proba[0][1]  # Probability of malicious class
                prediction_class = self.ml_model.predict(data)[0]
                
                # Update ML statistics
                self._update_ml_stats(malicious_probability, prediction_class, network_info)
                
                # Log ML prediction details
                self._log_ml_prediction(network_info, malicious_probability, prediction_class)
                
                return malicious_probability
            else:
                self.logger.warning("Failed to prepare network data for ML prediction")
                return 0.0
                
        except Exception as e:
            self.logger.error(f"ML prediction error: {e}")
            return 0.0
            
    def _prepare_logistic_regression_data(self, network_info):
        """Prepare network data for enhanced logistic regression model prediction."""
        try:
            # Create base features from network information
            base_features = {
                'duration': network_info.get('duration', 0.0),
                'orig_bytes': network_info.get('orig_bytes', 0),
                'resp_bytes': network_info.get('resp_bytes', 0),
                'orig_pkts': network_info.get('orig_pkts', 0),
                'resp_pkts': network_info.get('resp_pkts', 0),
                'file_changes': network_info.get('file_changes', 0),
                'entropy': network_info.get('entropy', 0.0),
                'proto_TCP': 1 if network_info.get('protocol', '').lower() == 'tcp' else 0,
                'proto_UDP': 1 if network_info.get('protocol', '').lower() == 'udp' else 0
            }
            
            # Create enhanced features (matching training)
            enhanced_features = base_features.copy()
            
            # Traffic ratio features
            enhanced_features['bytes_ratio'] = (
                base_features['orig_bytes'] / base_features['resp_bytes'] 
                if base_features['resp_bytes'] > 0 else base_features['orig_bytes']
            )
            
            enhanced_features['pkts_ratio'] = (
                base_features['orig_pkts'] / base_features['resp_pkts']
                if base_features['resp_pkts'] > 0 else base_features['orig_pkts']
            )
            
            # Throughput features
            enhanced_features['orig_throughput'] = (
                base_features['orig_bytes'] / base_features['duration']
                if base_features['duration'] > 0 else base_features['orig_bytes']
            )
            
            enhanced_features['resp_throughput'] = (
                base_features['resp_bytes'] / base_features['duration']
                if base_features['duration'] > 0 else base_features['resp_bytes']
            )
            
            # Protocol efficiency
            enhanced_features['protocol_efficiency'] = (
                base_features['proto_TCP'] * 2 + base_features['proto_UDP']
            )
            
            # Entropy category (binned)
            entropy = base_features['entropy']
            if entropy <= 3:
                enhanced_features['entropy_category'] = 0
            elif entropy <= 6:
                enhanced_features['entropy_category'] = 1
            elif entropy <= 9:
                enhanced_features['entropy_category'] = 2
            else:
                enhanced_features['entropy_category'] = 3
            
            # File change rate
            enhanced_features['file_change_rate'] = (
                base_features['file_changes'] / base_features['duration']
                if base_features['duration'] > 0 else base_features['file_changes']
            )
            
            # Convert to DataFrame format
            df = pd.DataFrame([enhanced_features])
            
            # Ensure all expected features are present in correct order
            feature_order = self.ml_features if hasattr(self, 'ml_features') else list(enhanced_features.keys())
            
            for feature in feature_order:
                if feature not in df.columns:
                    df[feature] = 0
            
            # Keep only the features used in training (in the same order)
            df_final = df[feature_order]
            
            # Scale the features
            df_scaled = self.ml_scaler.transform(df_final)
            
            return df_scaled
            
        except Exception as e:
            self.logger.error(f"Logistic regression data preparation error: {e}")
            return None
    def _prepare_network_data(self, network_info):
        """Prepare network data for IoT XGBoost model prediction (fallback)."""
        try:
            # Create a DataFrame with the network information for IoT model
            data_dict = {
                'id.orig_p': network_info.get('orig_port', 0),
                'id.resp_p': network_info.get('resp_port', 0),
                'proto': network_info.get('protocol', 'tcp'),
                'service': network_info.get('service', 'unknown'),
                'duration': network_info.get('duration', 0.0),
                'orig_bytes': network_info.get('orig_bytes', 0),
                'resp_bytes': network_info.get('resp_bytes', 0),
                'conn_state': network_info.get('conn_state', 'unknown'),
                'missed_bytes': network_info.get('missed_bytes', 0),
                'history': network_info.get('history', 'unknown'),
                'orig_pkts': network_info.get('orig_pkts', 0),
                'orig_ip_bytes': network_info.get('orig_ip_bytes', 0),
                'resp_pkts': network_info.get('resp_pkts', 0),
                'resp_ip_bytes': network_info.get('resp_ip_bytes', 0)
            }
            
            df = pd.DataFrame([data_dict])
            
            # Apply the same preprocessing as training
            df_processed = self._preprocess_for_ml(df)
            
            # Scale the features
            df_scaled = self.ml_scaler.transform(df_processed)
            
            return df_scaled
            
        except Exception as e:
            self.logger.error(f"IoT model data preparation error: {e}")
            return None
            
    def _update_ml_stats(self, confidence, prediction, network_info):
        """Update ML statistics for tracking and analysis."""
        try:
            self.ml_stats['total_predictions'] += 1
            self.ml_stats['last_prediction_time'] = datetime.now().isoformat()
            
            # Classification tracking
            if prediction == 1:  # Malicious
                self.ml_stats['malicious_detected'] += 1
            else:  # Benign
                self.ml_stats['benign_classified'] += 1
            
            # Confidence distribution
            if confidence > 0.8:
                self.ml_stats['confidence_distribution']['high'] += 1
                if prediction == 1:
                    self.ml_stats['high_confidence_alerts'] += 1
            elif confidence > 0.5:
                self.ml_stats['confidence_distribution']['medium'] += 1
            else:
                self.ml_stats['confidence_distribution']['low'] += 1
            
            # Network pattern tracking
            if 'service' in network_info:
                service = network_info['service']
                if service not in self.ml_stats['threat_types_detected']:
                    self.ml_stats['threat_types_detected'][service] = 0
                if prediction == 1:
                    self.ml_stats['threat_types_detected'][service] += 1
            
            # Calculate running average confidence
            self.ml_stats['prediction_history'].append(confidence)
            if len(self.ml_stats['prediction_history']) > 100:  # Keep last 100
                self.ml_stats['prediction_history'].pop(0)
            
            self.ml_stats['average_confidence'] = sum(self.ml_stats['prediction_history']) / len(self.ml_stats['prediction_history'])
            
            # Calculate false positive estimation (simplified)
            total = self.ml_stats['total_predictions']
            if total > 10:  # Need some data
                # Estimate based on low confidence predictions classified as malicious
                low_conf_malicious = sum(1 for p in self.ml_stats['prediction_history'] if p < 0.6)
                self.ml_stats['false_positive_rate'] = low_conf_malicious / total
            
        except Exception as e:
            self.logger.error(f"Error updating ML stats: {e}")
        
        # Save persistent stats after update
        try:
            self._save_persistent_stats()
        except Exception as e:
            self.logger.error(f"Error saving persistent stats: {e}")
    
    def _log_ml_prediction(self, network_info, confidence, prediction):
        """Log detailed ML prediction information."""
        try:
            # Determine log level based on confidence and prediction
            if prediction == 1 and confidence > 0.8:
                log_level = "CRITICAL"
            elif prediction == 1 and confidence > 0.5:
                log_level = "WARNING"
            else:
                log_level = "INFO"
            
            # Create detailed log entry
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'prediction': 'MALICIOUS' if prediction == 1 else 'BENIGN',
                'confidence': round(confidence, 4),
                'network_details': {
                    'service': network_info.get('service', 'unknown'),
                    'protocol': network_info.get('protocol', 'unknown'),
                    'dest_port': network_info.get('resp_port', 0),
                    'src_port': network_info.get('orig_port', 0),
                    'duration': network_info.get('duration', 0),
                    'bytes_sent': network_info.get('orig_bytes', 0),
                    'bytes_received': network_info.get('resp_bytes', 0)
                },
                'ml_stats': {
                    'total_predictions': self.ml_stats['total_predictions'],
                    'malicious_rate': self.ml_stats['malicious_detected'] / max(1, self.ml_stats['total_predictions']),
                    'avg_confidence': round(self.ml_stats['average_confidence'], 3)
                }
            }
            
            # Log based on severity
            if log_level == "CRITICAL":
                self.logger.critical(f"ML HIGH THREAT DETECTED: {log_entry}")
            elif log_level == "WARNING":
                self.logger.warning(f"ML SUSPICIOUS ACTIVITY: {log_entry}")
            else:
                self.logger.info(f"ML ANALYSIS: {log_entry}")
            
            # Special logging for specific threat patterns
            service = network_info.get('service', '')
            port = network_info.get('resp_port', 0)
            
            if service == 'irc' or port == 6667:
                self.logger.warning(f"IRC PATTERN DETECTED: Service={service}, Port={port}, Confidence={confidence:.3f}")
            elif port in [80, 443, 8080]:  # HTTP/HTTPS patterns
                self.logger.info(f"HTTP PATTERN ANALYZED: Port={port}, Confidence={confidence:.3f}")
            elif confidence > 0.9:
                self.logger.critical(f"VERY HIGH CONFIDENCE THREAT: {confidence:.3f} - Immediate investigation recommended")
                
        except Exception as e:
            self.logger.error(f"Error logging ML prediction: {e}")
    
    def get_ml_statistics(self):
        """Get comprehensive ML statistics for GUI display with enhanced model info."""
        try:
            # Load persistent stats if available
            stats = self._load_persistent_stats()
            
            # Update with current instance stats
            stats.update(self.ml_stats)
            
            # Add derived statistics
            total = stats['total_predictions']
            if total > 0:
                stats['malicious_rate'] = stats['malicious_detected'] / total
                stats['benign_rate'] = stats['benign_classified'] / total
                stats['high_confidence_rate'] = stats['high_confidence_alerts'] / total
            else:
                stats['malicious_rate'] = 0.0
                stats['benign_rate'] = 0.0
                stats['high_confidence_rate'] = 0.0
            
            # Add model status with enhanced info
            stats['model_loaded'] = self.ml_model is not None
            stats['model_features'] = len(self.ml_features) if self.ml_features else 0
            stats['monitoring_active'] = self.monitoring_active
            
            # Enhanced model information
            if hasattr(self, 'ml_metadata') and self.ml_metadata:
                stats['model_type'] = self.ml_metadata.get('model_type', 'Unknown')
                stats['model_version'] = self.ml_metadata.get('deadbolt_integration', {}).get('version', '1.0')
                performance = self.ml_metadata.get('performance', {})
                stats['model_accuracy'] = performance.get('mean_accuracy', 0.0)
                stats['model_stability'] = performance.get('model_stability', 'Unknown')
                stats['training_date'] = self.ml_metadata.get('training_date', 'Unknown')
            else:
                stats['model_type'] = 'XGBoost IoT (Legacy)' if self.ml_model else 'None'
                stats['model_version'] = '1.0'
                stats['model_accuracy'] = 0.0
                stats['model_stability'] = 'Unknown'
                stats['training_date'] = 'Unknown'
            
            # Format timestamps
            if stats['last_prediction_time']:
                try:
                    if isinstance(stats['last_prediction_time'], str):
                        stats['last_prediction_formatted'] = datetime.fromisoformat(stats['last_prediction_time']).strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        stats['last_prediction_formatted'] = str(stats['last_prediction_time'])
                except:
                    stats['last_prediction_formatted'] = str(stats['last_prediction_time'])
            else:
                stats['last_prediction_formatted'] = 'Never'
            
            return stats
            
        except Exception as e:
            self.logger.error(f"Error getting ML statistics: {e}")
            return {
                'total_predictions': 0,
                'malicious_detected': 0,
                'benign_classified': 0,
                'model_loaded': self.ml_model is not None,
                'model_features': len(self.ml_features) if self.ml_features else 0,
                'monitoring_active': self.monitoring_active,
                'model_type': 'Error',
                'error': str(e)
            }
    
    def _save_persistent_stats(self):
        """Save ML statistics to persistent file."""
        try:
            logs_dir = os.path.join(self.project_root, 'logs')
            os.makedirs(logs_dir, exist_ok=True)
            stats_file = os.path.join(logs_dir, 'ml_stats.json')
            
            # Prepare stats for JSON serialization
            stats_to_save = self.ml_stats.copy()
            
            # Convert numpy types to Python types
            for key, value in stats_to_save.items():
                if isinstance(value, (np.int64, np.int32, np.float64, np.float32)):
                    stats_to_save[key] = value.item()
                elif isinstance(value, np.ndarray):
                    stats_to_save[key] = value.tolist()
            
            with open(stats_file, 'w') as f:
                json.dump(stats_to_save, f, indent=2, default=str)
                
        except Exception as e:
            self.logger.error(f"Error saving persistent stats: {e}")
    
    def get_recent_ml_logs(self, limit=50):
        """Get recent ML log entries for GUI display."""
        try:
            log_file = os.path.join(self.project_root, 'logs', 'ml_detector.log')
            
            if not os.path.exists(log_file):
                return []
            
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            # Get the last 'limit' lines
            recent_lines = lines[-limit:] if len(lines) > limit else lines
            
            # Parse and format log entries
            formatted_logs = []
            for line in recent_lines:
                line = line.strip()
                if line and ' - ' in line:
                    try:
                        parts = line.split(' - ', 2)
                        if len(parts) >= 3:
                            timestamp = parts[0]
                            level = parts[1]
                            message = parts[2]
                            
                            # Determine severity color for GUI
                            severity_color = {
                                'CRITICAL': '#ff4444',
                                'ERROR': '#ff6666',
                                'WARNING': '#ffaa44',
                                'INFO': '#44aaff',
                                'DEBUG': '#888888'
                            }.get(level, '#ffffff')
                            
                            formatted_logs.append({
                                'timestamp': timestamp,
                                'level': level,
                                'message': message,
                                'color': severity_color,
                                'full_line': line
                            })
                    except Exception:
                        # If parsing fails, add as raw line
                        formatted_logs.append({
                            'timestamp': 'Unknown',
                            'level': 'INFO',
                            'message': line,
                            'color': '#ffffff',
                            'full_line': line
                        })
            
            return formatted_logs
            
        except Exception as e:
            self.logger.error(f"Error reading ML logs: {e}")
            return [{
                'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'level': 'ERROR',
                'message': f"Failed to read ML logs: {e}",
                'color': '#ff4444',
                'full_line': f"Error reading logs: {e}"
            }]
            
    def _preprocess_for_ml(self, df):
        """Preprocess data to match ML model training format."""
        try:
            # Handle missing values for numeric columns
            numeric_columns = ['duration', 'orig_bytes', 'resp_bytes', 'missed_bytes', 
                              'orig_pkts', 'orig_ip_bytes', 'resp_pkts', 'resp_ip_bytes']
            
            for col in numeric_columns:
                if col in df.columns:
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                    df[col] = df[col].fillna(0)
            
            # Handle missing values for categorical columns
            categorical_columns = ['proto', 'service', 'conn_state', 'history']
            for col in categorical_columns:
                if col in df.columns:
                    df[col] = df[col].fillna('unknown')
            
            # One-hot encode categorical variables
            existing_categorical = [col for col in categorical_columns if col in df.columns]
            if existing_categorical:
                df_encoded = pd.get_dummies(df, columns=existing_categorical, prefix=existing_categorical)
            else:
                df_encoded = df
            
            # Ensure all expected features are present
            for feature in self.ml_features:
                if feature not in df_encoded.columns:
                    df_encoded[feature] = 0
            
            # Keep only the features used in training (in the same order)
            df_final = df_encoded[self.ml_features]
            
            return df_final
            
        except Exception as e:
            self.logger.error(f"Preprocessing error: {e}")
            return df
    
    # Include all the rest of the methods from the original detector
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
        """AGGRESSIVE response level determination for instant ransomware protection."""
        # INSTANT CRITICAL response for ANY mass file operations or ML-detected threats
        if (threat_score >= 15 or
            threat_type in ['mass_modification', 'mass_delete', 'mass_rename', 'ml_malicious'] or
            any(score > 15 for score in self.process_suspicion_scores.values())):
            return 'CRITICAL'
        
        elif threat_score >= 10:
            return 'HIGH'
        elif threat_score >= 5:
            return 'MEDIUM'
        else:
            return 'LOW'
            
    def _send_notification(self, threat_info, threat_score, response_level):
        """Send multiple types of notifications for maximum visibility using enhanced AlertManager."""
        try:
            current_time = time.time()
            
            if current_time - self.last_notification_time < self.notification_cooldown:
                return
            
            threat_type = threat_info.get('type', 'Unknown Threat')
            file_count = threat_info.get('count', 'Multiple')
            
            if response_level == 'CRITICAL':
                # Determine if ML detected the threat
                ml_detected = 'ml_malicious' in threat_type or 'network_info' in threat_info
                
                if ml_detected:
                    title = "AI DETECTED RANSOMWARE!"
                    message = f"Machine Learning model detected malicious behavior!\n\nAI Confidence: High\nThreat neutralized automatically."
                else:
                    title = "RANSOMWARE DETECTED & BLOCKED!"
                    message = f"Suspicious behavior stopped!\n\nFiles protected: {file_count}\nThreat neutralized automatically."
                
                # Use enhanced AlertManager for desktop notifications
                alert_manager.show_ransomware_alert(threat_type, file_count, threat_score)
                
                # Console alert
                alert_msg = f"\n" + "="*60 + "\n"
                alert_msg += f"🤖🚨 DEADBOLT ML ALERT 🚨🤖\n" if ml_detected else f"🚨🚨🚨 DEADBOLT ALERT 🚨🚨🚨\n"
                alert_msg += f"TIME: {datetime.now().strftime('%H:%M:%S')}\n"
                alert_msg += f"THREAT: {threat_type.upper()}\n"
                alert_msg += f"SCORE: {threat_score}\n"
                alert_msg += f"STATUS: BLOCKED & NEUTRALIZED\n"
                if ml_detected:
                    alert_msg += f"DETECTION: AI/ML Model\n"
                alert_msg += "="*60 + "\n"
                print(alert_msg)
                
                # System beep
                try:
                    import winsound
                    for _ in range(3):
                        winsound.Beep(1000, 200)
                        time.sleep(0.1)
                except ImportError:
                    pass
                
                # Fallback notification method for compatibility
                if TOAST_AVAILABLE and self.toaster:
                    try:
                        self.toaster.show_toast(
                            title=title,
                            msg=message,
                            duration=20,
                            threaded=True
                        )
                    except Exception:
                        pass
                
                self.last_notification_time = current_time
                self.logger.critical(f"ML-ENHANCED ALERT SENT - Level: {response_level}, Score: {threat_score}")
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
            
    def _trigger_response(self, threat_info, response_level):
        """Trigger response with ML-enhanced targeting."""
        try:
            suspicious_pids = []
            process_info = threat_info.get('process_info', [])
            
            for pid, process_name in process_info:
                if self._is_system_process(process_name):
                    continue
                
                if response_level == 'CRITICAL':
                    suspicious_pids.append(pid)
                elif self.process_suspicion_scores.get(pid, 0) > 10:
                    suspicious_pids.append(pid)
            
            response_info = {
                'threat_info': threat_info,
                'response_level': response_level,
                'suspicious_pids': suspicious_pids,
                'timestamp': datetime.now().isoformat(),
                'ml_enhanced': self.ml_model is not None
            }
            
            self.logger.critical(f"Triggering ML-enhanced {response_level} response - Target PIDs: {suspicious_pids}")
            
            if response_level == 'CRITICAL' or suspicious_pids:
                self.responder_callback(response_info)
            
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
            recent = [t for t in threats if (current_time - t['time']).total_seconds() < 3600]
            summary[threat_type] = len(recent)
            
        return summary

# Alias for backward compatibility
ThreatDetector = MLThreatDetector