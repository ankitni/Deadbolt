#!/usr/bin/env python3
"""
Ransomware Detection Inference Script - Enhanced Version
Loads the enhanced logistic regression model from joblib files for predictions
Integrated with Deadbolt Premium ML detection system
"""

import pandas as pd
import numpy as np
import joblib
import os
import json
from datetime import datetime

class EnhancedRansomwareDetector:
    """Enhanced ransomware detection model wrapper with feature engineering"""
    
    def __init__(self, model_dir="models"):
        """Initialize the detector by loading saved model components"""
        self.model_dir = model_dir
        self.model = None
        self.scaler = None
        self.label_encoder = None
        self.feature_names = None
        self.metadata = None
        self.load_model()
        
        # Feature engineering functions
        self.enhanced_features_enabled = True
    
    def load_model(self):
        """Load all model components from joblib files with metadata support"""
        try:
            model_path = os.path.join(self.model_dir, "ransomware_detection_model.joblib")
            scaler_path = os.path.join(self.model_dir, "feature_scaler.joblib")
            encoder_path = os.path.join(self.model_dir, "label_encoder.joblib")
            features_path = os.path.join(self.model_dir, "feature_names.joblib")
            metadata_path = os.path.join(self.model_dir, "model_metadata.json")
            
            # Load core components
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            self.label_encoder = joblib.load(encoder_path)
            self.feature_names = joblib.load(features_path)
            
            # Load metadata if available
            if os.path.exists(metadata_path):
                with open(metadata_path, 'r') as f:
                    self.metadata = json.load(f)
            
            model_type = self.metadata.get('model_type', 'Logistic Regression') if self.metadata else 'Logistic Regression'
            performance = self.metadata.get('performance', {}) if self.metadata else {}
            
            print(f"✅ Enhanced Ransomware Detection Model Loaded Successfully!")
            print(f"   Model Type: {model_type}")
            print(f"   Features: {len(self.feature_names)} features")
            print(f"   Training Date: {self.metadata.get('training_date', 'Unknown')[:10] if self.metadata else 'Unknown'}")
            if performance:
                print(f"   Performance: {performance.get('mean_accuracy', 0):.3f} accuracy, {performance.get('model_stability', 'Unknown')} stability")
            print(f"   Deadbolt Integration: {'Ready' if self.metadata and self.metadata.get('deadbolt_integration', {}).get('compatible') else 'Compatible'}")
            
        except Exception as e:
            raise Exception(f"Failed to load enhanced model: {str(e)}")
    
    def create_enhanced_features(self, base_features):
        """Create enhanced features matching the training pipeline"""
        if not self.enhanced_features_enabled:
            return base_features
            
        enhanced = base_features.copy()
        
        # Traffic ratio features
        enhanced['bytes_ratio'] = (
            enhanced['orig_bytes'] / enhanced['resp_bytes'] 
            if enhanced['resp_bytes'] > 0 else enhanced['orig_bytes']
        )
        
        enhanced['pkts_ratio'] = (
            enhanced['orig_pkts'] / enhanced['resp_pkts']
            if enhanced['resp_pkts'] > 0 else enhanced['orig_pkts']
        )
        
        # Throughput features
        enhanced['orig_throughput'] = (
            enhanced['orig_bytes'] / enhanced['duration']
            if enhanced['duration'] > 0 else enhanced['orig_bytes']
        )
        
        enhanced['resp_throughput'] = (
            enhanced['resp_bytes'] / enhanced['duration']
            if enhanced['duration'] > 0 else enhanced['resp_bytes']
        )
        
        # Protocol efficiency
        enhanced['protocol_efficiency'] = (
            enhanced['proto_TCP'] * 2 + enhanced['proto_UDP']
        )
        
        # Entropy category (binned)
        entropy = enhanced['entropy']
        if entropy <= 3:
            enhanced['entropy_category'] = 0
        elif entropy <= 6:
            enhanced['entropy_category'] = 1
        elif entropy <= 9:
            enhanced['entropy_category'] = 2
        else:
            enhanced['entropy_category'] = 3
        
        # File change rate
        enhanced['file_change_rate'] = (
            enhanced['file_changes'] / enhanced['duration']
            if enhanced['duration'] > 0 else enhanced['file_changes']
        )
        
        return enhanced
    def predict_single(self, features):
        """
        Predict ransomware for a single network traffic sample with enhanced features
        
        Args:
            features: Dict or array with network traffic features
                     Expected base keys: duration, orig_bytes, resp_bytes, orig_pkts, 
                                       resp_pkts, file_changes, entropy, proto_TCP, proto_UDP
        
        Returns:
            dict: Enhanced prediction result with label, confidence, and probabilities
        """
        if isinstance(features, dict):
            # Apply feature engineering
            enhanced_features = self.create_enhanced_features(features)
            
            # Convert dict to array in correct order
            feature_array = np.array([enhanced_features[name] for name in self.feature_names])
        else:
            feature_array = np.array(features)
        
        # Ensure 2D array
        if feature_array.ndim == 1:
            feature_array = feature_array.reshape(1, -1)
        
        # Scale features
        features_scaled = self.scaler.transform(feature_array)
        
        # Make prediction
        prediction = self.model.predict(features_scaled)[0]
        probabilities = self.model.predict_proba(features_scaled)[0]
        
        # Decode prediction
        predicted_label = self.label_encoder.inverse_transform([prediction])[0]
        confidence = max(probabilities)
        
        # Enhanced result with additional info
        result = {
            'prediction': predicted_label,
            'confidence': confidence,
            'probabilities': {
                'benign': probabilities[0],
                'malicious': probabilities[1]
            },
            'is_malicious': predicted_label == 'malicious',
            'threat_level': self._determine_threat_level(confidence, predicted_label),
            'model_info': {
                'type': self.metadata.get('model_type', 'Enhanced Logistic Regression') if self.metadata else 'Enhanced Logistic Regression',
                'features_used': len(self.feature_names),
                'enhanced_features': self.enhanced_features_enabled
            }
        }
        
        return result
    
    def _determine_threat_level(self, confidence, prediction):
        """Determine threat level based on confidence and prediction"""
        if prediction == 'malicious':
            if confidence >= 0.9:
                return 'CRITICAL'
            elif confidence >= 0.7:
                return 'HIGH'
            elif confidence >= 0.5:
                return 'MEDIUM'
            else:
                return 'LOW'
        else:
            return 'SAFE'
    
    def predict_batch(self, data):
        """
        Predict ransomware for multiple network traffic samples
        
        Args:
            data: DataFrame or array with network traffic features
        
        Returns:
            list: List of prediction results
        """
        if isinstance(data, pd.DataFrame):
            features_array = data[self.feature_names].values
        else:
            features_array = np.array(data)
        
        # Scale features
        features_scaled = self.scaler.transform(features_array)
        
        # Make predictions
        predictions = self.model.predict(features_scaled)
        probabilities = self.model.predict_proba(features_scaled)
        
        # Decode predictions
        results = []
        for i, (pred, probs) in enumerate(zip(predictions, probabilities)):
            predicted_label = self.label_encoder.inverse_transform([pred])[0]
            confidence = max(probs)
            
            results.append({
                'prediction': predicted_label,
                'confidence': confidence,
                'probabilities': {
                    'benign': probs[0],
                    'malicious': probs[1]
                },
                'is_malicious': predicted_label == 'malicious'
            })
        
        return results
    
    def get_feature_importance(self):
        """Get feature importance from the logistic regression model"""
        coefficients = pd.DataFrame({
            'feature': self.feature_names,
            'coefficient': self.model.coef_[0],
            'abs_coefficient': np.abs(self.model.coef_[0])
        }).sort_values('abs_coefficient', ascending=False)
        
        return coefficients

def demo_enhanced_prediction():
    """Demonstrate the enhanced ransomware detector with sample data"""
    print("=" * 70)
    print("ENHANCED RANSOMWARE DETECTION DEMO - Deadbolt Premium Integration")
    print("=" * 70)
    
    # Initialize enhanced detector
    detector = EnhancedRansomwareDetector()
    
    # Enhanced test cases with more realistic scenarios
    test_cases = [
        {
            'name': 'High Entropy + File Changes (Likely Ransomware)',
            'features': {
                'duration': 4, 'orig_bytes': 9206, 'resp_bytes': 727, 
                'orig_pkts': 314, 'resp_pkts': 3, 'file_changes': 334, 
                'entropy': 8.27, 'proto_TCP': 1, 'proto_UDP': 0
            }
        },
        {
            'name': 'Low Entropy + Normal Traffic (Likely Benign)', 
            'features': {
                'duration': 12, 'orig_bytes': 1053, 'resp_bytes': 3870,
                'orig_pkts': 50, 'resp_pkts': 45, 'file_changes': 3,
                'entropy': 2.64, 'proto_TCP': 1, 'proto_UDP': 0
            }
        },
        {
            'name': 'Moderate Entropy + Heavy File Activity (Suspicious)',
            'features': {
                'duration': 8, 'orig_bytes': 15000, 'resp_bytes': 500,
                'orig_pkts': 200, 'resp_pkts': 10, 'file_changes': 150,
                'entropy': 6.2, 'proto_TCP': 1, 'proto_UDP': 1
            }
        },
        {
            'name': 'Very High Entropy + Fast Execution (Critical Threat)',
            'features': {
                'duration': 2, 'orig_bytes': 8000, 'resp_bytes': 200,
                'orig_pkts': 100, 'resp_pkts': 5, 'file_changes': 500,
                'entropy': 8.9, 'proto_TCP': 0, 'proto_UDP': 1
            }
        }
    ]
    
    print(f"\nRunning enhanced predictions on {len(test_cases)} test cases...")
    print("-" * 70)
    
    for i, test_case in enumerate(test_cases, 1):
        result = detector.predict_single(test_case['features'])
        
        print(f"\n{i}. {test_case['name']}:")
        print(f"   🔍 Prediction: {result['prediction'].upper()}")
        print(f"   📊 Confidence: {result['confidence']:.4f}")
        print(f"   ⚠️  Threat Level: {result['threat_level']}")
        print(f"   📈 Probabilities: Benign={result['probabilities']['benign']:.4f}, Malicious={result['probabilities']['malicious']:.4f}")
        print(f"   🤖 Model: {result['model_info']['type']} ({result['model_info']['features_used']} features)")
        
        if result['is_malicious']:
            if result['threat_level'] == 'CRITICAL':
                print("   🚨 ALERT: Critical ransomware threat detected! Immediate action required!")
            elif result['threat_level'] == 'HIGH':
                print("   ⚠️  WARNING: High probability ransomware detected!")
            else:
                print("   ⚠️  CAUTION: Potential ransomware activity detected.")
        else:
            print("   ✅ SAFE: Traffic appears benign.")
    
    # Show feature importance
    print(f"\n{'='*70}")
    print("ENHANCED FEATURE IMPORTANCE ANALYSIS")
    print(f"{'='*70}")
    
    importance = detector.get_feature_importance()
    print("\nTop 10 Most Important Features:")
    print(importance.head(10).to_string(index=False))
    
    # Model information
    if detector.metadata:
        print(f"\n{'='*70}")
        print("MODEL INFORMATION & PERFORMANCE")
        print(f"{'='*70}")
        performance = detector.metadata.get('performance', {})
        print(f"Training Accuracy: {performance.get('mean_accuracy', 'N/A'):.4f}")
        print(f"Model Stability: {performance.get('model_stability', 'Unknown')}")
        print(f"Training Date: {detector.metadata.get('training_date', 'Unknown')[:10]}")
        print(f"Deadbolt Integration: v{detector.metadata.get('deadbolt_integration', {}).get('version', '1.0')}")
    
    print(f"\n{'='*70}")
    print("DEMO COMPLETED - Enhanced Model Ready for Deadbolt Premium!")
    print(f"{'='*70}")

def demo_prediction():
    print("=" * 60)
    print("RANSOMWARE DETECTION DEMO")
    print("=" * 60)
    
    # Initialize detector
    detector = RansomwareDetector()
    
    # Sample test cases
    test_cases = [
        {
            'name': 'High Entropy Traffic (Likely Malicious)',
            'features': {
                'duration': 4, 'orig_bytes': 9206, 'resp_bytes': 727, 
                'orig_pkts': 314, 'resp_pkts': 3, 'file_changes': 334, 
                'entropy': 8.27, 'proto_TCP': 1, 'proto_UDP': 1
            }
        },
        {
            'name': 'Low Entropy Traffic (Likely Benign)', 
            'features': {
                'duration': 12, 'orig_bytes': 1053, 'resp_bytes': 3870,
                'orig_pkts': 50, 'resp_pkts': 45, 'file_changes': 3,
                'entropy': 2.64, 'proto_TCP': 1, 'proto_UDP': 1
            }
        },
        {
            'name': 'Custom Test Case',
            'features': {
                'duration': 3, 'orig_bytes': 15000, 'resp_bytes': 500,
                'orig_pkts': 200, 'resp_pkts': 10, 'file_changes': 400,
                'entropy': 7.5, 'proto_TCP': 1, 'proto_UDP': 0
            }
        }
    ]
    
    print(f"\\nRunning predictions on {len(test_cases)} test cases...")
    print("-" * 60)
    
    for test_case in test_cases:
        result = detector.predict_single(test_case['features'])
        
        print(f"\\n{test_case['name']}:")
        print(f"  Prediction: {result['prediction'].upper()}")
        print(f"  Confidence: {result['confidence']:.4f}")
        print(f"  Benign probability: {result['probabilities']['benign']:.4f}")
        print(f"  Malicious probability: {result['probabilities']['malicious']:.4f}")
        
        if result['is_malicious']:
            print("  ⚠️  WARNING: Potential ransomware detected!")
        else:
            print("  ✅ Traffic appears benign")
    
    # Show feature importance
    print(f"\\n{'='*60}")
    print("FEATURE IMPORTANCE ANALYSIS")
    print(f"{'='*60}")
    
    importance = detector.get_feature_importance()
    print("\\nTop 5 Most Important Features:")
    print(importance.head().to_string(index=False))
    
    print(f"\\n{'='*60}")
    print("DEMO COMPLETED - Model ready for production use!")
    print(f"{'='*60}")

def interactive_mode():
    """Interactive prediction mode"""
    detector = RansomwareDetector()
    
    print(f"\\n{'='*60}")
    print("INTERACTIVE RANSOMWARE DETECTION")
    print(f"{'='*60}")
    print("Enter network traffic features (or 'quit' to exit):")
    
    while True:
        print(f"\\n{'-'*40}")
        try:
            # Get user input
            print("Enter traffic features (press Enter for default malicious example):")
            
            features = {}
            defaults = {
                'duration': 4, 'orig_bytes': 9206, 'resp_bytes': 727,
                'orig_pkts': 314, 'resp_pkts': 3, 'file_changes': 334,
                'entropy': 8.27, 'proto_TCP': 1, 'proto_UDP': 1
            }
            
            for feature_name in detector.feature_names:
                user_input = input(f"{feature_name} (default: {defaults[feature_name]}): ").strip()
                
                if user_input.lower() == 'quit':
                    return
                
                if user_input == "":
                    features[feature_name] = defaults[feature_name]
                else:
                    try:
                        features[feature_name] = float(user_input)
                    except ValueError:
                        print(f"Invalid input, using default: {defaults[feature_name]}")
                        features[feature_name] = defaults[feature_name]
            
            # Make prediction
            result = detector.predict_single(features)
            
            print(f"\\n{'='*40}")
            print("PREDICTION RESULT")
            print(f"{'='*40}")
            print(f"Prediction: {result['prediction'].upper()}")
            print(f"Confidence: {result['confidence']:.4f}")
            print(f"Probabilities: Benign={result['probabilities']['benign']:.4f}, "
                  f"Malicious={result['probabilities']['malicious']:.4f}")
            
            if result['is_malicious']:
                print("⚠️  WARNING: Potential ransomware detected!")
            else:
                print("✅ Traffic appears benign")
                
        except KeyboardInterrupt:
            print("\\n\\nExiting...")
            break
        except Exception as e:
            print(f"Error: {str(e)}")

def main():
    """Main function with enhanced demo"""
    print("Enhanced Ransomware Detection System - Deadbolt Premium Integration")
    print("1. Enhanced demo with threat levels")
    print("2. Interactive prediction")
    print("3. Basic demo (legacy)")
    print("")

    choice = input("\\nSelect mode (1-3): ").strip()
    
    if choice == "1":
        demo_enhanced_prediction()
    elif choice == "2":
        interactive_mode()
    elif choice == "3":
        demo_prediction()  # Legacy function
    else:
        print("Invalid choice. Running enhanced demo...")
        demo_enhanced_prediction()

if __name__ == "__main__":
    main()