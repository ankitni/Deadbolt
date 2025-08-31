#!/usr/bin/env python3
"""Quick test for ML dashboard status"""

import sys
import os
sys.path.insert(0, 'src')

def quick_test():
    print("Quick ML Dashboard Test")
    print("=" * 30)
    
    try:
        from core.ml_detector import MLThreatDetector
        
        # Create detector
        detector = MLThreatDetector(lambda x: None)
        stats = detector.get_ml_statistics()
        
        print("Current ML Status:")
        print(f"  Model Loaded: {stats.get('model_loaded', False)}")
        print(f"  Features: {stats.get('model_features', 0)}")
        print(f"  Monitoring: {stats.get('monitoring_active', False)}")
        print(f"  Predictions: {stats.get('total_predictions', 0)}")
        
        # Test a simple threat
        test_threat = {
            'type': 'mass_modification',
            'severity': 'HIGH', 
            'description': 'Quick test threat',
            'count': 10,
            'process_info': [(1111, 'test.exe')],
            'network_info': {
                'orig_port': 50000,
                'resp_port': 6667,
                'protocol': 'tcp', 
                'service': 'irc',
                'duration': 1.0,
                'orig_bytes': 100,
                'resp_bytes': 200,
                'conn_state': 'SF'
            }
        }
        
        print("\nProcessing test threat...")
        detector.analyze_threat(test_threat)
        
        # Get updated stats
        updated_stats = detector.get_ml_statistics()
        print(f"After test - Predictions: {updated_stats.get('total_predictions', 0)}")
        print(f"After test - Malicious: {updated_stats.get('malicious_detected', 0)}")
        
        return True
        
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    quick_test()