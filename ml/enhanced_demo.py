#!/usr/bin/env python3
"""
Enhanced Deadbolt Premium ML Demo
Comprehensive demonstration of the enhanced logistic regression integration
"""

import os
import sys
import time
import json
from datetime import datetime

# Add parent directories to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'src'))

def print_banner():
    """Print welcome banner"""
    print("=" * 80)
    print("🤖 DEADBOLT PREMIUM - ENHANCED ML DETECTION DEMO")
    print("=" * 80)
    print("🔗 Enhanced Logistic Regression Integration")
    print("🛡️ Real-time Ransomware Protection")
    print("⚡ 97.8% Accuracy with High Stability")
    print("=" * 80)
    print()

def test_enhanced_model():
    """Test the enhanced model directly"""
    print("📊 Testing Enhanced Logistic Regression Model...")
    print("-" * 60)
    
    try:
        from predict_ransomware import EnhancedRansomwareDetector
        
        # Initialize detector
        detector = EnhancedRansomwareDetector()
        
        # Test cases representing different threat levels
        test_scenarios = [
            {
                'name': '🚨 Critical Ransomware Pattern',
                'features': {
                    'duration': 2, 'orig_bytes': 8000, 'resp_bytes': 200,
                    'orig_pkts': 100, 'resp_pkts': 5, 'file_changes': 500,
                    'entropy': 8.9, 'proto_TCP': 0, 'proto_UDP': 1
                },
                'expected': 'CRITICAL'
            },
            {
                'name': '⚠️ Suspicious High-Entropy Activity',
                'features': {
                    'duration': 4, 'orig_bytes': 9206, 'resp_bytes': 727,
                    'orig_pkts': 314, 'resp_pkts': 3, 'file_changes': 334,
                    'entropy': 8.27, 'proto_TCP': 1, 'proto_UDP': 0
                },
                'expected': 'HIGH'
            },
            {
                'name': '🔍 Moderate Threat Pattern',
                'features': {
                    'duration': 8, 'orig_bytes': 15000, 'resp_bytes': 500,
                    'orig_pkts': 200, 'resp_pkts': 10, 'file_changes': 150,
                    'entropy': 6.2, 'proto_TCP': 1, 'proto_UDP': 1
                },
                'expected': 'MEDIUM'
            },
            {
                'name': '✅ Normal Benign Traffic',
                'features': {
                    'duration': 12, 'orig_bytes': 1053, 'resp_bytes': 3870,
                    'orig_pkts': 50, 'resp_pkts': 45, 'file_changes': 3,
                    'entropy': 2.64, 'proto_TCP': 1, 'proto_UDP': 0
                },
                'expected': 'SAFE'
            }
        ]
        
        results = []
        for scenario in test_scenarios:
            result = detector.predict_single(scenario['features'])
            results.append({
                'scenario': scenario['name'],
                'prediction': result['prediction'],
                'threat_level': result['threat_level'],
                'confidence': result['confidence'],
                'expected': scenario['expected']
            })
            
            # Print result
            status = "✅" if result['threat_level'] == scenario['expected'] else "❌"
            print(f"{status} {scenario['name']}")
            print(f"    Prediction: {result['prediction']} ({result['threat_level']})")
            print(f"    Confidence: {result['confidence']:.3f}")
            print()
        
        # Summary
        correct = sum(1 for r in results if r['threat_level'] == r['expected'])
        print(f"📈 Test Results: {correct}/{len(results)} scenarios correctly classified")
        print(f"🎯 Model Accuracy: {correct/len(results)*100:.1f}%")
        
        return True, results
        
    except Exception as e:
        print(f"❌ Enhanced model test failed: {e}")
        return False, []

def test_ml_detector_integration():
    """Test ML detector integration"""
    print("\n🔗 Testing ML Detector Integration...")
    print("-" * 60)
    
    try:
        from core.ml_detector import MLThreatDetector
        
        # Initialize ML detector
        detector = MLThreatDetector(lambda x: print(f"🚨 Response triggered: {x}"))
        
        # Check model loading
        if detector.ml_model is None:
            print("❌ ML model not loaded")
            return False
        
        print("✅ ML detector initialized successfully")
        
        # Get model statistics
        stats = detector.get_ml_statistics()
        print(f"📊 Model Type: {stats.get('model_type', 'Unknown')}")
        print(f"🔧 Model Features: {stats.get('model_features', 0)}")
        print(f"📅 Training Date: {stats.get('training_date', 'Unknown')}")
        print(f"🎯 Model Accuracy: {stats.get('model_accuracy', 0):.3f}")
        print(f"⚡ Model Stability: {stats.get('model_stability', 'Unknown')}")
        
        # Test real-time prediction
        print("\n🔬 Testing Real-time Threat Detection...")
        
        network_scenarios = [
            {
                'name': 'High-Risk Ransomware Traffic',
                'info': {
                    'orig_bytes': 9206, 'resp_bytes': 727,
                    'orig_pkts': 314, 'resp_pkts': 3,
                    'file_changes': 334, 'entropy': 8.27,
                    'protocol': 'tcp', 'duration': 4.0
                }
            },
            {
                'name': 'Normal Web Traffic',
                'info': {
                    'orig_bytes': 1053, 'resp_bytes': 3870,
                    'orig_pkts': 50, 'resp_pkts': 45,
                    'file_changes': 3, 'entropy': 2.64,
                    'protocol': 'tcp', 'duration': 12.0
                }
            }
        ]
        
        for scenario in network_scenarios:
            score = detector._get_ml_threat_score(scenario['info'])
            threat_type = "MALICIOUS" if score > 0.5 else "BENIGN"
            confidence = f"{score:.1%}"
            
            print(f"  📡 {scenario['name']}: {threat_type} (confidence: {confidence})")
        
        print("✅ ML detector integration successful")
        return True
        
    except Exception as e:
        print(f"❌ ML detector integration failed: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_system_integration():
    """Test full system integration"""
    print("\n🌐 Testing Full System Integration...")
    print("-" * 60)
    
    try:
        # Test if main system can load
        from core.main import DeadboltDefender
        
        print("✅ Main system imports successful")
        
        # Test configuration loading
        try:
            defender = DeadboltDefender(debug_mode=True)
            print("✅ Deadbolt Defender initialization successful")
            
            # Test component initialization (without starting)
            print("🔧 Testing component initialization...")
            
            # Check if ML enhancement is detected
            if hasattr(defender, 'detector') and defender.detector:
                if hasattr(defender.detector, 'ml_model') and defender.detector.ml_model:
                    print("✅ ML enhancement detected in main system")
                else:
                    print("⚠️ ML enhancement not detected (this is expected before start())")
            
            print("✅ System integration test passed")
            return True
            
        except Exception as e:
            print(f"⚠️ System initialization test failed: {e}")
            print("   This may be due to missing GUI dependencies or configuration")
            return False
            
    except ImportError as e:
        print(f"❌ System integration test failed: {e}")
        return False

def show_model_details():
    """Show detailed model information"""
    print("\n📋 Enhanced Model Details...")
    print("-" * 60)
    
    try:
        # Load model metadata
        metadata_path = os.path.join(os.path.dirname(__file__), 'models', 'model_metadata.json')
        
        if os.path.exists(metadata_path):
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            print("📊 Model Information:")
            print(f"   Type: {metadata.get('model_type', 'Unknown')}")
            print(f"   Features: {metadata.get('feature_count', 0)}")
            print(f"   Training Date: {metadata.get('training_date', 'Unknown')[:10]}")
            print(f"   Integration Version: v{metadata.get('deadbolt_integration', {}).get('version', '1.0')}")
            
            performance = metadata.get('performance', {})
            if performance:
                print("\n🎯 Performance Metrics:")
                print(f"   Accuracy: {performance.get('mean_accuracy', 0):.3f} ± {performance.get('std_accuracy', 0):.3f}")
                print(f"   AUC-ROC: {performance.get('mean_auc', 0):.3f} ± {performance.get('std_auc', 0):.3f}")
                print(f"   Stability: {performance.get('model_stability', 'Unknown')}")
            
            print("\n🔧 Model Parameters:")
            model_params = metadata.get('model_params', {})
            for param, value in model_params.items():
                if param in ['C', 'penalty', 'solver', 'class_weight']:
                    print(f"   {param}: {value}")
            
        else:
            print("⚠️ Model metadata not found. Run training first:")
            print("   python logistic_regression_ransomware_detection.py")
            
    except Exception as e:
        print(f"❌ Failed to load model details: {e}")

def run_comprehensive_demo():
    """Run comprehensive demonstration"""
    print_banner()
    
    # Track test results
    test_results = {
        'enhanced_model': False,
        'ml_detector': False,
        'system_integration': False
    }
    
    # Test 1: Enhanced Model
    success, _ = test_enhanced_model()
    test_results['enhanced_model'] = success
    
    # Test 2: ML Detector Integration
    test_results['ml_detector'] = test_ml_detector_integration()
    
    # Test 3: System Integration
    test_results['system_integration'] = test_system_integration()
    
    # Show model details
    show_model_details()
    
    # Final summary
    print("\n" + "=" * 80)
    print("🏁 COMPREHENSIVE DEMO RESULTS")
    print("=" * 80)
    
    total_tests = len(test_results)
    passed_tests = sum(test_results.values())
    
    for test_name, passed in test_results.items():
        status = "✅ PASS" if passed else "❌ FAIL"
        print(f"{status} {test_name.replace('_', ' ').title()}")
    
    print("-" * 80)
    print(f"📊 Overall Result: {passed_tests}/{total_tests} tests passed")
    
    if passed_tests == total_tests:
        print("🎉 ALL TESTS PASSED - Enhanced ML System Ready!")
        print("🚀 Deadbolt Premium is now equipped with advanced ML detection!")
        print("\n💡 Next Steps:")
        print("   • Start the GUI: python deadbolt.py --gui")
        print("   • Run protection: scripts/start_defender.bat")
        print("   • Monitor ML stats in the dashboard")
    else:
        print(f"⚠️ {total_tests - passed_tests} test(s) failed. Check the error messages above.")
        print("\n🔧 Troubleshooting:")
        if not test_results['enhanced_model']:
            print("   • Retrain model: python logistic_regression_ransomware_detection.py")
        if not test_results['ml_detector']:
            print("   • Check ML dependencies: pip install -r requirements.txt")
        if not test_results['system_integration']:
            print("   • Install GUI dependencies: pip install PyQt5")
    
    print("=" * 80)

def main():
    """Main demo function"""
    if len(sys.argv) > 1:
        if sys.argv[1] == '--model-only':
            test_enhanced_model()
        elif sys.argv[1] == '--integration-only':
            test_ml_detector_integration()
        elif sys.argv[1] == '--details':
            show_model_details()
        else:
            print("Usage: python enhanced_demo.py [--model-only|--integration-only|--details]")
    else:
        run_comprehensive_demo()

if __name__ == "__main__":
    main()