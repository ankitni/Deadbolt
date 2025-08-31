#!/usr/bin/env python3
"""
Test script to exactly replicate what the GUI refresh_ml_stats method does
"""

import sys
import os
sys.path.insert(0, 'src')

def test_gui_exact_behavior():
    """Test the exact same logic as the GUI refresh_ml_stats method"""
    print("Testing Exact GUI ML Refresh Behavior")
    print("=" * 50)
    
    # Import exactly as the GUI does
    try:
        from ui.main_gui import ML_DETECTOR_AVAILABLE, MLThreatDetector
        print(f"1. ✅ GUI Import successful - ML_DETECTOR_AVAILABLE: {ML_DETECTOR_AVAILABLE}")
    except Exception as e:
        print(f"❌ GUI Import failed: {e}")
        return False
    
    # Test the exact logic from refresh_ml_stats
    if not ML_DETECTOR_AVAILABLE:
        print("❌ ML_DETECTOR_AVAILABLE is False - this would show 'ML not activated'")
        return False
    
    # Try to get ML statistics exactly as GUI does
    try:
        # Create temporary instance to get stats (as GUI does)
        temp_detector = MLThreatDetector(lambda x: None)
        ml_stats = temp_detector.get_ml_statistics()
        
        print("2. ✅ ML detector created successfully")
        print(f"   Model loaded: {ml_stats.get('model_loaded', False)}")
        print(f"   Features: {ml_stats.get('model_features', 0)}")
        print(f"   Monitoring active: {ml_stats.get('monitoring_active', False)}")
        print(f"   Total predictions: {ml_stats.get('total_predictions', 0)}")
        print(f"   Malicious detected: {ml_stats.get('malicious_detected', 0)}")
        print(f"   Benign classified: {ml_stats.get('benign_classified', 0)}")
        print(f"   High confidence: {ml_stats.get('high_confidence_alerts', 0)}")
        print(f"   Average confidence: {ml_stats.get('average_confidence', 0.0):.3f}")
        
        # Determine what the GUI status would show
        if ml_stats.get('model_loaded', False):
            status = "Model: Active - Loaded"
            status_color = "green"
        else:
            status = "Model: Inactive - Not Loaded"
            status_color = "red"
        
        print(f"\n3. GUI Status Display:")
        print(f"   Status: {status} (color: {status_color})")
        
        # Check if we have any predictions to display
        total_preds = ml_stats.get('total_predictions', 0)
        if total_preds > 0:
            print(f"   ✅ Dashboard would show {total_preds} predictions")
        else:
            print(f"   ⚠️ Dashboard would show 0 predictions (empty)")
        
        return True
        
    except Exception as e:
        print(f"❌ Error getting ML stats exactly as GUI does: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_gui_logs():
    """Test the exact same logic as the GUI refresh_ml_logs method"""
    print("\nTesting Exact GUI ML Logs Behavior")
    print("=" * 40)
    
    try:
        from ui.main_gui import ML_DETECTOR_AVAILABLE, MLThreatDetector
        
        if not ML_DETECTOR_AVAILABLE:
            print("❌ ML_DETECTOR_AVAILABLE is False - logs would show 'not available'")
            return False
        
        # Try to get ML logs exactly as GUI does
        temp_detector = MLThreatDetector(lambda x: None)
        ml_logs = temp_detector.get_recent_ml_logs(limit=100)
        
        print(f"✅ ML logs retrieved: {len(ml_logs)} entries")
        
        if len(ml_logs) > 0:
            print("Recent log entries (as GUI would show):")
            for i, log_entry in enumerate(ml_logs[-5:]):  # Last 5 like GUI
                timestamp = log_entry.get('timestamp', '')
                level = log_entry.get('level', 'INFO')
                message = log_entry.get('message', '')[:60] + "..."
                print(f"   {i+1}. [{level}] {timestamp} - {message}")
        else:
            print("⚠️ No ML logs found - dashboard would be empty")
        
        return True
        
    except Exception as e:
        print(f"❌ Error getting ML logs exactly as GUI does: {e}")
        return False

def main():
    print("🔍 GUI Exact Behavior Test")
    print("=" * 60)
    
    test1_passed = test_gui_exact_behavior()
    test2_passed = test_gui_logs()
    
    print("\n" + "=" * 60)
    if test1_passed and test2_passed:
        print("🎉 GUI SHOULD BE WORKING CORRECTLY!")
        print("✅ ML status detection working")
        print("✅ ML statistics available") 
        print("✅ ML logs available")
        print("\n💡 If GUI still shows 'ML not activated':")
        print("   1. Make sure to refresh the ML tab")
        print("   2. Check if GUI is importing from the right path")
        print("   3. Try restarting the GUI application")
        print("\n🚀 Start GUI: python run_full_gui.py")
    else:
        print("❌ ISSUES DETECTED!")
        print("The GUI behavior replication found problems")
    print("=" * 60)

if __name__ == "__main__":
    main()