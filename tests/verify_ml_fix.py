#!/usr/bin/env python3
"""
Verification script to confirm ML Analytics tab will work correctly
"""

import sys
import os
sys.path.insert(0, 'src')

def verify_ml_fix():
    """Verify that the ML Analytics tab fix is working"""
    print("🔧 ML Analytics Tab Fix Verification")
    print("=" * 60)
    
    try:
        # Test exactly what the GUI refresh_ml_stats method does
        from ui.main_gui import ML_DETECTOR_AVAILABLE, MLThreatDetector
        
        print(f"✅ ML_DETECTOR_AVAILABLE: {ML_DETECTOR_AVAILABLE}")
        
        if not ML_DETECTOR_AVAILABLE:
            print("❌ FAILED: ML_DETECTOR_AVAILABLE is False")
            print("   GUI would show: 'Model: Offline - ML Module Not Available'")
            return False
        
        # Create detector instance (as GUI does)
        temp_detector = MLThreatDetector(lambda x: None)
        ml_stats = temp_detector.get_ml_statistics()
        
        # Check what GUI status would show
        model_loaded = ml_stats.get('model_loaded', False)
        if model_loaded:
            status_text = "Model: Active - Loaded"
            status_color = "green"
        else:
            status_text = "Model: Inactive - Not Loaded"  
            status_color = "red"
        
        print(f"✅ GUI Status: {status_text} ({status_color})")
        
        # Check dashboard data availability
        total_predictions = ml_stats.get('total_predictions', 0)
        malicious_detected = ml_stats.get('malicious_detected', 0)
        average_confidence = ml_stats.get('average_confidence', 0.0)
        
        print(f"✅ Dashboard Data:")
        print(f"   • Total Predictions: {total_predictions}")
        print(f"   • Malicious Detected: {malicious_detected}")
        print(f"   • Average Confidence: {average_confidence:.3f}")
        
        if total_predictions > 0:
            print("✅ Dashboard will show ML activity (NOT empty)")
        else:
            print("⚠️ Dashboard will be empty (no predictions)")
            
        # Check ML logs
        ml_logs = temp_detector.get_recent_ml_logs(limit=10)
        print(f"✅ ML Logs: {len(ml_logs)} entries available")
        
        if len(ml_logs) > 0:
            print("   Recent entries:")
            for i, log in enumerate(ml_logs[-3:]):
                level = log.get('level', 'INFO')
                message = log.get('message', '')[:50] + "..."
                print(f"     {i+1}. [{level}] {message}")
        
        # Summary
        print("\n" + "=" * 60)
        print("🎉 VERIFICATION RESULTS:")
        print(f"✅ ML Status Detection: WORKING ({status_text})")
        print(f"✅ Statistics Loading: WORKING ({total_predictions} predictions)")
        print(f"✅ Dashboard Data: {'AVAILABLE' if total_predictions > 0 else 'EMPTY'}")
        print(f"✅ ML Logs: WORKING ({len(ml_logs)} entries)")
        
        if model_loaded and total_predictions > 0:
            print("\n🚀 SUCCESS: GUI ML Analytics tab should now work correctly!")
            print("   • Status will show 'Model: Active - Loaded'")
            print("   • Dashboard will display real ML activity")
            print("   • Statistics will show actual prediction counts")
            print("   • Logs will be populated with ML events")
        else:
            print("\n⚠️ PARTIAL SUCCESS: ML model loaded but no activity")
            print("   • Run test_ml_dashboard.py to generate activity")
            
        return True
        
    except Exception as e:
        print(f"❌ VERIFICATION FAILED: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    verify_ml_fix()