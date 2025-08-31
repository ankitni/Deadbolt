#!/usr/bin/env python3
"""
Test script to generate ML activity and verify dashboard display
"""

import sys
import os
import time
sys.path.insert(0, 'src')

def generate_ml_activity():
    """Generate some ML activity to test the dashboard"""
    print("Generating ML Activity for Dashboard Testing")
    print("=" * 50)
    
    try:
        from core.ml_detector import MLThreatDetector
        
        # Create detector instance
        def response_callback(response_info):
            print(f"Response triggered: {response_info.get('level', 'Unknown')} - {response_info.get('description', 'No description')}")
        
        detector = MLThreatDetector(response_callback)
        detector.start_monitoring()
        
        print("✅ ML detector initialized and monitoring started")
        
        # Generate some test threats with ML analysis
        test_threats = [
            {
                'type': 'mass_modification',
                'severity': 'HIGH',
                'description': 'Test mass file encryption (IRC pattern)',
                'count': 25,
                'process_info': [(1234, 'ransomware_test.exe')],
                'network_info': {
                    'orig_port': 45123,
                    'resp_port': 6667,  # IRC port - should trigger high ML confidence
                    'protocol': 'tcp',
                    'service': 'irc',
                    'duration': 2.5,
                    'orig_bytes': 75,
                    'resp_bytes': 243,
                    'conn_state': 'S3'
                }
            },
            {
                'type': 'mass_deletion',
                'severity': 'CRITICAL',
                'description': 'Test mass file deletion (HTTP pattern)',
                'count': 50,
                'process_info': [(5678, 'malware_test.exe')],
                'network_info': {
                    'orig_port': 49123,
                    'resp_port': 80,
                    'protocol': 'tcp',
                    'service': 'http',
                    'duration': 1.5,
                    'orig_bytes': 512,
                    'resp_bytes': 8192,
                    'conn_state': 'SF'
                }
            },
            {
                'type': 'mass_rename',
                'severity': 'MEDIUM',
                'description': 'Test mass file rename (Unknown service)',
                'count': 15,
                'process_info': [(9999, 'suspicious_test.exe')],
                'network_info': {
                    'orig_port': 60123,
                    'resp_port': 12345,
                    'protocol': 'tcp',
                    'service': 'unknown',
                    'duration': 0.8,
                    'orig_bytes': 128,
                    'resp_bytes': 64,
                    'conn_state': 'S1'
                }
            }
        ]
        
        print(f"📊 Processing {len(test_threats)} test threats...")
        
        for i, threat in enumerate(test_threats, 1):
            print(f"\n🔍 Processing test threat {i}: {threat['description']}")
            detector.analyze_threat(threat)
            time.sleep(1)  # Small delay between threats
        
        print("\n📈 Getting ML statistics...")
        stats = detector.get_ml_statistics()
        
        print("ML Statistics Summary:")
        print(f"  • Model Loaded: {stats.get('model_loaded', False)}")
        print(f"  • Total Predictions: {stats.get('total_predictions', 0)}")
        print(f"  • Malicious Detected: {stats.get('malicious_detected', 0)}")
        print(f"  • Benign Classified: {stats.get('benign_classified', 0)}")
        print(f"  • High Confidence Alerts: {stats.get('high_confidence_alerts', 0)}")
        print(f"  • Average Confidence: {stats.get('average_confidence', 0.0):.3f}")
        
        print("\n📋 Recent ML logs:")
        logs = detector.get_recent_ml_logs(limit=5)
        for log in logs[-3:]:  # Show last 3 logs
            print(f"  [{log.get('level', 'INFO')}] {log.get('message', 'No message')[:80]}...")
        
        detector.stop_monitoring()
        
        print("\n" + "=" * 50)
        print("✅ ML ACTIVITY GENERATION COMPLETE!")
        print("📊 The ML dashboard should now show activity")
        print("🚀 Open the GUI and check the ML Analytics tab")
        print("=" * 50)
        
        return True
        
    except Exception as e:
        print(f"❌ Error generating ML activity: {e}")
        import traceback
        traceback.print_exc()
        return False

def check_ml_logs():
    """Check current ML log status"""
    print("\nChecking ML Log Status")
    print("=" * 30)
    
    try:
        log_file = "logs/ml_detector.log"
        if os.path.exists(log_file):
            with open(log_file, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            print(f"📄 ML log file: {len(lines)} total lines")
            
            # Count different log levels
            levels = {'CRITICAL': 0, 'WARNING': 0, 'INFO': 0, 'ERROR': 0}
            for line in lines:
                for level in levels:
                    if f' - {level} - ' in line:
                        levels[level] += 1
                        break
            
            print("Log Level Distribution:")
            for level, count in levels.items():
                if count > 0:
                    print(f"  • {level}: {count} entries")
            
            # Show recent entries
            print("\nRecent ML Log Entries:")
            for line in lines[-5:]:  # Last 5 lines
                if line.strip():
                    # Extract timestamp and level
                    parts = line.strip().split(' - ', 2)
                    if len(parts) >= 3:
                        timestamp = parts[0]
                        level = parts[1]
                        message = parts[2][:60] + "..." if len(parts[2]) > 60 else parts[2]
                        print(f"  [{level}] {message}")
        else:
            print(f"❌ ML log file not found: {log_file}")
            
    except Exception as e:
        print(f"❌ Error checking logs: {e}")

def main():
    print("🤖 ML Dashboard Activity Generator")
    print("=" * 60)
    
    # Check current log status
    check_ml_logs()
    
    # Generate new activity
    success = generate_ml_activity()
    
    # Check updated log status
    check_ml_logs()
    
    print("\n" + "=" * 60)
    if success:
        print("🎉 ML ACTIVITY GENERATED SUCCESSFULLY!")
        print("💡 Next steps:")
        print("  1. Open the GUI: python run_full_gui.py")
        print("  2. Go to the 'ML Analytics' tab")
        print("  3. Check the ML statistics and logs")
        print("  4. The dashboard should now show ML activity!")
    else:
        print("❌ FAILED TO GENERATE ML ACTIVITY")
        print("Please check the error messages above")
    print("=" * 60)

if __name__ == "__main__":
    main()