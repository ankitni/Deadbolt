"""Deadbolt Ransomware Defender - ML-Enhanced Threat Detector
This module imports the ML-enhanced threat detector that replaces the original rule-based detection."""

# Import the ML-enhanced detector
from .ml_detector import MLThreatDetector as ThreatDetector

# For backward compatibility, export the main function
def main():
    """Test the ML-enhanced detector independently."""
    import time
    from datetime import datetime
    
    def test_responder_callback(response_info):
        print(f"RESPONSE TRIGGERED: {response_info}")
    
    detector = ThreatDetector(test_responder_callback)
    detector.start_monitoring()
    
    # Test ML capabilities
    print("🤖 Testing ML-Enhanced Threat Detector...")
    
    # Simulate some threats with network information
    test_threats = [
        {
            'type': 'mass_delete',
            'severity': 'HIGH',
            'description': 'Test mass deletion',
            'count': 15,
            'process_info': [(1234, 'test.exe')],
            'network_info': {
                'orig_port': 49123,
                'resp_port': 6667,  # IRC port - suspicious
                'protocol': 'tcp',
                'service': 'irc',
                'duration': 2.5,
                'orig_bytes': 75,
                'resp_bytes': 243,
                'conn_state': 'S3'
            }
        },
        {
            'type': 'mass_modification',
            'severity': 'CRITICAL',
            'description': 'Test mass file encryption',
            'count': 50,
            'process_info': [(5678, 'malware.exe')],
            'network_info': {
                'orig_port': 45123,
                'resp_port': 80,
                'protocol': 'tcp',
                'service': 'http',
                'duration': 1.5,
                'orig_bytes': 512,
                'resp_bytes': 8192,
                'conn_state': 'SF'
            }
        }
    ]
    
    try:
        for i, threat in enumerate(test_threats, 1):
            print(f"\nTest {i}: {threat['description']}")
            detector.analyze_threat(threat)
            time.sleep(2)
        
        print("\nPress Ctrl+C to stop.")
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\nStopping ML detector...")
        detector.stop_monitoring()
        print("ML detector stopped.")

if __name__ == "__main__":
    import time
    main()