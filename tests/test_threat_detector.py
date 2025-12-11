"""
Unit Tests for Threat Detection Engine
Comprehensive test coverage for security functions
"""

import pytest
import pandas as pd
import numpy as np
from datetime import datetime
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app.threat_detector import ThreatDetector

class TestThreatDetector:
    """Test suite for ThreatDetector class"""
    
    @pytest.fixture
    def detector(self):
        """Create ThreatDetector instance for testing"""
        return ThreatDetector()
    
    @pytest.fixture
    def sample_traffic_data(self):
        """Generate sample network traffic data"""
        return pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=100, freq='1min'),
            'src_ip': [f'192.168.1.{i%255}' for i in range(100)],
            'dst_ip': [f'10.0.0.{i%255}' for i in range(100)],
            'protocol': np.random.choice(['TCP', 'UDP', 'ICMP'], 100),
            'bytes': np.random.randint(100, 10000, 100)
        })
    
    def test_detector_initialization(self, detector):
        """Test detector initializes correctly"""
        assert detector is not None
        assert detector.threat_signatures is not None
        assert detector.ioc_database is not None
        assert detector.detection_rules is not None
    
    def test_load_threat_signatures(self, detector):
        """Test threat signatures are loaded"""
        signatures = detector.threat_signatures
        
        assert 'malware' in signatures
        assert 'phishing' in signatures
        assert 'ddos' in signatures
        assert len(signatures['malware']) > 0
    
    def test_load_ioc_database(self, detector):
        """Test IOC database is loaded"""
        ioc_db = detector.ioc_database
        
        assert 'malicious_ips' in ioc_db
        assert 'malicious_domains' in ioc_db
        assert 'malicious_hashes' in ioc_db
        assert len(ioc_db['malicious_ips']) > 0
    
    def test_analyze_network_traffic(self, detector, sample_traffic_data):
        """Test network traffic analysis"""
        result = detector.analyze_network_traffic(sample_traffic_data)
        
        assert 'total_analyzed' in result
        assert 'threats_found' in result
        assert 'threats' in result
        assert 'analysis_time' in result
        assert result['total_analyzed'] == len(sample_traffic_data)
    
    def test_detect_ddos_attack(self, detector):
        """Test DDoS attack detection"""
        # Create traffic data with DDoS pattern
        ddos_data = pd.DataFrame({
            'timestamp': pd.date_range(start='2024-01-01', periods=2000, freq='1s'),
            'src_ip': ['192.168.1.100'] * 2000,  # Same source IP
            'dst_ip': ['10.0.0.1'] * 2000,
            'protocol': ['TCP'] * 2000,
            'bytes': [100] * 2000
        })
        
        result = detector.analyze_network_traffic(ddos_data)
        
        assert result['threats_found'] > 0
        assert any(threat['type'] == 'DDoS' for threat in result['threats'])
    
    def test_detect_malware_positive(self, detector):
        """Test malware detection with known malicious hash"""
        malicious_hash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
        
        result = detector.detect_malware(malicious_hash, 'suspicious.exe')
        
        assert result['is_malicious'] == True
        assert result['severity'] == 'Critical'
        assert result['confidence'] > 0.9
    
    def test_detect_malware_negative(self, detector):
        """Test malware detection with clean hash"""
        clean_hash = 'abc123def456789'
        
        result = detector.detect_malware(clean_hash, 'clean.txt')
        
        assert result['is_malicious'] == False
        assert result['severity'] == 'Clean'
        assert result['confidence'] == 0.0
    
    def test_analyze_phishing_email_positive(self, detector):
        """Test phishing email detection with suspicious content"""
        phishing_content = """
        URGENT: Your account has been suspended!
        Click here immediately to verify your identity and restore access.
        """
        
        result = detector.analyze_phishing_email(phishing_content, 'scammer@malicious-site.com')
        
        assert result['is_phishing'] == True
        assert result['phishing_score'] >= 50
        assert len(result['indicators']) > 0
    
    def test_analyze_phishing_email_negative(self, detector):
        """Test phishing email detection with legitimate content"""
        legitimate_content = "Hello, this is a normal business email."
        
        result = detector.analyze_phishing_email(legitimate_content, 'user@legitimate.com')
        
        assert result['phishing_score'] < 50
    
    def test_detect_anomalous_behavior(self, detector):
        """Test anomalous behavior detection"""
        user_activity = pd.DataFrame({
            'login_time': pd.date_range(start='2024-01-01 02:00', periods=10, freq='1H'),
            'resource_accessed': ['file.txt'] * 150,
            'user_id': ['user123'] * 150
        })
        
        result = detector.detect_anomalous_behavior(user_activity)
        
        assert 'anomalies_detected' in result
        assert 'anomalies' in result
        assert 'risk_score' in result
    
    def test_correlate_threats(self, detector):
        """Test threat correlation"""
        threat_events = [
            {'type': 'Malware', 'source': '192.168.1.100', 'severity': 'High'},
            {'type': 'DDoS', 'source': '192.168.1.100', 'severity': 'High'},
            {'type': 'Intrusion', 'source': '192.168.1.100', 'severity': 'Critical'},
            {'type': 'Phishing', 'source': '10.0.0.50', 'severity': 'Medium'}
        ]
        
        result = detector.correlate_threats(threat_events)
        
        assert result['total_events'] == 4
        assert result['unique_sources'] == 2
        assert result['campaigns_detected'] >= 1
    
    def test_generate_threat_report(self, detector):
        """Test threat report generation"""
        analysis_results = {
            'threats_found': 5,
            'max_severity': 'Critical',
            'avg_confidence': 0.85,
            'threats': [
                {
                    'type': 'Malware',
                    'severity': 'Critical',
                    'source': '192.168.1.100',
                    'details': 'Known malware detected',
                    'confidence': 0.95
                }
            ]
        }
        
        report = detector.generate_threat_report(analysis_results)
        
        assert isinstance(report, str)
        assert 'THREAT INTELLIGENCE REPORT' in report
        assert 'Malware' in report
        assert 'Critical' in report


class TestThreatDetectorEdgeCases:
    """Test edge cases and error handling"""
    
    @pytest.fixture
    def detector(self):
        return ThreatDetector()
    
    def test_empty_traffic_data(self, detector):
        """Test handling of empty traffic data"""
        empty_data = pd.DataFrame()
        
        result = detector.analyze_network_traffic(empty_data)
        
        assert result['total_analyzed'] == 0
        assert result['threats_found'] == 0
    
    def test_malformed_email(self, detector):
        """Test handling of malformed email"""
        result = detector.analyze_phishing_email("", "invalid-email")
        
        assert 'phishing_score' in result
        assert result['phishing_score'] >= 0
    
    def test_invalid_hash_format(self, detector):
        """Test handling of invalid hash format"""
        result = detector.detect_malware("invalid", "test.exe")
        
        assert result['is_malicious'] == False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
