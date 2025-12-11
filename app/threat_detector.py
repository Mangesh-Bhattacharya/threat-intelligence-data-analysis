"""
Advanced Threat Detection Engine
Real-time threat identification and classification system
"""

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Tuple
import hashlib
import re

class ThreatDetector:
    """
    Core threat detection engine with multi-layered security analysis
    """
    
    def __init__(self):
        self.threat_signatures = self._load_threat_signatures()
        self.ioc_database = self._load_ioc_database()
        self.detection_rules = self._load_detection_rules()
        
    def _load_threat_signatures(self) -> Dict:
        """Load known threat signatures"""
        return {
            'malware': {
                'wannacry': 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'emotet': 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3',
                'trickbot': '2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae'
            },
            'phishing': {
                'patterns': [
                    r'urgent.*account.*suspended',
                    r'verify.*identity.*immediately',
                    r'click.*here.*claim.*prize'
                ]
            },
            'ddos': {
                'request_threshold': 1000,
                'time_window': 60
            }
        }
    
    def _load_ioc_database(self) -> Dict:
        """Load Indicators of Compromise (IOCs)"""
        return {
            'malicious_ips': [
                '192.168.100.50',
                '10.0.0.99',
                '172.16.0.88'
            ],
            'malicious_domains': [
                'malicious-site.com',
                'phishing-bank.net',
                'fake-update.org'
            ],
            'malicious_hashes': [
                'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
                'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3'
            ]
        }
    
    def _load_detection_rules(self) -> List[Dict]:
        """Load YARA-style detection rules"""
        return [
            {
                'name': 'Suspicious PowerShell Execution',
                'severity': 'High',
                'pattern': r'powershell.*-encodedcommand',
                'category': 'Execution'
            },
            {
                'name': 'Credential Dumping Attempt',
                'severity': 'Critical',
                'pattern': r'mimikatz|lsass\.exe',
                'category': 'Credential Access'
            },
            {
                'name': 'Lateral Movement',
                'severity': 'High',
                'pattern': r'psexec|wmic.*process',
                'category': 'Lateral Movement'
            }
        ]
    
    def analyze_network_traffic(self, traffic_data: pd.DataFrame) -> Dict:
        """
        Analyze network traffic for threats
        
        Args:
            traffic_data: DataFrame with columns [timestamp, src_ip, dst_ip, protocol, bytes]
        
        Returns:
            Dictionary with threat analysis results
        """
        threats_detected = []
        
        # Check for DDoS patterns
        ip_request_counts = traffic_data.groupby('src_ip').size()
        ddos_threshold = self.threat_signatures['ddos']['request_threshold']
        
        for ip, count in ip_request_counts.items():
            if count > ddos_threshold:
                threats_detected.append({
                    'type': 'DDoS',
                    'severity': 'High',
                    'source': ip,
                    'details': f'Excessive requests: {count} in time window',
                    'confidence': 0.85
                })
        
        # Check against IOC database
        for idx, row in traffic_data.iterrows():
            if row['src_ip'] in self.ioc_database['malicious_ips']:
                threats_detected.append({
                    'type': 'Malicious IP',
                    'severity': 'Critical',
                    'source': row['src_ip'],
                    'details': 'Known malicious IP in IOC database',
                    'confidence': 0.95
                })
        
        return {
            'total_analyzed': len(traffic_data),
            'threats_found': len(threats_detected),
            'threats': threats_detected,
            'analysis_time': datetime.now().isoformat()
        }
    
    def detect_malware(self, file_hash: str, file_name: str = None) -> Dict:
        """
        Detect malware based on file hash
        
        Args:
            file_hash: SHA-256 hash of the file
            file_name: Optional filename for additional analysis
        
        Returns:
            Detection results
        """
        is_malicious = file_hash in self.ioc_database['malicious_hashes']
        
        # Check against known malware signatures
        malware_family = None
        for family, hash_val in self.threat_signatures['malware'].items():
            if file_hash == hash_val:
                malware_family = family
                break
        
        return {
            'is_malicious': is_malicious,
            'malware_family': malware_family,
            'file_hash': file_hash,
            'file_name': file_name,
            'severity': 'Critical' if is_malicious else 'Clean',
            'confidence': 0.98 if is_malicious else 0.0,
            'scan_time': datetime.now().isoformat()
        }
    
    def analyze_phishing_email(self, email_content: str, sender: str) -> Dict:
        """
        Analyze email for phishing indicators
        
        Args:
            email_content: Email body text
            sender: Sender email address
        
        Returns:
            Phishing analysis results
        """
        phishing_score = 0
        indicators = []
        
        # Check against phishing patterns
        for pattern in self.threat_signatures['phishing']['patterns']:
            if re.search(pattern, email_content, re.IGNORECASE):
                phishing_score += 30
                indicators.append(f'Suspicious pattern: {pattern}')
        
        # Check sender domain
        if '@' in sender:
            domain = sender.split('@')[1]
            if domain in self.ioc_database['malicious_domains']:
                phishing_score += 50
                indicators.append(f'Known malicious domain: {domain}')
        
        # Check for suspicious links
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, email_content)
        
        if len(urls) > 5:
            phishing_score += 20
            indicators.append(f'Excessive URLs: {len(urls)}')
        
        is_phishing = phishing_score >= 50
        
        return {
            'is_phishing': is_phishing,
            'phishing_score': min(phishing_score, 100),
            'severity': 'High' if is_phishing else 'Low',
            'indicators': indicators,
            'sender': sender,
            'confidence': phishing_score / 100,
            'analysis_time': datetime.now().isoformat()
        }
    
    def detect_anomalous_behavior(self, user_activity: pd.DataFrame) -> Dict:
        """
        Detect anomalous user behavior patterns
        
        Args:
            user_activity: DataFrame with user activity logs
        
        Returns:
            Anomaly detection results
        """
        anomalies = []
        
        # Analyze login times
        if 'login_time' in user_activity.columns:
            user_activity['hour'] = pd.to_datetime(user_activity['login_time']).dt.hour
            
            # Flag logins outside business hours (9 AM - 6 PM)
            off_hours = user_activity[
                (user_activity['hour'] < 9) | (user_activity['hour'] > 18)
            ]
            
            if len(off_hours) > 0:
                anomalies.append({
                    'type': 'Off-hours Access',
                    'severity': 'Medium',
                    'count': len(off_hours),
                    'details': 'User activity detected outside business hours'
                })
        
        # Analyze access patterns
        if 'resource_accessed' in user_activity.columns:
            resource_counts = user_activity['resource_accessed'].value_counts()
            
            # Flag excessive access to single resource
            if resource_counts.max() > 100:
                anomalies.append({
                    'type': 'Excessive Resource Access',
                    'severity': 'High',
                    'resource': resource_counts.idxmax(),
                    'count': resource_counts.max(),
                    'details': 'Unusual access pattern detected'
                })
        
        return {
            'anomalies_detected': len(anomalies),
            'anomalies': anomalies,
            'total_activities': len(user_activity),
            'risk_score': min(len(anomalies) * 25, 100),
            'analysis_time': datetime.now().isoformat()
        }
    
    def correlate_threats(self, threat_events: List[Dict]) -> Dict:
        """
        Correlate multiple threat events to identify attack campaigns
        
        Args:
            threat_events: List of individual threat events
        
        Returns:
            Correlation analysis results
        """
        # Group threats by source IP
        ip_groups = {}
        for event in threat_events:
            source = event.get('source', 'unknown')
            if source not in ip_groups:
                ip_groups[source] = []
            ip_groups[source].append(event)
        
        # Identify potential attack campaigns
        campaigns = []
        for source, events in ip_groups.items():
            if len(events) >= 3:  # Multiple events from same source
                campaigns.append({
                    'source': source,
                    'event_count': len(events),
                    'threat_types': list(set([e.get('type') for e in events])),
                    'severity': 'Critical',
                    'confidence': 0.9
                })
        
        return {
            'total_events': len(threat_events),
            'unique_sources': len(ip_groups),
            'campaigns_detected': len(campaigns),
            'campaigns': campaigns,
            'correlation_time': datetime.now().isoformat()
        }
    
    def generate_threat_report(self, analysis_results: Dict) -> str:
        """
        Generate human-readable threat report
        
        Args:
            analysis_results: Results from threat analysis
        
        Returns:
            Formatted threat report
        """
        report = f"""
        ╔══════════════════════════════════════════════════════════╗
        ║           THREAT INTELLIGENCE REPORT                     ║
        ╚══════════════════════════════════════════════════════════╝
        
        Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        SUMMARY
        -------
        Total Threats Detected: {analysis_results.get('threats_found', 0)}
        Severity: {analysis_results.get('max_severity', 'N/A')}
        Confidence: {analysis_results.get('avg_confidence', 0):.2%}
        
        THREAT BREAKDOWN
        ----------------
        """
        
        for threat in analysis_results.get('threats', []):
            report += f"""
        • Type: {threat.get('type')}
          Severity: {threat.get('severity')}
          Source: {threat.get('source')}
          Details: {threat.get('details')}
          Confidence: {threat.get('confidence', 0):.2%}
        """
        
        report += f"""
        
        RECOMMENDATIONS
        ---------------
        1. Block identified malicious IPs immediately
        2. Update firewall rules to prevent similar attacks
        3. Conduct forensic analysis on affected systems
        4. Review and update security policies
        5. Implement additional monitoring for identified patterns
        
        ═══════════════════════════════════════════════════════════
        """
        
        return report
