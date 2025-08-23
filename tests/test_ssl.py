import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
from datetime import datetime, timedelta

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner.ssl_checker import SSLChecker
from utils.risk_engine import RiskLevel

class TestSSLChecker(unittest.TestCase):
    """Test cases for SSLChecker class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.ssl_checker = SSLChecker(timeout=5)
        self.test_target = "example.com"
    
    def test_ssl_checker_initialization(self):
        """Test SSL checker initialization"""
        self.assertEqual(self.ssl_checker.timeout, 5)
        self.assertIsNotNone(self.ssl_checker.risk_engine)
        self.assertIsInstance(self.ssl_checker.weak_ciphers, list)
        self.assertIsInstance(self.ssl_checker.weak_protocols, list)
    
    def test_weak_cipher_detection(self):
        """Test weak cipher detection"""
        weak_ciphers = ['RC4-SHA', 'DES-CBC-SHA', '3DES-EDE-CBC-SHA']
        
        for cipher in weak_ciphers:
            with self.subTest(cipher=cipher):
                self.ssl_checker._check_weak_ciphers([cipher])
                findings = self.ssl_checker.risk_engine.findings
                self.assertGreater(len(findings), 0)
                self.assertEqual(findings[-1].vuln_type, "Weak Cipher Suite")
                self.assertEqual(findings[-1].risk_level, RiskLevel.MEDIUM)
    
    def test_weak_protocol_detection(self):
        """Test weak protocol detection"""
        protocol_support = {
            'SSLv2': True,
            'SSLv3': True,
            'TLSv1.0': True,
            'TLSv1.2': True
        }
        
        self.ssl_checker._check_weak_protocols(protocol_support)
        findings = self.ssl_checker.risk_engine.findings
        
        # Should find 3 weak protocols (SSLv2, SSLv3, TLSv1.0)
        weak_protocol_findings = [f for f in findings if 'Weak SSL/TLS Protocol' in f.vuln_type]
        self.assertEqual(len(weak_protocol_findings), 3)
        
        for finding in weak_protocol_findings:
            self.assertEqual(finding.risk_level, RiskLevel.HIGH)
    
    def test_certificate_validity_expired(self):
        """Test expired certificate detection"""
        # Mock expired certificate
        expired_date = (datetime.now() - timedelta(days=30)).isoformat()
        cert_info = {
            'not_valid_before': (datetime.now() - timedelta(days=365)).isoformat(),
            'not_valid_after': expired_date,
            'subject': {'commonName': 'example.com'},
            'issuer': {'commonName': 'Test CA'}
        }
        
        self.ssl_checker._check_certificate_validity(cert_info)
        findings = self.ssl_checker.risk_engine.findings
        
        expired_findings = [f for f in findings if 'Expired SSL Certificate' in f.vuln_type]
        self.assertEqual(len(expired_findings), 1)
        self.assertEqual(expired_findings[0].risk_level, RiskLevel.HIGH)
    
    def test_certificate_validity_expiring_soon(self):
        """Test certificate expiring soon detection"""
        # Mock certificate expiring in 15 days
        expiring_date = (datetime.now() + timedelta(days=15)).isoformat()
        cert_info = {
            'not_valid_before': (datetime.now() - timedelta(days=30)).isoformat(),
            'not_valid_after': expiring_date,
            'subject': {'commonName': 'example.com'},
            'issuer': {'commonName': 'Test CA'}
        }
        
        self.ssl_checker._check_certificate_validity(cert_info)
        findings = self.ssl_checker.risk_engine.findings
        
        expiring_findings = [f for f in findings if 'Expiring Soon' in f.vuln_type]
        self.assertEqual(len(expiring_findings), 1)
        self.assertEqual(expiring_findings[0].risk_level, RiskLevel.MEDIUM)
    
    def test_self_signed_certificate(self):
        """Test self-signed certificate detection"""
        # Mock self-signed certificate (subject == issuer)
        cert_info = {
            'not_valid_before': (datetime.now() - timedelta(days=30)).isoformat(),
            'not_valid_after': (datetime.now() + timedelta(days=365)).isoformat(),
            'subject': {'commonName': 'example.com'},
            'issuer': {'commonName': 'example.com'}  # Same as subject
        }
        
        self.ssl_checker._check_certificate_validity(cert_info)
        findings = self.ssl_checker.risk_engine.findings
        
        self_signed_findings = [f for f in findings if 'Self-Signed' in f.vuln_type]
        self.assertEqual(len(self_signed_findings), 1)
        self.assertEqual(self_signed_findings[0].risk_level, RiskLevel.MEDIUM)
    
    def test_weak_key_size(self):
        """Test weak key size detection"""
        # Mock certificate with weak key size
        cert_info = {
            'not_valid_before': (datetime.now() - timedelta(days=30)).isoformat(),
            'not_valid_after': (datetime.now() + timedelta(days=365)).isoformat(),
            'subject': {'commonName': 'example.com'},
            'issuer': {'commonName': 'Test CA'},
            'public_key_size': 1024  # Weak key size
        }
        
        self.ssl_checker._check_certificate_validity(cert_info)
        findings = self.ssl_checker.risk_engine.findings
        
        weak_key_findings = [f for f in findings if 'Weak SSL Key Size' in f.vuln_type]
        self.assertEqual(len(weak_key_findings), 1)
        self.assertEqual(weak_key_findings[0].risk_level, RiskLevel.HIGH)
    
    def test_ssl_grade_calculation(self):
        """Test SSL grade calculation"""
        # Test different risk scenarios
        test_cases = [
            ({'Critical': 1, 'High': 0, 'Medium': 0}, 'F'),
            ({'Critical': 0, 'High': 3, 'Medium': 0}, 'D'),
            ({'Critical': 0, 'High': 1, 'Medium': 0}, 'C'),
            ({'Critical': 0, 'High': 0, 'Medium': 3}, 'B'),
            ({'Critical': 0, 'High': 0, 'Medium': 1}, 'B+'),
            ({'Critical': 0, 'High': 0, 'Medium': 0}, 'A')
        ]
        
        for risk_summary, expected_grade in test_cases:
            with self.subTest(risk_summary=risk_summary):
                # Mock risk summary
                with patch.object(self.ssl_checker.risk_engine, 'get_risk_summary', return_value=risk_summary):
                    grade = self.ssl_checker._calculate_ssl_grade()
                    self.assertEqual(grade, expected_grade)
    
    def test_heartbleed_test(self):
        """Test Heartbleed vulnerability test"""
        # This is a simplified test since actual Heartbleed testing is complex
        result = self.ssl_checker._test_heartbleed(self.test_target, 443)
        self.assertIsInstance(result, bool)
    
    def test_poodle_test(self):
        """Test POODLE vulnerability test"""
        # This is a simplified test
        result = self.ssl_checker._test_poodle(self.test_target, 443)
        self.assertIsInstance(result, bool)
    
    def test_ssl_summary_generation(self):
        """Test SSL summary generation"""
        # Add some test findings
        from utils.risk_engine import VulnerabilityFinding
        
        finding = VulnerabilityFinding(
            vuln_type="Weak Cipher Suite",
            description="Server supports weak cipher",
            risk_level=RiskLevel.MEDIUM
        )
        
        self.ssl_checker.risk_engine.add_finding(finding)
        summary = self.ssl_checker.get_ssl_summary()
        
        self.assertIn('total_findings', summary)
        self.assertIn('risk_summary', summary)
        self.assertIn('overall_score', summary)
        self.assertIn('ssl_grade', summary)
        self.assertIn('recommendations', summary)
        
        self.assertEqual(summary['total_findings'], 1)
        self.assertEqual(summary['risk_summary']['Medium'], 1)

if __name__ == '__main__':
    unittest.main()
