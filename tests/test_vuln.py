import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os
import requests

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner.vuln_checker import VulnerabilityChecker
from utils.risk_engine import RiskLevel

class TestVulnerabilityChecker(unittest.TestCase):
    """Test cases for VulnerabilityChecker class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.vuln_checker = VulnerabilityChecker(timeout=5, delay=0.1)
        self.test_target = "example.com"
        self.test_port = 80
    
    def test_vuln_checker_initialization(self):
        """Test vulnerability checker initialization"""
        self.assertEqual(self.vuln_checker.timeout, 5)
        self.assertEqual(self.vuln_checker.delay, 0.1)
        self.assertIsNotNone(self.vuln_checker.risk_engine)
        self.assertIsInstance(self.vuln_checker.sql_payloads, list)
        self.assertIsInstance(self.vuln_checker.xss_payloads, list)
        self.assertIsInstance(self.vuln_checker.lfi_payloads, list)
    
    @patch('scanner.vuln_checker.requests.Session.request')
    def test_make_request_success(self, mock_request):
        """Test successful HTTP request"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<html><body>Test</body></html>"
        mock_response.headers = {'Content-Type': 'text/html'}
        mock_request.return_value = mock_response
        
        response = self.vuln_checker._make_request('GET', 'http://example.com')
        
        self.assertIsNotNone(response)
        self.assertEqual(response.status_code, 200)
        mock_request.assert_called_once()
    
    @patch('scanner.vuln_checker.requests.Session.request')
    def test_make_request_failure(self, mock_request):
        """Test failed HTTP request"""
        # Mock request exception
        mock_request.side_effect = requests.RequestException("Connection failed")
        
        response = self.vuln_checker._make_request('GET', 'http://example.com')
        
        self.assertIsNone(response)
    
    @patch('scanner.vuln_checker.requests.Session.request')
    def test_check_security_headers(self, mock_request):
        """Test security headers check"""
        # Mock response with missing security headers
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'Content-Type': 'text/html',
            'X-Frame-Options': 'DENY'  # Only one security header present
        }
        mock_request.return_value = mock_response
        
        headers = self.vuln_checker._check_security_headers('http://example.com')
        
        # Should detect missing headers
        self.assertIn('X-Frame-Options', headers)
        self.assertEqual(headers['X-Frame-Options'], 'DENY')
        self.assertIsNone(headers.get('X-XSS-Protection'))
        
        # Should create finding for missing headers
        findings = self.vuln_checker.risk_engine.findings
        missing_header_findings = [f for f in findings if 'Missing Security Headers' in f.vuln_type]
        self.assertGreater(len(missing_header_findings), 0)
    
    def test_discover_forms(self):
        """Test form discovery from HTML"""
        html_content = '''
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
            <form action="/search" method="GET">
                <input type="text" name="query" />
                <input type="submit" value="Search" />
            </form>
        </body>
        </html>
        '''
        
        with patch('scanner.vuln_checker.VulnerabilityChecker._make_request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.text = html_content
            mock_request.return_value = mock_response
            
            forms = self.vuln_checker._discover_forms('http://example.com', ['/'])
            
            self.assertEqual(len(forms), 2)
            
            # Check login form
            login_form = next((f for f in forms if f['action'] == '/login'), None)
            self.assertIsNotNone(login_form)
            self.assertEqual(login_form['method'], 'POST')
            self.assertEqual(len(login_form['inputs']), 2)
            
            # Check search form
            search_form = next((f for f in forms if f['action'] == '/search'), None)
            self.assertIsNotNone(search_form)
            self.assertEqual(search_form['method'], 'GET')
    
    def test_detect_sql_injection(self):
        """Test SQL injection detection"""
        # Test cases for SQL injection detection
        test_cases = [
            ("SQL syntax error", True),
            ("mysql_fetch_array() error", True),
            ("PostgreSQL ERROR", True),
            ("OLE DB SQL Server", True),
            ("Normal response", False)
        ]
        
        for response_text, should_detect in test_cases:
            with self.subTest(response_text=response_text):
                mock_response = Mock()
                mock_response.text = response_text
                mock_response.elapsed.total_seconds.return_value = 1.0
                
                result = self.vuln_checker._detect_sql_injection(mock_response, "' OR '1'='1")
                self.assertEqual(result, should_detect)
    
    def test_detect_xss(self):
        """Test XSS detection"""
        payload = "<script>alert('XSS')</script>"
        
        # Test reflected XSS
        mock_response = Mock()
        mock_response.text = f"<html><body>Hello {payload}</body></html>"
        
        result = self.vuln_checker._detect_xss(mock_response, payload)
        self.assertTrue(result)
        
        # Test no XSS
        mock_response.text = "<html><body>Hello World</body></html>"
        result = self.vuln_checker._detect_xss(mock_response, payload)
        self.assertFalse(result)
    
    def test_detect_directory_traversal(self):
        """Test directory traversal detection"""
        # Test cases for directory traversal detection
        test_cases = [
            ("root:x:0:0:root:/root:/bin/bash", True),  # /etc/passwd content
            ("[boot loader]", True),  # Windows boot.ini
            ("127.0.0.1 localhost", True),  # hosts file
            ("Normal web page content", False)
        ]
        
        for response_text, should_detect in test_cases:
            with self.subTest(response_text=response_text):
                mock_response = Mock()
                mock_response.text = response_text
                
                result = self.vuln_checker._detect_directory_traversal(mock_response)
                self.assertEqual(result, should_detect)
    
    @patch('scanner.vuln_checker.VulnerabilityChecker._make_request')
    def test_csrf_vulnerability_detection(self, mock_request):
        """Test CSRF vulnerability detection"""
        # Mock form without CSRF token
        forms = [{
            'url': 'http://example.com/form',
            'action': '/submit',
            'method': 'POST',
            'inputs': [
                {'name': 'username', 'type': 'text', 'value': ''},
                {'name': 'password', 'type': 'password', 'value': ''}
            ]
        }]
        
        self.vuln_checker._test_csrf_vulnerabilities('http://example.com', forms)
        
        # Should detect CSRF vulnerability
        findings = self.vuln_checker.risk_engine.findings
        csrf_findings = [f for f in findings if 'CSRF' in f.vuln_type]
        self.assertGreater(len(csrf_findings), 0)
        self.assertEqual(csrf_findings[0].risk_level, RiskLevel.HIGH)
    
    @patch('scanner.vuln_checker.VulnerabilityChecker._make_request')
    def test_information_disclosure(self, mock_request):
        """Test information disclosure detection"""
        # Mock response for sensitive file access
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "<?php $db_password = 'secret123'; ?>"
        mock_request.return_value = mock_response
        
        self.vuln_checker._test_information_disclosure('http://example.com')
        
        # Should detect information disclosure
        findings = self.vuln_checker.risk_engine.findings
        info_disclosure_findings = [f for f in findings if 'Information Disclosure' in f.vuln_type]
        self.assertGreater(len(info_disclosure_findings), 0)
    
    @patch('scanner.vuln_checker.VulnerabilityChecker._make_request')
    def test_dangerous_http_methods(self, mock_request):
        """Test dangerous HTTP method detection"""
        # Mock response allowing PUT method
        mock_response = Mock()
        mock_response.status_code = 200  # Method allowed
        mock_request.return_value = mock_response
        
        self.vuln_checker._test_common_misconfigurations('http://example.com')
        
        # Should detect dangerous HTTP method
        findings = self.vuln_checker.risk_engine.findings
        method_findings = [f for f in findings if 'HTTP' in f.vuln_type and 'Method' in f.vuln_type]
        self.assertGreater(len(method_findings), 0)
    
    def test_vulnerability_summary(self):
        """Test vulnerability summary generation"""
        # Add some test findings
        from utils.risk_engine import VulnerabilityFinding
        
        findings = [
            VulnerabilityFinding(
                vuln_type="SQL Injection",
                description="SQL injection in login form",
                risk_level=RiskLevel.CRITICAL
            ),
            VulnerabilityFinding(
                vuln_type="XSS",
                description="Reflected XSS in search",
                risk_level=RiskLevel.MEDIUM
            )
        ]
        
        for finding in findings:
            self.vuln_checker.risk_engine.add_finding(finding)
        
        summary = self.vuln_checker.get_vulnerability_summary()
        
        self.assertEqual(summary['total_findings'], 2)
        self.assertEqual(summary['risk_summary']['Critical'], 1)
        self.assertEqual(summary['risk_summary']['Medium'], 1)
        self.assertGreater(summary['overall_score'], 0)
        self.assertIsInstance(summary['recommendations'], list)
    
    @patch('scanner.vuln_checker.VulnerabilityChecker._test_connectivity')
    @patch('scanner.vuln_checker.VulnerabilityChecker._check_security_headers')
    @patch('scanner.vuln_checker.VulnerabilityChecker._discover_forms')
    def test_scan_web_vulnerabilities_integration(self, mock_discover, mock_headers, mock_connectivity):
        """Test complete web vulnerability scan integration"""
        # Mock successful connectivity
        mock_connectivity.return_value = True
        
        # Mock security headers
        mock_headers.return_value = {
            'X-Frame-Options': None,
            'X-XSS-Protection': None
        }
        
        # Mock form discovery
        mock_discover.return_value = [{
            'url': 'http://example.com/',
            'action': '/login',
            'method': 'POST',
            'inputs': [{'name': 'username', 'type': 'text', 'value': ''}]
        }]
        
        results = self.vuln_checker.scan_web_vulnerabilities(self.test_target, self.test_port)
        
        self.assertIn('target', results)
        self.assertIn('base_url', results)
        self.assertIn('security_headers', results)
        self.assertIn('forms_tested', results)
        self.assertEqual(results['target'], f"{self.test_target}:{self.test_port}")

if __name__ == '__main__':
    unittest.main()
