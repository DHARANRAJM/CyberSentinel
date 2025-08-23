import unittest
from unittest.mock import Mock, patch, MagicMock
import sys
import os

# Add src directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from scanner.port_scanner import PortScanner
from utils.risk_engine import RiskLevel

class TestPortScanner(unittest.TestCase):
    """Test cases for PortScanner class"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.scanner = PortScanner(timeout=1, max_threads=10)
        self.test_target = "127.0.0.1"
    
    def test_scanner_initialization(self):
        """Test scanner initialization"""
        self.assertEqual(self.scanner.timeout, 1)
        self.assertEqual(self.scanner.max_threads, 10)
        self.assertIsNotNone(self.scanner.nm)
        self.assertIsNotNone(self.scanner.risk_engine)
    
    @patch('scanner.port_scanner.nmap.PortScanner')
    def test_nmap_scan_success(self, mock_nmap):
        """Test successful nmap scan"""
        # Mock nmap results
        mock_nm = Mock()
        mock_nm.all_hosts.return_value = [self.test_target]
        mock_nm.__getitem__.return_value = {
            'tcp': {
                80: {
                    'state': 'open',
                    'name': 'http',
                    'version': 'Apache 2.4',
                    'product': 'Apache httpd',
                    'extrainfo': ''
                },
                443: {
                    'state': 'open',
                    'name': 'https',
                    'version': '',
                    'product': '',
                    'extrainfo': ''
                }
            }
        }
        mock_nm[self.test_target].all_protocols.return_value = ['tcp']
        mock_nm[self.test_target]['tcp'].keys.return_value = [80, 443]
        
        mock_nmap.return_value = mock_nm
        self.scanner.nm = mock_nm
        
        # Run scan
        results = self.scanner.scan_target(self.test_target, "80,443")
        
        # Verify results
        self.assertEqual(results['target'], self.test_target)
        self.assertIn(80, results['open_ports'])
        self.assertIn(443, results['open_ports'])
        self.assertEqual(len(results['open_ports']), 2)
        
        # Check service information
        self.assertEqual(results['services'][80]['service'], 'http')
        self.assertEqual(results['services'][80]['version'], 'Apache 2.4')
    
    def test_identify_service(self):
        """Test service identification by port"""
        test_cases = [
            (22, 'ssh'),
            (80, 'http'),
            (443, 'https'),
            (21, 'ftp'),
            (25, 'smtp'),
            (9999, 'unknown')
        ]
        
        for port, expected_service in test_cases:
            with self.subTest(port=port):
                service = self.scanner._identify_service(port)
                self.assertEqual(service, expected_service)
    
    def test_port_risk_assessment(self):
        """Test port risk assessment"""
        # High risk ports
        high_risk_ports = [21, 23, 135, 139, 445, 1433, 3389, 5432]
        for port in high_risk_ports:
            with self.subTest(port=port):
                risk = self.scanner.risk_engine.assess_port_risk(port)
                self.assertEqual(risk, RiskLevel.HIGH)
        
        # Medium risk ports
        medium_risk_ports = [22, 25, 53, 110, 143]
        for port in medium_risk_ports:
            with self.subTest(port=port):
                risk = self.scanner.risk_engine.assess_port_risk(port)
                self.assertEqual(risk, RiskLevel.MEDIUM)
        
        # Well-known ports (< 1024) should be medium risk
        risk = self.scanner.risk_engine.assess_port_risk(80)
        self.assertEqual(risk, RiskLevel.MEDIUM)
        
        # High ports should be low risk
        risk = self.scanner.risk_engine.assess_port_risk(8080)
        self.assertEqual(risk, RiskLevel.LOW)
    
    @patch('scanner.port_scanner.socket.socket')
    def test_socket_scan_fallback(self, mock_socket):
        """Test socket-based scanning fallback"""
        # Mock successful connection
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 0  # Success
        mock_socket.return_value = mock_sock
        
        # Test port check
        is_open, service = self.scanner._check_port(self.test_target, 80)
        
        self.assertTrue(is_open)
        self.assertEqual(service, 'http')
        mock_sock.connect_ex.assert_called_once_with((self.test_target, 80))
        mock_sock.close.assert_called_once()
    
    @patch('scanner.port_scanner.socket.socket')
    def test_socket_scan_closed_port(self, mock_socket):
        """Test socket scan with closed port"""
        # Mock failed connection
        mock_sock = Mock()
        mock_sock.connect_ex.return_value = 1  # Connection refused
        mock_socket.return_value = mock_sock
        
        # Test port check
        is_open, service = self.scanner._check_port(self.test_target, 9999)
        
        self.assertFalse(is_open)
        self.assertEqual(service, '')
    
    def test_get_port_remediation(self):
        """Test port remediation advice"""
        # Test high-risk port remediation
        remediation = self.scanner._get_port_remediation(21, 'ftp')
        self.assertIn('FTP', remediation)
        self.assertIn('SFTP', remediation)
        
        remediation = self.scanner._get_port_remediation(23, 'telnet')
        self.assertIn('Telnet', remediation)
        self.assertIn('SSH', remediation)
        
        # Test generic remediation
        remediation = self.scanner._get_port_remediation(8080, 'http-alt')
        self.assertIn('service', remediation.lower())
        self.assertIn('secured', remediation.lower())
    
    def test_scan_summary(self):
        """Test scan summary generation"""
        # Add some test findings
        from utils.risk_engine import VulnerabilityFinding
        
        finding1 = VulnerabilityFinding(
            vuln_type="Open Port - SSH",
            description="SSH port is open",
            risk_level=RiskLevel.MEDIUM,
            details={'port': 22}
        )
        
        finding2 = VulnerabilityFinding(
            vuln_type="Open Port - Telnet",
            description="Telnet port is open",
            risk_level=RiskLevel.HIGH,
            details={'port': 23}
        )
        
        self.scanner.risk_engine.add_finding(finding1)
        self.scanner.risk_engine.add_finding(finding2)
        
        summary = self.scanner.get_scan_summary()
        
        self.assertEqual(summary['total_findings'], 2)
        self.assertEqual(summary['risk_summary']['High'], 1)
        self.assertEqual(summary['risk_summary']['Medium'], 1)
        self.assertGreater(summary['overall_score'], 0)
        self.assertIsInstance(summary['recommendations'], list)
        self.assertGreater(len(summary['recommendations']), 0)

if __name__ == '__main__':
    unittest.main()
