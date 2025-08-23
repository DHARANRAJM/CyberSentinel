import ssl
import socket
import datetime
import subprocess
import re
from typing import Dict, List, Any, Tuple
import requests
from urllib.parse import urlparse
from cryptography import x509
from cryptography.hazmat.backends import default_backend

from ..utils.logger import logger
from ..utils.risk_engine import RiskEngine, VulnerabilityFinding, RiskLevel

class SSLChecker:
    """SSL/TLS security analyzer"""
    
    def __init__(self, timeout: int = 10):
        self.timeout = timeout
        self.risk_engine = RiskEngine()
        
        # Weak cipher suites to detect
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'SHA1', 'NULL',
            'EXPORT', 'ADH', 'AECDH', 'PSK', 'SRP'
        ]
        
        # Weak protocols
        self.weak_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0']
    
    def check_ssl_security(self, target: str, port: int = 443) -> Dict[str, Any]:
        """
        Comprehensive SSL/TLS security check
        
        Args:
            target: Hostname or IP to check
            port: Port to check (default 443)
            
        Returns:
            Dictionary containing SSL security analysis
        """
        logger.info(f"Starting SSL/TLS security check for {target}:{port}")
        
        ssl_results = {
            'target': target,
            'port': port,
            'timestamp': datetime.datetime.now().isoformat(),
            'certificate_info': {},
            'protocol_support': {},
            'cipher_suites': [],
            'vulnerabilities': [],
            'overall_grade': 'Unknown'
        }
        
        try:
            # Get certificate information
            cert_info = self._get_certificate_info(target, port)
            ssl_results['certificate_info'] = cert_info
            
            # Check certificate validity
            self._check_certificate_validity(cert_info)
            
            # Test protocol support
            protocol_support = self._test_protocol_support(target, port)
            ssl_results['protocol_support'] = protocol_support
            
            # Check for weak protocols
            self._check_weak_protocols(protocol_support)
            
            # Get supported cipher suites
            cipher_suites = self._get_cipher_suites(target, port)
            ssl_results['cipher_suites'] = cipher_suites
            
            # Check for weak ciphers
            self._check_weak_ciphers(cipher_suites)
            
            # Check for common SSL vulnerabilities
            self._check_ssl_vulnerabilities(target, port)
            
            # Calculate overall grade
            ssl_results['overall_grade'] = self._calculate_ssl_grade()
            
            logger.info(f"SSL/TLS check completed. Grade: {ssl_results['overall_grade']}")
            
        except Exception as e:
            logger.error(f"SSL/TLS check failed: {str(e)}")
            ssl_results['error'] = str(e)
        
        return ssl_results
    
    def _get_certificate_info(self, target: str, port: int) -> Dict[str, Any]:
        """Extract certificate information"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            # Connect and get certificate
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_info = ssock.getpeercert()
            
            # Parse certificate with cryptography library
            cert = x509.load_der_x509_certificate(cert_der, default_backend())
            
            # Extract detailed certificate information
            cert_details = {
                'subject': self._parse_certificate_name(cert.subject),
                'issuer': self._parse_certificate_name(cert.issuer),
                'version': cert.version.name,
                'serial_number': str(cert.serial_number),
                'not_valid_before': cert.not_valid_before.isoformat(),
                'not_valid_after': cert.not_valid_after.isoformat(),
                'signature_algorithm': cert.signature_algorithm_oid._name,
                'public_key_algorithm': cert.public_key().__class__.__name__,
                'public_key_size': cert.public_key().key_size if hasattr(cert.public_key(), 'key_size') else 'Unknown',
                'is_ca': False,
                'san_dns_names': [],
                'san_ip_addresses': []
            }
            
            # Extract Subject Alternative Names
            try:
                san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
                for name in san_ext.value:
                    if isinstance(name, x509.DNSName):
                        cert_details['san_dns_names'].append(name.value)
                    elif isinstance(name, x509.IPAddress):
                        cert_details['san_ip_addresses'].append(str(name.value))
            except x509.ExtensionNotFound:
                pass
            
            # Check if it's a CA certificate
            try:
                basic_constraints = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.BASIC_CONSTRAINTS)
                cert_details['is_ca'] = basic_constraints.value.ca
            except x509.ExtensionNotFound:
                pass
            
            return cert_details
            
        except Exception as e:
            logger.error(f"Failed to get certificate info: {str(e)}")
            return {'error': str(e)}
    
    def _parse_certificate_name(self, name) -> Dict[str, str]:
        """Parse certificate name attributes safely"""
        try:
            result = {}
            for attribute in name:
                # Get the attribute name
                oid = attribute.oid
                value = attribute.value
                
                # Map common OIDs to readable names
                oid_name_map = {
                    '2.5.4.3': 'commonName',
                    '2.5.4.6': 'countryName', 
                    '2.5.4.7': 'localityName',
                    '2.5.4.8': 'stateOrProvinceName',
                    '2.5.4.10': 'organizationName',
                    '2.5.4.11': 'organizationalUnitName',
                    '1.2.840.113549.1.9.1': 'emailAddress'
                }
                
                # Use mapped name or dotted string representation
                attr_name = oid_name_map.get(oid.dotted_string, oid.dotted_string)
                result[attr_name] = value
                
            return result
        except Exception as e:
            logger.debug(f"Error parsing certificate name: {str(e)}")
            return {}
    
    def _check_certificate_validity(self, cert_info: Dict[str, Any]):
        """Check certificate validity and create findings"""
        if 'error' in cert_info:
            return
        
        try:
            now = datetime.datetime.now()
            not_before = datetime.datetime.fromisoformat(cert_info['not_valid_before'].replace('Z', '+00:00'))
            not_after = datetime.datetime.fromisoformat(cert_info['not_valid_after'].replace('Z', '+00:00'))
            
            # Check if certificate is expired
            if now > not_after:
                finding = VulnerabilityFinding(
                    vuln_type="Expired SSL Certificate",
                    description="SSL certificate has expired",
                    risk_level=RiskLevel.HIGH,
                    details={'expiry_date': cert_info['not_valid_after']},
                    remediation="Renew SSL certificate immediately"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found("Expired SSL Certificate", "High", f"Expired on {cert_info['not_valid_after']}")
            
            # Check if certificate expires soon (within 30 days)
            elif (not_after - now).days <= 30:
                finding = VulnerabilityFinding(
                    vuln_type="SSL Certificate Expiring Soon",
                    description=f"SSL certificate expires in {(not_after - now).days} days",
                    risk_level=RiskLevel.MEDIUM,
                    details={'expiry_date': cert_info['not_valid_after']},
                    remediation="Plan certificate renewal"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found("SSL Certificate Expiring Soon", "Medium", f"Expires {cert_info['not_valid_after']}")
            
            # Check if certificate is not yet valid
            if now < not_before:
                finding = VulnerabilityFinding(
                    vuln_type="SSL Certificate Not Yet Valid",
                    description="SSL certificate is not yet valid",
                    risk_level=RiskLevel.HIGH,
                    details={'valid_from': cert_info['not_valid_before']},
                    remediation="Check system time or certificate validity period"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found("SSL Certificate Not Yet Valid", "High")
            
            # Check for self-signed certificate
            if cert_info.get('subject') == cert_info.get('issuer'):
                finding = VulnerabilityFinding(
                    vuln_type="Self-Signed SSL Certificate",
                    description="SSL certificate is self-signed",
                    risk_level=RiskLevel.MEDIUM,
                    details={'issuer': str(cert_info.get('issuer'))},
                    remediation="Use certificate from trusted Certificate Authority"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found("Self-Signed SSL Certificate", "Medium")
            
            # Check key size
            key_size = cert_info.get('public_key_size')
            if isinstance(key_size, int) and key_size < 2048:
                finding = VulnerabilityFinding(
                    vuln_type="Weak SSL Key Size",
                    description=f"SSL certificate uses weak key size: {key_size} bits",
                    risk_level=RiskLevel.HIGH,
                    details={'key_size': key_size},
                    remediation="Use at least 2048-bit RSA or 256-bit ECC keys"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found("Weak SSL Key Size", "High", f"{key_size} bits")
            
        except Exception as e:
            logger.error(f"Certificate validity check failed: {str(e)}")
    
    def _test_protocol_support(self, target: str, port: int) -> Dict[str, bool]:
        """Test which SSL/TLS protocols are supported"""
        protocols = {
            'SSLv2': ssl.PROTOCOL_SSLv23,  # Will be rejected by modern systems
            'SSLv3': ssl.PROTOCOL_SSLv23,
            'TLSv1.0': ssl.PROTOCOL_TLSv1,
            'TLSv1.1': ssl.PROTOCOL_TLSv1_1,
            'TLSv1.2': ssl.PROTOCOL_TLSv1_2,
        }
        
        # Add TLS 1.3 if available
        if hasattr(ssl, 'PROTOCOL_TLSv1_3'):
            protocols['TLSv1.3'] = ssl.PROTOCOL_TLSv1_3
        
        supported_protocols = {}
        
        for protocol_name, protocol_const in protocols.items():
            try:
                context = ssl.SSLContext(protocol_const)
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock) as ssock:
                        supported_protocols[protocol_name] = True
                        logger.debug(f"Protocol {protocol_name} is supported")
            except:
                supported_protocols[protocol_name] = False
        
        return supported_protocols
    
    def _check_weak_protocols(self, protocol_support: Dict[str, bool]):
        """Check for weak protocol support"""
        for protocol in self.weak_protocols:
            if protocol_support.get(protocol, False):
                finding = VulnerabilityFinding(
                    vuln_type=f"Weak SSL/TLS Protocol - {protocol}",
                    description=f"Server supports weak protocol: {protocol}",
                    risk_level=RiskLevel.HIGH,
                    details={'protocol': protocol},
                    remediation=f"Disable {protocol} support and use TLS 1.2 or higher"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found(f"Weak Protocol {protocol}", "High")
    
    def _get_cipher_suites(self, target: str, port: int) -> List[str]:
        """Get list of supported cipher suites"""
        cipher_suites = []
        
        try:
            # Use OpenSSL command if available
            result = subprocess.run([
                'openssl', 's_client', '-connect', f'{target}:{port}',
                '-cipher', 'ALL', '-brief'
            ], capture_output=True, text=True, timeout=self.timeout)
            
            if result.returncode == 0:
                # Parse cipher information from output
                for line in result.stdout.split('\n'):
                    if 'Cipher:' in line:
                        cipher = line.split('Cipher:')[1].strip()
                        if cipher and cipher != '0000':
                            cipher_suites.append(cipher)
        except:
            # Fallback to Python SSL context
            try:
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                with socket.create_connection((target, port), timeout=self.timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=target) as ssock:
                        cipher_info = ssock.cipher()
                        if cipher_info:
                            cipher_suites.append(cipher_info[0])
            except Exception as e:
                logger.debug(f"Failed to get cipher suites: {str(e)}")
        
        return cipher_suites
    
    def _check_weak_ciphers(self, cipher_suites: List[str]):
        """Check for weak cipher suites"""
        for cipher in cipher_suites:
            for weak_cipher in self.weak_ciphers:
                if weak_cipher.upper() in cipher.upper():
                    finding = VulnerabilityFinding(
                        vuln_type="Weak Cipher Suite",
                        description=f"Server supports weak cipher: {cipher}",
                        risk_level=RiskLevel.MEDIUM,
                        details={'cipher': cipher, 'weakness': weak_cipher},
                        remediation="Disable weak cipher suites and use strong encryption"
                    )
                    self.risk_engine.add_finding(finding)
                    logger.vulnerability_found(f"Weak Cipher {cipher}", "Medium")
                    break
    
    def _check_ssl_vulnerabilities(self, target: str, port: int):
        """Check for known SSL vulnerabilities"""
        # Check for Heartbleed (CVE-2014-0160)
        if self._test_heartbleed(target, port):
            finding = VulnerabilityFinding(
                vuln_type="Heartbleed Vulnerability (CVE-2014-0160)",
                description="Server is vulnerable to Heartbleed attack",
                risk_level=RiskLevel.CRITICAL,
                details={'cve': 'CVE-2014-0160'},
                remediation="Update OpenSSL to version 1.0.1g or later immediately"
            )
            self.risk_engine.add_finding(finding)
            logger.vulnerability_found("Heartbleed Vulnerability", "Critical")
        
        # Check for POODLE vulnerability
        if self._test_poodle(target, port):
            finding = VulnerabilityFinding(
                vuln_type="POODLE Vulnerability (CVE-2014-3566)",
                description="Server is vulnerable to POODLE attack",
                risk_level=RiskLevel.HIGH,
                details={'cve': 'CVE-2014-3566'},
                remediation="Disable SSLv3 support"
            )
            self.risk_engine.add_finding(finding)
            logger.vulnerability_found("POODLE Vulnerability", "High")
    
    def _test_heartbleed(self, target: str, port: int) -> bool:
        """Test for Heartbleed vulnerability"""
        # Simplified Heartbleed test - in production, use specialized tools
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    # Check if server uses OpenSSL and version
                    cert = ssock.getpeercert()
                    # This is a simplified check - real Heartbleed testing requires
                    # sending malformed heartbeat requests
                    return False  # Placeholder
        except:
            return False
    
    def _test_poodle(self, target: str, port: int) -> bool:
        """Test for POODLE vulnerability"""
        try:
            # POODLE affects SSLv3
            context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
            context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1_2
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((target, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock) as ssock:
                    return True  # SSLv3 is supported, potentially vulnerable
        except:
            return False  # SSLv3 not supported
    
    def _calculate_ssl_grade(self) -> str:
        """Calculate overall SSL grade based on findings"""
        risk_summary = self.risk_engine.get_risk_summary()
        
        if risk_summary['Critical'] > 0:
            return 'F'
        elif risk_summary['High'] > 2:
            return 'D'
        elif risk_summary['High'] > 0:
            return 'C'
        elif risk_summary['Medium'] > 2:
            return 'B'
        elif risk_summary['Medium'] > 0:
            return 'B+'
        else:
            return 'A'
    
    def get_ssl_summary(self) -> Dict[str, Any]:
        """Get SSL security summary"""
        return {
            'total_findings': len(self.risk_engine.findings),
            'risk_summary': self.risk_engine.get_risk_summary(),
            'overall_score': self.risk_engine.calculate_overall_score(),
            'ssl_grade': self._calculate_ssl_grade(),
            'recommendations': self.risk_engine.generate_recommendations()
        }
