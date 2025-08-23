#!/usr/bin/env python3
"""
Vulnerability Checker Module
Part of CyberSentinel - Automated Vulnerability Assessment Tool

👨‍💻 Author: M DHARAN RAJ -- Web Developer------CISCO Trained & CISCO Certified Ethical Hacker----- 🔒
🌐 Web Developer | 🔐 CISCO Certified | ⚡ Ethical Hacker | 🛡️ Security Expert
"""

import requests
import re
import urllib.parse
from typing import Dict, List, Any, Optional
import time
import random
from bs4 import BeautifulSoup
import json

from utils.logger import logger
from utils.risk_engine import RiskEngine, VulnerabilityFinding, RiskLevel

class VulnerabilityChecker:
    """Web application vulnerability scanner"""
    
    def __init__(self, timeout: int = 10, delay: float = 1.0):
        self.timeout = timeout
        self.delay = delay  # Delay between requests to be respectful
        self.risk_engine = RiskEngine()
        self.session = requests.Session()
        
        # Common user agents to rotate
        self.user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        ]
        
        # SQL injection payloads
        self.sql_payloads = [
            "' OR '1'='1",
            "' OR 1=1--",
            "' UNION SELECT NULL--",
            "'; DROP TABLE users--",
            "' OR 'a'='a",
            "1' OR '1'='1' --",
            "admin'--",
            "' OR 1=1#"
        ]
        
        # XSS payloads
        self.xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>"
        ]
        
        # Directory traversal payloads
        self.lfi_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd"
        ]
    
    def scan_web_vulnerabilities(self, target: str, port: int = 80, paths: List[str] = None) -> Dict[str, Any]:
        """
        Comprehensive web vulnerability scan
        
        Args:
            target: Target hostname or IP
            port: Port to scan (default 80)
            paths: List of paths to test (optional)
            
        Returns:
            Dictionary containing vulnerability scan results
        """
        logger.info(f"Starting web vulnerability scan for {target}:{port}")
        
        protocol = 'https' if port == 443 else 'http'
        base_url = f"{protocol}://{target}:{port}"
        
        scan_results = {
            'target': f"{target}:{port}",
            'base_url': base_url,
            'timestamp': time.time(),
            'vulnerabilities_found': [],
            'security_headers': {},
            'forms_tested': 0,
            'total_requests': 0,
            'scan_duration': 0
        }
        
        start_time = time.time()
        
        try:
            # Test basic connectivity
            if not self._test_connectivity(base_url):
                logger.error(f"Cannot connect to {base_url}")
                return scan_results
            
            # Security headers check
            scan_results['security_headers'] = self._check_security_headers(base_url)
            
            # Discover and test forms
            forms = self._discover_forms(base_url, paths or ['/'])
            scan_results['forms_tested'] = len(forms)
            
            # Test for SQL injection
            self._test_sql_injection(base_url, forms)
            
            # Test for XSS
            self._test_xss_vulnerabilities(base_url, forms)
            
            # Test for CSRF
            self._test_csrf_vulnerabilities(base_url, forms)
            
            # Test for directory traversal/LFI
            self._test_directory_traversal(base_url, paths or ['/'])
            
            # Test for information disclosure
            self._test_information_disclosure(base_url)
            
            # Test for common misconfigurations
            self._test_common_misconfigurations(base_url)
            
            scan_duration = time.time() - start_time
            scan_results['scan_duration'] = scan_duration
            scan_results['total_requests'] = self.session.adapters['http://'].config.get('pool_connections', 0)
            
            logger.info(f"Web vulnerability scan completed in {scan_duration:.2f} seconds")
            
        except Exception as e:
            logger.error(f"Web vulnerability scan failed: {str(e)}")
            scan_results['error'] = str(e)
        
        return scan_results
    
    def _test_connectivity(self, base_url: str) -> bool:
        """Test basic connectivity to target"""
        try:
            response = self._make_request('GET', base_url)
            return response is not None
        except:
            return False
    
    def _make_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling and rate limiting"""
        try:
            # Random user agent rotation
            headers = kwargs.get('headers', {})
            headers['User-Agent'] = random.choice(self.user_agents)
            kwargs['headers'] = headers
            
            # Set timeout
            kwargs['timeout'] = self.timeout
            kwargs['verify'] = False  # Ignore SSL warnings for testing
            kwargs['allow_redirects'] = True
            
            # Make request
            response = self.session.request(method, url, **kwargs)
            
            # Rate limiting
            time.sleep(self.delay)
            
            return response
            
        except requests.RequestException as e:
            logger.debug(f"Request failed for {url}: {str(e)}")
            return None
    
    def _check_security_headers(self, base_url: str) -> Dict[str, Any]:
        """Check for security headers"""
        logger.info("Checking security headers")
        
        response = self._make_request('GET', base_url)
        if not response:
            return {}
        
        security_headers = {
            'X-Frame-Options': response.headers.get('X-Frame-Options'),
            'X-XSS-Protection': response.headers.get('X-XSS-Protection'),
            'X-Content-Type-Options': response.headers.get('X-Content-Type-Options'),
            'Strict-Transport-Security': response.headers.get('Strict-Transport-Security'),
            'Content-Security-Policy': response.headers.get('Content-Security-Policy'),
            'Referrer-Policy': response.headers.get('Referrer-Policy'),
            'Permissions-Policy': response.headers.get('Permissions-Policy')
        }
        
        # Check for missing security headers
        missing_headers = []
        for header, value in security_headers.items():
            if not value:
                missing_headers.append(header)
        
        if missing_headers:
            finding = VulnerabilityFinding(
                vuln_type="Missing Security Headers",
                description=f"Missing security headers: {', '.join(missing_headers)}",
                risk_level=RiskLevel.MEDIUM,
                details={'missing_headers': missing_headers, 'present_headers': {k: v for k, v in security_headers.items() if v}},
                remediation="Implement missing security headers to prevent common attacks"
            )
            self.risk_engine.add_finding(finding)
            logger.vulnerability_found("Missing Security Headers", "Medium", f"Missing: {len(missing_headers)} headers")
        
        return security_headers
    
    def _discover_forms(self, base_url: str, paths: List[str]) -> List[Dict[str, Any]]:
        """Discover forms on the website"""
        logger.info("Discovering forms for testing")
        forms = []
        
        for path in paths:
            url = urllib.parse.urljoin(base_url, path)
            response = self._make_request('GET', url)
            
            if response and response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                page_forms = soup.find_all('form')
                
                for form in page_forms:
                    form_data = {
                        'url': url,
                        'action': form.get('action', ''),
                        'method': form.get('method', 'GET').upper(),
                        'inputs': []
                    }
                    
                    # Extract form inputs
                    inputs = form.find_all(['input', 'textarea', 'select'])
                    for input_elem in inputs:
                        input_data = {
                            'name': input_elem.get('name', ''),
                            'type': input_elem.get('type', 'text'),
                            'value': input_elem.get('value', '')
                        }
                        if input_data['name']:
                            form_data['inputs'].append(input_data)
                    
                    if form_data['inputs']:  # Only add forms with inputs
                        forms.append(form_data)
        
        logger.info(f"Discovered {len(forms)} forms for testing")
        return forms
    
    def _test_sql_injection(self, base_url: str, forms: List[Dict[str, Any]]):
        """Test for SQL injection vulnerabilities"""
        logger.info("Testing for SQL injection vulnerabilities")
        
        for form in forms:
            for payload in self.sql_payloads:
                # Test each input field
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'password', 'email', 'search']:
                        test_data = {}
                        
                        # Fill form with normal data except the test field
                        for inp in form['inputs']:
                            if inp['name'] == input_field['name']:
                                test_data[inp['name']] = payload
                            else:
                                test_data[inp['name']] = inp['value'] or 'test'
                        
                        # Submit form
                        action_url = urllib.parse.urljoin(form['url'], form['action'])
                        
                        if form['method'] == 'POST':
                            response = self._make_request('POST', action_url, data=test_data)
                        else:
                            response = self._make_request('GET', action_url, params=test_data)
                        
                        if response and self._detect_sql_injection(response, payload):
                            finding = VulnerabilityFinding(
                                vuln_type="SQL Injection",
                                description=f"SQL injection vulnerability in {input_field['name']} parameter",
                                risk_level=RiskLevel.CRITICAL,
                                details={
                                    'url': action_url,
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'method': form['method']
                                },
                                remediation="Use parameterized queries and input validation"
                            )
                            self.risk_engine.add_finding(finding)
                            logger.vulnerability_found("SQL Injection", "Critical", f"Parameter: {input_field['name']}")
                            break  # Don't test more payloads for this field
    
    def _detect_sql_injection(self, response: requests.Response, payload: str) -> bool:
        """Detect SQL injection based on response"""
        if not response:
            return False
        
        # Common SQL error patterns
        sql_errors = [
            r"SQL syntax.*MySQL",
            r"Warning.*mysql_.*",
            r"valid MySQL result",
            r"MySqlClient\.",
            r"PostgreSQL.*ERROR",
            r"Warning.*pg_.*",
            r"valid PostgreSQL result",
            r"Npgsql\.",
            r"Driver.* SQL[\-\_\ ]*Server",
            r"OLE DB.* SQL Server",
            r"(\W|\A)SQL Server.*Driver",
            r"Warning.*mssql_.*",
            r"(\W|\A)SQL Server.*[0-9a-fA-F]{8}",
            r"Exception.*\WSystem\.Data\.SqlClient\.",
            r"Exception.*\WRoadhouse\.Cms\.",
            r"Microsoft Access Driver",
            r"JET Database Engine",
            r"Access Database Engine",
            r"ODBC Microsoft Access",
            r"Syntax error.*query expression"
        ]
        
        response_text = response.text.lower()
        
        for error_pattern in sql_errors:
            if re.search(error_pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for time-based indicators (simplified)
        if response.elapsed.total_seconds() > 5:  # Unusually slow response
            return True
        
        return False
    
    def _test_xss_vulnerabilities(self, base_url: str, forms: List[Dict[str, Any]]):
        """Test for XSS vulnerabilities"""
        logger.info("Testing for XSS vulnerabilities")
        
        for form in forms:
            for payload in self.xss_payloads:
                for input_field in form['inputs']:
                    if input_field['type'] in ['text', 'email', 'search', 'textarea']:
                        test_data = {}
                        
                        for inp in form['inputs']:
                            if inp['name'] == input_field['name']:
                                test_data[inp['name']] = payload
                            else:
                                test_data[inp['name']] = inp['value'] or 'test'
                        
                        action_url = urllib.parse.urljoin(form['url'], form['action'])
                        
                        if form['method'] == 'POST':
                            response = self._make_request('POST', action_url, data=test_data)
                        else:
                            response = self._make_request('GET', action_url, params=test_data)
                        
                        if response and self._detect_xss(response, payload):
                            # Determine XSS type
                            xss_type = "Reflected XSS" if payload in response.text else "Stored XSS"
                            risk_level = RiskLevel.HIGH if xss_type == "Stored XSS" else RiskLevel.MEDIUM
                            
                            finding = VulnerabilityFinding(
                                vuln_type=xss_type,
                                description=f"{xss_type} vulnerability in {input_field['name']} parameter",
                                risk_level=risk_level,
                                details={
                                    'url': action_url,
                                    'parameter': input_field['name'],
                                    'payload': payload,
                                    'method': form['method']
                                },
                                remediation="Implement proper input validation and output encoding"
                            )
                            self.risk_engine.add_finding(finding)
                            logger.vulnerability_found(xss_type, risk_level.value, f"Parameter: {input_field['name']}")
                            break
    
    def _detect_xss(self, response: requests.Response, payload: str) -> bool:
        """Detect XSS based on response"""
        if not response:
            return False
        
        # Check if payload is reflected in response
        return payload in response.text
    
    def _test_csrf_vulnerabilities(self, base_url: str, forms: List[Dict[str, Any]]):
        """Test for CSRF vulnerabilities"""
        logger.info("Testing for CSRF vulnerabilities")
        
        for form in forms:
            # Check if form has CSRF protection
            has_csrf_token = False
            
            for input_field in form['inputs']:
                if any(token_name in input_field['name'].lower() 
                      for token_name in ['csrf', 'token', '_token', 'authenticity_token']):
                    has_csrf_token = True
                    break
            
            if not has_csrf_token and form['method'] == 'POST':
                finding = VulnerabilityFinding(
                    vuln_type="CSRF Vulnerability",
                    description=f"Form lacks CSRF protection at {form['url']}",
                    risk_level=RiskLevel.HIGH,
                    details={
                        'url': form['url'],
                        'action': form['action'],
                        'method': form['method']
                    },
                    remediation="Implement CSRF tokens for all state-changing operations"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found("CSRF Vulnerability", "High", f"Form at {form['url']}")
    
    def _test_directory_traversal(self, base_url: str, paths: List[str]):
        """Test for directory traversal/LFI vulnerabilities"""
        logger.info("Testing for directory traversal vulnerabilities")
        
        # Common parameters that might be vulnerable
        test_params = ['file', 'page', 'include', 'path', 'document', 'folder', 'root']
        
        for path in paths:
            url = urllib.parse.urljoin(base_url, path)
            
            for param in test_params:
                for payload in self.lfi_payloads:
                    test_url = f"{url}?{param}={payload}"
                    response = self._make_request('GET', test_url)
                    
                    if response and self._detect_directory_traversal(response):
                        finding = VulnerabilityFinding(
                            vuln_type="Directory Traversal/LFI",
                            description=f"Directory traversal vulnerability in {param} parameter",
                            risk_level=RiskLevel.HIGH,
                            details={
                                'url': test_url,
                                'parameter': param,
                                'payload': payload
                            },
                            remediation="Validate and sanitize file path inputs"
                        )
                        self.risk_engine.add_finding(finding)
                        logger.vulnerability_found("Directory Traversal", "High", f"Parameter: {param}")
                        break
    
    def _detect_directory_traversal(self, response: requests.Response) -> bool:
        """Detect directory traversal based on response"""
        if not response:
            return False
        
        # Look for common file contents
        indicators = [
            'root:x:0:0:',  # /etc/passwd
            '[boot loader]',  # Windows boot.ini
            '127.0.0.1',  # hosts file
            'localhost'
        ]
        
        response_text = response.text.lower()
        return any(indicator in response_text for indicator in indicators)
    
    def _test_information_disclosure(self, base_url: str):
        """Test for information disclosure vulnerabilities"""
        logger.info("Testing for information disclosure")
        
        # Common sensitive files/directories
        sensitive_paths = [
            '/.git/',
            '/.svn/',
            '/backup/',
            '/admin/',
            '/phpmyadmin/',
            '/robots.txt',
            '/.htaccess',
            '/web.config',
            '/config.php',
            '/database.sql',
            '/.env'
        ]
        
        for path in sensitive_paths:
            url = urllib.parse.urljoin(base_url, path)
            response = self._make_request('GET', url)
            
            if response and response.status_code == 200 and len(response.text) > 0:
                finding = VulnerabilityFinding(
                    vuln_type="Information Disclosure",
                    description=f"Sensitive file/directory accessible: {path}",
                    risk_level=RiskLevel.MEDIUM,
                    details={
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': len(response.text)
                    },
                    remediation=f"Restrict access to {path}"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found("Information Disclosure", "Medium", f"Path: {path}")
    
    def _test_common_misconfigurations(self, base_url: str):
        """Test for common security misconfigurations"""
        logger.info("Testing for common misconfigurations")
        
        # Test for HTTP methods
        dangerous_methods = ['PUT', 'DELETE', 'TRACE', 'CONNECT']
        
        for method in dangerous_methods:
            response = self._make_request(method, base_url)
            if response and response.status_code not in [405, 501]:  # Method not allowed/not implemented
                finding = VulnerabilityFinding(
                    vuln_type="Dangerous HTTP Method",
                    description=f"HTTP {method} method is enabled",
                    risk_level=RiskLevel.MEDIUM,
                    details={
                        'method': method,
                        'status_code': response.status_code
                    },
                    remediation=f"Disable HTTP {method} method if not required"
                )
                self.risk_engine.add_finding(finding)
                logger.vulnerability_found(f"HTTP {method} Enabled", "Medium")
    
    def get_vulnerability_summary(self) -> Dict[str, Any]:
        """Get vulnerability scan summary"""
        return {
            'total_findings': len(self.risk_engine.findings),
            'risk_summary': self.risk_engine.get_risk_summary(),
            'overall_score': self.risk_engine.calculate_overall_score(),
            'top_risks': [finding.to_dict() for finding in self.risk_engine.get_top_risks()],
            'recommendations': self.risk_engine.generate_recommendations()
        }
