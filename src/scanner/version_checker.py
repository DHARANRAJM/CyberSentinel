#!/usr/bin/env python3
"""
Version Checker Module
Part of CyberSentinel - Automated Vulnerability Assessment Tool

👨‍💻 Author: M DHARAN RAJ -- Web Developer------CISCO Trained & CISCO Certified Ethical Hacker----- 🔒
🌐 Web Developer | 🔐 CISCO Certified | ⚡ Ethical Hacker | 🛡️ Security Expert
"""

import json
import re
import requests
from typing import Dict, List, Any, Optional
import os
from pathlib import Path

from ..utils.logger import logger
from ..utils.risk_engine import RiskEngine, VulnerabilityFinding, RiskLevel

class VersionChecker:
    """Software version vulnerability checker against CVE database"""
    
    def __init__(self, cve_db_path: str = None):
        self.risk_engine = RiskEngine()
        
        # Default CVE database path
        if cve_db_path is None:
            current_dir = Path(__file__).parent.parent.parent
            cve_db_path = current_dir / "data" / "cve_db.json"
        
        self.cve_db_path = cve_db_path
        self.cve_data = self._load_cve_database()
    
    def _load_cve_database(self) -> Dict[str, Any]:
        """Load CVE database from JSON file"""
        try:
            with open(self.cve_db_path, 'r') as f:
                cve_data = json.load(f)
            logger.info(f"Loaded CVE database with {len(cve_data)} software entries")
            return cve_data
        except FileNotFoundError:
            logger.error(f"CVE database not found at {self.cve_db_path}")
            return {}
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in CVE database: {str(e)}")
            return {}
    
    def check_software_versions(self, services: Dict[int, Dict[str, Any]]) -> Dict[str, Any]:
        """
        Check discovered services against CVE database
        
        Args:
            services: Dictionary of services from port scanner
            
        Returns:
            Dictionary containing version check results
        """
        logger.info("Starting software version vulnerability check")
        
        version_results = {
            'timestamp': None,
            'total_services_checked': 0,
            'vulnerable_services': [],
            'outdated_software': [],
            'cve_matches': []
        }
        
        try:
            for port, service_info in services.items():
                version_results['total_services_checked'] += 1
                
                software = service_info.get('service', '').lower()
                version = service_info.get('version', '')
                product = service_info.get('product', '').lower()
                
                # Check against CVE database
                vulnerabilities = self._check_against_cve_db(software, version, product, port)
                
                if vulnerabilities:
                    version_results['vulnerable_services'].append({
                        'port': port,
                        'service': software,
                        'version': version,
                        'product': product,
                        'vulnerabilities': vulnerabilities
                    })
                
                # Check if software is outdated
                outdated_info = self._check_if_outdated(software, version, product)
                if outdated_info:
                    version_results['outdated_software'].append({
                        'port': port,
                        'service': software,
                        'current_version': version,
                        'latest_version': outdated_info.get('latest_version'),
                        'recommendation': outdated_info.get('recommendation')
                    })
            
            logger.info(f"Version check completed. Found {len(version_results['vulnerable_services'])} vulnerable services")
            
        except Exception as e:
            logger.error(f"Version checking failed: {str(e)}")
            version_results['error'] = str(e)
        
        return version_results
    
    def _check_against_cve_db(self, software: str, version: str, product: str, port: int) -> List[Dict[str, Any]]:
        """Check software version against CVE database"""
        vulnerabilities = []
        
        # Normalize software names for matching
        software_variants = [software, product]
        if product and software != product:
            software_variants.append(f"{product} {software}")
        
        for software_name in software_variants:
            if not software_name:
                continue
                
            # Check direct matches in CVE database
            for cve_software, versions_data in self.cve_data.items():
                if self._is_software_match(software_name, cve_software):
                    vuln_info = self._check_version_vulnerability(version, versions_data, cve_software)
                    if vuln_info:
                        vulnerabilities.extend(vuln_info)
                        
                        # Create vulnerability findings
                        for vuln in vuln_info:
                            risk_level = RiskLevel(vuln['risk'])
                            finding = VulnerabilityFinding(
                                vuln_type=f"Outdated Software - {cve_software.title()}",
                                description=f"{cve_software.title()} {version} contains known vulnerabilities",
                                risk_level=risk_level,
                                details={
                                    'software': cve_software,
                                    'version': version,
                                    'port': port,
                                    'cves': vuln['cves'],
                                    'description': vuln['description']
                                },
                                remediation=f"Update {cve_software} to the latest secure version"
                            )
                            self.risk_engine.add_finding(finding)
                            
                            logger.vulnerability_found(
                                f"Outdated {cve_software.title()} {version}",
                                risk_level.value,
                                f"CVEs: {', '.join(vuln['cves'][:3])}"
                            )
        
        return vulnerabilities
    
    def _is_software_match(self, detected_software: str, cve_software: str) -> bool:
        """Check if detected software matches CVE database entry"""
        detected_lower = detected_software.lower().strip()
        cve_lower = cve_software.lower().strip()
        
        # Direct match
        if detected_lower == cve_lower:
            return True
        
        # Partial matches
        if cve_lower in detected_lower or detected_lower in cve_lower:
            return True
        
        # Common software name variations
        variations = {
            'apache': ['httpd', 'apache2', 'apache-httpd'],
            'nginx': ['nginx-core', 'nginx-full'],
            'mysql': ['mysql-server', 'mariadb'],
            'postgresql': ['postgres', 'pgsql'],
            'openssh': ['ssh', 'sshd'],
            'openssl': ['ssl', 'tls']
        }
        
        for canonical, variants in variations.items():
            if cve_lower == canonical and any(var in detected_lower for var in variants):
                return True
            if detected_lower == canonical and any(var in cve_lower for var in variants):
                return True
        
        return False
    
    def _check_version_vulnerability(self, version: str, versions_data: Dict, software: str) -> List[Dict[str, Any]]:
        """Check if specific version is vulnerable"""
        vulnerabilities = []
        
        if not version:
            return vulnerabilities
        
        # Clean version string
        clean_version = self._clean_version_string(version)
        
        for vuln_version, vuln_info in versions_data.items():
            if self._is_version_vulnerable(clean_version, vuln_version):
                vulnerabilities.append({
                    'software': software,
                    'vulnerable_version': vuln_version,
                    'detected_version': version,
                    'cves': vuln_info.get('cves', []),
                    'risk': vuln_info.get('risk', 'Medium'),
                    'description': vuln_info.get('description', 'Known vulnerabilities exist')
                })
        
        return vulnerabilities
    
    def _clean_version_string(self, version: str) -> str:
        """Clean and normalize version string"""
        if not version:
            return ""
        
        # Remove common prefixes and suffixes
        version = re.sub(r'^(v|version|ver)\.?\s*', '', version, flags=re.IGNORECASE)
        version = re.sub(r'\s*\(.*\)$', '', version)  # Remove parenthetical info
        version = re.sub(r'\s*-.*$', '', version)     # Remove build info
        
        # Extract main version number
        version_match = re.match(r'^(\d+(?:\.\d+)*)', version)
        if version_match:
            return version_match.group(1)
        
        return version.strip()
    
    def _is_version_vulnerable(self, detected_version: str, vulnerable_version: str) -> bool:
        """Check if detected version matches vulnerable version pattern"""
        if not detected_version or not vulnerable_version:
            return False
        
        # Exact match
        if detected_version == vulnerable_version:
            return True
        
        # Version range matching (simplified)
        try:
            detected_parts = [int(x) for x in detected_version.split('.')]
            vulnerable_parts = [int(x) for x in vulnerable_version.split('.')]
            
            # Pad shorter version with zeros
            max_len = max(len(detected_parts), len(vulnerable_parts))
            detected_parts.extend([0] * (max_len - len(detected_parts)))
            vulnerable_parts.extend([0] * (max_len - len(vulnerable_parts)))
            
            # Check if detected version is less than or equal to vulnerable version
            # This is a simplified approach - real version comparison is more complex
            return detected_parts <= vulnerable_parts
            
        except ValueError:
            # Fallback to string comparison if version parsing fails
            return detected_version.startswith(vulnerable_version)
    
    def _check_if_outdated(self, software: str, version: str, product: str) -> Optional[Dict[str, Any]]:
        """Check if software version is outdated (simplified implementation)"""
        # This would typically query external APIs or databases for latest versions
        # For now, we'll use a simple heuristic based on version age
        
        if not version:
            return None
        
        try:
            clean_version = self._clean_version_string(version)
            if not clean_version:
                return None
            
            version_parts = [int(x) for x in clean_version.split('.')]
            
            # Simple heuristic: if major version is very old, consider outdated
            outdated_thresholds = {
                'apache': 2.4,
                'nginx': 1.18,
                'mysql': 8.0,
                'postgresql': 13.0,
                'openssh': 8.0,
                'openssl': 1.1
            }
            
            for soft_name, threshold in outdated_thresholds.items():
                if soft_name in software.lower():
                    if len(version_parts) >= 2:
                        major_minor = float(f"{version_parts[0]}.{version_parts[1]}")
                        if major_minor < threshold:
                            return {
                                'software': software,
                                'current_version': version,
                                'latest_version': f">= {threshold}",
                                'recommendation': f"Update {software} to version {threshold} or later"
                            }
            
        except (ValueError, IndexError):
            pass
        
        return None
    
    def check_web_application_versions(self, target: str, port: int = 80) -> Dict[str, Any]:
        """Check web application versions through HTTP headers and responses"""
        logger.info(f"Checking web application versions for {target}:{port}")
        
        web_version_results = {
            'target': f"{target}:{port}",
            'server_headers': {},
            'detected_technologies': [],
            'vulnerable_components': []
        }
        
        try:
            # Make HTTP request to get server headers
            protocol = 'https' if port == 443 else 'http'
            url = f"{protocol}://{target}:{port}"
            
            response = requests.get(url, timeout=10, verify=False, allow_redirects=True)
            
            # Analyze server headers
            headers_to_check = ['server', 'x-powered-by', 'x-aspnet-version', 'x-generator']
            
            for header in headers_to_check:
                if header in response.headers:
                    header_value = response.headers[header]
                    web_version_results['server_headers'][header] = header_value
                    
                    # Parse version information from headers
                    tech_info = self._parse_technology_header(header, header_value)
                    if tech_info:
                        web_version_results['detected_technologies'].append(tech_info)
                        
                        # Check for vulnerabilities
                        vulns = self._check_against_cve_db(
                            tech_info['name'], 
                            tech_info['version'], 
                            tech_info['name'], 
                            port
                        )
                        if vulns:
                            web_version_results['vulnerable_components'].extend(vulns)
            
            # Analyze response content for technology fingerprinting
            content_tech = self._fingerprint_web_technologies(response.text)
            web_version_results['detected_technologies'].extend(content_tech)
            
        except requests.RequestException as e:
            logger.error(f"Failed to check web application versions: {str(e)}")
            web_version_results['error'] = str(e)
        
        return web_version_results
    
    def _parse_technology_header(self, header_name: str, header_value: str) -> Optional[Dict[str, str]]:
        """Parse technology and version from HTTP header"""
        # Common patterns for extracting version info
        patterns = [
            r'([a-zA-Z-]+)/(\d+(?:\.\d+)*)',  # Apache/2.4.41
            r'([a-zA-Z-]+)\s+(\d+(?:\.\d+)*)', # nginx 1.18.0
            r'([a-zA-Z-]+)(?:\s+|/)v?(\d+(?:\.\d+)*)', # PHP/7.4.3
        ]
        
        for pattern in patterns:
            match = re.search(pattern, header_value, re.IGNORECASE)
            if match:
                return {
                    'name': match.group(1).lower(),
                    'version': match.group(2),
                    'source': f"{header_name} header",
                    'raw_value': header_value
                }
        
        # If no version found, just return the technology name
        tech_name = header_value.split('/')[0].split()[0]
        return {
            'name': tech_name.lower(),
            'version': '',
            'source': f"{header_name} header",
            'raw_value': header_value
        }
    
    def _fingerprint_web_technologies(self, content: str) -> List[Dict[str, str]]:
        """Fingerprint web technologies from HTML content"""
        technologies = []
        
        # Common technology fingerprints
        fingerprints = {
            'wordpress': [r'wp-content/', r'wordpress', r'/wp-includes/'],
            'drupal': [r'drupal', r'sites/default/', r'/misc/drupal.js'],
            'joomla': [r'joomla', r'/media/system/js/', r'option=com_'],
            'jquery': [r'jquery[.-](\d+(?:\.\d+)*)', r'jQuery v(\d+(?:\.\d+)*)'],
            'bootstrap': [r'bootstrap[.-](\d+(?:\.\d+)*)', r'Bootstrap v(\d+(?:\.\d+)*)'],
            'angular': [r'angular[.-](\d+(?:\.\d+)*)', r'AngularJS v(\d+(?:\.\d+)*)']
        }
        
        for tech_name, patterns in fingerprints.items():
            for pattern in patterns:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    version = match.group(1) if match.groups() else ''
                    technologies.append({
                        'name': tech_name,
                        'version': version,
                        'source': 'content analysis',
                        'pattern': pattern
                    })
                    break  # Only add once per technology
        
        return technologies
    
    def get_version_summary(self) -> Dict[str, Any]:
        """Get version check summary"""
        return {
            'total_findings': len(self.risk_engine.findings),
            'risk_summary': self.risk_engine.get_risk_summary(),
            'overall_score': self.risk_engine.calculate_overall_score(),
            'top_risks': [finding.to_dict() for finding in self.risk_engine.get_top_risks()],
            'recommendations': self.risk_engine.generate_recommendations()
        }
