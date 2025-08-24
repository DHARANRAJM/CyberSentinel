#!/usr/bin/env python3
"""
Port Scanner Module
Part of CyberSentinel - Automated Vulnerability Assessment Tool

👨‍💻 Author: M DHARAN RAJ -- Web Developer------CISCO Trained & CISCO Certified Ethical Hacker----- 🔒
🌐 Web Developer | 🔐 CISCO Certified | ⚡ Ethical Hacker | 🛡️ Security Expert
"""

import nmap
import socket
import subprocess
import threading
import time
from typing import Dict, List, Any, Tuple, Any
import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..utils.logger import logger
from ..utils.risk_engine import RiskEngine, VulnerabilityFinding, RiskLevel

class PortScanner:
    """Network port scanner using nmap and custom socket scanning"""
    
    def __init__(self, timeout: int = 5, max_threads: int = 100):
        self.timeout = timeout
        self.max_threads = max_threads
        self.nm = nmap.PortScanner()
        self.risk_engine = RiskEngine()
    
    def scan_target(self, target: str, port_range: str = "1-1000") -> Dict[str, Any]:
        """
        Comprehensive port scan of target
        
        Args:
            target: IP address or hostname to scan
            port_range: Port range to scan (e.g., "1-1000", "22,80,443")
            
        Returns:
            Dictionary containing scan results
        """
        logger.info(f"Starting port scan for {target}")
        start_time = time.time()
        
        scan_results = {
            'target': target,
            'timestamp': time.time(),
            'open_ports': [],
            'services': {},
            'os_detection': {},
            'scan_duration': 0,
            'total_ports_scanned': 0
        }
        
        try:
            # Perform nmap scan with service detection and OS fingerprinting
            logger.info(f"Scanning ports {port_range} on {target}")
            
            # Basic TCP SYN scan with service version detection
            self.nm.scan(target, port_range, arguments='-sS -sV -O --version-intensity 5')
            
            if target in self.nm.all_hosts():
                host_info = self.nm[target]
                
                # Extract open ports and services
                for protocol in host_info.all_protocols():
                    ports = host_info[protocol].keys()
                    scan_results['total_ports_scanned'] = len(ports)
                    
                    for port in ports:
                        port_info = host_info[protocol][port]
                        if port_info['state'] == 'open':
                            service_info = {
                                'port': port,
                                'protocol': protocol,
                                'service': port_info.get('name', 'unknown'),
                                'version': port_info.get('version', ''),
                                'product': port_info.get('product', ''),
                                'extrainfo': port_info.get('extrainfo', ''),
                                'state': port_info['state']
                            }
                            
                            scan_results['open_ports'].append(port)
                            scan_results['services'][port] = service_info
                            
                            # Assess risk for this port
                            risk_level = self.risk_engine.assess_port_risk(port, service_info['service'])
                            
                            # Create vulnerability finding
                            finding = VulnerabilityFinding(
                                vuln_type=f"Open Port - {service_info['service']}",
                                description=f"Port {port}/{protocol} ({service_info['service']}) is open",
                                risk_level=risk_level,
                                details=service_info,
                                remediation=self._get_port_remediation(port, service_info['service'])
                            )
                            self.risk_engine.add_finding(finding)
                            
                            logger.vulnerability_found(
                                f"Open Port {port} ({service_info['service']})",
                                risk_level.value,
                                f"Version: {service_info['version']}" if service_info['version'] else ""
                            )
                
                # OS Detection
                if 'osmatch' in host_info:
                    for os_match in host_info['osmatch']:
                        scan_results['os_detection'] = {
                            'name': os_match['name'],
                            'accuracy': os_match['accuracy'],
                            'line': os_match['line']
                        }
                        logger.info(f"OS Detection: {os_match['name']} ({os_match['accuracy']}% accuracy)")
                        break
            
            scan_duration = time.time() - start_time
            scan_results['scan_duration'] = scan_duration
            
            logger.info(f"Port scan completed. Found {len(scan_results['open_ports'])} open ports")
            logger.scan_complete(target, scan_duration)
            
        except Exception as e:
            logger.error(f"Port scan failed: {str(e)}")
            # Fallback to custom socket scanning
            logger.info("Falling back to custom socket scanning")
            scan_results = self._socket_scan_fallback(target, port_range, scan_results)
        
        return scan_results
    
    def _socket_scan_fallback(self, target: str, port_range: str, scan_results: Dict) -> Dict:
        """Fallback socket-based port scanning"""
        try:
            # Parse port range
            if '-' in port_range:
                start_port, end_port = map(int, port_range.split('-'))
                ports_to_scan = range(start_port, end_port + 1)
            else:
                ports_to_scan = [int(p.strip()) for p in port_range.split(',')]
            
            scan_results['total_ports_scanned'] = len(list(ports_to_scan))
            
            # Multi-threaded socket scanning
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                future_to_port = {
                    executor.submit(self._check_port, target, port): port 
                    for port in ports_to_scan
                }
                
                for future in as_completed(future_to_port):
                    port = future_to_port[future]
                    try:
                        is_open, service = future.result()
                        if is_open:
                            scan_results['open_ports'].append(port)
                            scan_results['services'][port] = {
                                'port': port,
                                'protocol': 'tcp',
                                'service': service,
                                'version': '',
                                'product': '',
                                'extrainfo': '',
                                'state': 'open'
                            }
                            
                            # Assess risk
                            risk_level = self.risk_engine.assess_port_risk(port, service)
                            finding = VulnerabilityFinding(
                                vuln_type=f"Open Port - {service}",
                                description=f"Port {port}/tcp ({service}) is open",
                                risk_level=risk_level,
                                details=scan_results['services'][port],
                                remediation=self._get_port_remediation(port, service)
                            )
                            self.risk_engine.add_finding(finding)
                            
                            logger.vulnerability_found(f"Open Port {port} ({service})", risk_level.value)
                    
                    except Exception as e:
                        logger.debug(f"Error scanning port {port}: {e}")
            
            logger.info(f"Socket scan completed. Found {len(scan_results['open_ports'])} open ports")
            
        except Exception as e:
            logger.error(f"Socket scan fallback failed: {str(e)}")
        
        return scan_results
    
    def _check_port(self, target: str, port: int) -> Tuple[bool, str]:
        """Check if a specific port is open using socket connection"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                service = self._identify_service(port)
                return True, service
            return False, ""
            
        except Exception:
            return False, ""
    
    def _identify_service(self, port: int) -> str:
        """Identify service running on port based on common port mappings"""
        common_ports = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp', 53: 'dns',
            80: 'http', 110: 'pop3', 135: 'msrpc', 139: 'netbios-ssn',
            143: 'imap', 443: 'https', 445: 'microsoft-ds', 993: 'imaps',
            995: 'pop3s', 1433: 'mssql', 3306: 'mysql', 3389: 'rdp',
            5432: 'postgresql', 5900: 'vnc', 6379: 'redis', 27017: 'mongodb'
        }
        return common_ports.get(port, 'unknown')
    
    def _get_port_remediation(self, port: int, service: str) -> str:
        """Get remediation advice for open ports"""
        high_risk_remediations = {
            21: "Disable FTP or use SFTP/FTPS with strong authentication",
            23: "Disable Telnet and use SSH instead",
            135: "Block RPC ports at firewall level",
            139: "Disable NetBIOS or restrict access",
            445: "Restrict SMB access and apply latest patches",
            1433: "Secure SQL Server with strong authentication and encryption",
            3389: "Use VPN for RDP access and enable NLA"
        }
        
        if port in high_risk_remediations:
            return high_risk_remediations[port]
        elif port < 1024:
            return f"Review necessity of {service} service and restrict access if possible"
        else:
            return f"Verify {service} service is required and properly secured"
    
    def get_scan_summary(self) -> Dict[str, Any]:
        """Get summary of scan results and risk assessment"""
        return {
            'total_findings': len(self.risk_engine.findings),
            'risk_summary': self.risk_engine.get_risk_summary(),
            'overall_score': self.risk_engine.calculate_overall_score(),
            'top_risks': [finding.to_dict() for finding in self.risk_engine.get_top_risks()],
            'recommendations': self.risk_engine.generate_recommendations()
        }
    
    def export_results(self, filename: str = "port_scan_results.json"):
        """Export scan results to JSON file"""
        results = {
            'findings': self.risk_engine.export_findings(),
            'summary': self.get_scan_summary()
        }
        
        with open(filename, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Port scan results exported to {filename}")
