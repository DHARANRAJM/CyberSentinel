#!/usr/bin/env python3
"""
Website Security Tester for CyberSentinel
Safely tests random websites for common vulnerabilities
"""

import random
import time
import requests
from urllib.parse import urlparse
from typing import List, Dict, Optional

# Import CyberSentinel components
from src.scanner.port_scanner import PortScanner
from src.scanner.ssl_checker import SSLChecker
from src.scanner.vuln_checker import VulnerabilityChecker
from src.utils.logger import logger
from src.utils.risk_engine import RiskEngine

class WebsiteTester:
    """Test random websites for common vulnerabilities"""
    
    def __init__(self, max_sites: int = 5, delay: int = 5):
        """
        Initialize the website tester
        
        Args:
            max_sites: Maximum number of websites to test
            delay: Delay between requests in seconds
        """
        self.max_sites = max_sites
        self.delay = delay
        self.port_scanner = PortScanner()
        self.ssl_checker = SSLChecker()
        self.vuln_checker = VulnerabilityChecker()
        self.risk_engine = RiskEngine()
        
        # List of popular websites for testing (safe, high-traffic sites)
        self.popular_websites = [
            'example.com',
            'wikipedia.org',
            'github.com',
            'stackoverflow.com',
            'reddit.com',
            'microsoft.com',
            'apple.com',
            'mozilla.org',
            'python.org',
            'docker.com'
        ]
        
        # Common ports to scan
        self.common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1723, 3306, 3389, 5900, 8080]
    
    def get_random_website(self) -> str:
        """Get a random website from the predefined list"""
        return random.choice(self.popular_websites)
    
    def is_website_accessible(self, url: str) -> bool:
        """Check if website is accessible"""
        try:
            response = requests.get(f"https://{url}", timeout=10, allow_redirects=True)
            return response.status_code == 200
        except requests.RequestException:
            try:
                response = requests.get(f"http://{url}", timeout=10, allow_redirects=True)
                return response.status_code == 200
            except:
                return False
    
    def scan_website(self, domain: str) -> Dict[str, Any]:
        """Perform security scan on a single website"""
        logger.info(f"Scanning website: {domain}")
        
        results = {
            'target': domain,
            'timestamp': time.time(),
            'accessible': False,
            'ports': {},
            'ssl': {},
            'vulnerabilities': []
        }
        
        # Check if website is accessible
        if not self.is_website_accessible(domain):
            logger.warning(f"Website {domain} is not accessible")
            results['error'] = "Website not accessible"
            return results
            
        results['accessible'] = True
        
        try:
            # Port scanning
            logger.info(f"Scanning ports for {domain}...")
            port_results = self.port_scanner.scan_target(domain, 
                                                       port_range=','.join(map(str, self.common_ports)))
            results['ports'] = port_results.get('open_ports', [])
            
            # SSL/TLS scanning
            logger.info(f"Checking SSL/TLS for {domain}...")
            ssl_results = self.ssl_checker.check_ssl(domain)
            results['ssl'] = ssl_results
            
            # Basic vulnerability scanning
            logger.info(f"Checking for common vulnerabilities on {domain}...")
            vuln_results = self.vuln_checker.check_website(domain)
            results['vulnerabilities'] = vuln_results
            
            # Calculate overall risk
            risk_score = self.risk_engine.calculate_risk(results)
            results['risk_score'] = risk_score
            
        except Exception as e:
            logger.error(f"Error scanning {domain}: {str(e)}")
            results['error'] = str(e)
            
        return results
    
    def run_random_scans(self) -> List[Dict[str, Any]]:
        """Run security scans on random websites"""
        results = []
        
        for i in range(min(self.max_sites, len(self.popular_websites))):
            if i > 0:
                logger.info(f"Waiting {self.delay} seconds before next scan...")
                time.sleep(self.delay)
                
            website = self.get_random_website()
            logger.info(f"\n{'='*50}")
            logger.info(f"Scanning website {i+1}/{self.max_sites}: {website}")
            
            try:
                result = self.scan_website(website)
                results.append(result)
                self.print_scan_summary(result)
            except Exception as e:
                logger.error(f"Failed to scan {website}: {str(e)}")
                
        return results
    
    def print_scan_summary(self, result: Dict[str, Any]):
        """Print a summary of the scan results"""
        print("\n" + "="*50)
        print(f"Scan Results for {result['target']}")
        print("="*50)
        
        if not result.get('accessible', False):
            print("❌ Website is not accessible")
            if 'error' in result:
                print(f"   Error: {result['error']}")
            return
            
        print(f"✅ Website is accessible")
        
        # Print open ports
        if result.get('ports'):
            print("\n🔍 Open Ports:")
            for port in result['ports']:
                print(f"   - Port {port['port']} ({port.get('service', 'unknown')}) - {port.get('state', 'open')}")
        
        # Print SSL info
        if result.get('ssl'):
            ssl = result['ssl']
            print("\n🔒 SSL/TLS Information:")
            print(f"   - Protocol: {ssl.get('protocol', 'Unknown')}")
            print(f"   - Cipher: {ssl.get('cipher', 'Unknown')}")
            if 'expires_in' in ssl:
                print(f"   - Expires in: {ssl['expires_in']} days")
            
        # Print vulnerabilities
        if result.get('vulnerabilities'):
            print("\n⚠️  Potential Vulnerabilities:")
            for vuln in result['vulnerabilities']:
                print(f"   - {vuln.get('title', 'Unknown')} ({vuln.get('severity', 'medium')})")
        
        print(f"\n💯 Overall Risk Score: {result.get('risk_score', 'N/A')}")
        print("="*50 + "\n")

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Website Security Tester')
    parser.add_argument('--max-sites', type=int, default=3,
                       help='Maximum number of websites to test (default: 3)')
    parser.add_argument('--delay', type=int, default=5,
                       help='Delay between scans in seconds (default: 5)')
    
    args = parser.parse_args()
    
    print("""
    🌐 CyberSentinel Website Tester
    -----------------------------
    This tool will test random popular websites for common security issues.
    Please use responsibly and respect website terms of service.
    """)
    
    tester = WebsiteTester(max_sites=args.max_sites, delay=args.delay)
    results = tester.run_random_scans()
    
    print("\n✅ Scan complete!")
    print(f"Scanned {len(results)} websites.")

if __name__ == "__main__":
    main()
