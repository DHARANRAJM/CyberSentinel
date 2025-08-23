#!/usr/bin/env python3
"""
CyberSentinel - Automated Vulnerability Assessment Tool
Main orchestrator that coordinates all scanning modules

👨‍💻 Author: M DHARAN RAJ -- Web Developer------CISCO Trained & CISCO Certified Ethical Hacker----- 🔒
🌐 Web Developer | 🔐 CISCO Certified | ⚡ Ethical Hacker | 🛡️ Security Expert
"""

import argparse
import sys
import time
from pathlib import Path
from typing import Dict, Any, List
import json

# Import scanner modules
from scanner.port_scanner import PortScanner
from scanner.ssl_checker import SSLChecker
from scanner.version_checker import VersionChecker
from scanner.vuln_checker import VulnerabilityChecker

# Import report generators
from reports.pdf_report import PDFReportGenerator
from reports.html_report import HTMLReportGenerator

# Import utilities
from utils.logger import logger
from utils.risk_engine import RiskEngine, RiskLevel

class CyberSentinel:
    """Main CyberSentinel vulnerability assessment orchestrator"""
    
    def __init__(self):
        self.target = None
        self.scan_results = {}
        self.overall_risk_engine = RiskEngine()
        
        # Initialize scanners
        self.port_scanner = PortScanner()
        self.ssl_checker = SSLChecker()
        self.version_checker = VersionChecker()
        self.vuln_checker = VulnerabilityChecker()
        
        # Initialize report generators
        self.pdf_generator = PDFReportGenerator()
        self.html_generator = HTMLReportGenerator()
    
    def run_comprehensive_scan(self, target: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Run comprehensive vulnerability assessment
        
        Args:
            target: Target IP address or hostname
            options: Scan configuration options
            
        Returns:
            Complete scan results dictionary
        """
        if options is None:
            options = {}
        
        self.target = target
        logger.scan_start(target)
        start_time = time.time()
        
        try:
            # Initialize results structure
            self.scan_results = {
                'target': target,
                'scan_start_time': start_time,
                'scan_options': options,
                'port_scan': {},
                'ssl_check': {},
                'version_check': {},
                'vulnerability_scan': {},
                'overall_summary': {}
            }
            
            # 1. Port Scanning
            if options.get('skip_port_scan', False):
                logger.info("Skipping port scan (disabled by user)")
            else:
                logger.info("=" * 50)
                logger.info("PHASE 1: PORT SCANNING")
                logger.info("=" * 50)
                
                port_range = options.get('port_range', '1-1000')
                port_results = self.port_scanner.scan_target(target, port_range)
                self.scan_results['port_scan'] = port_results
                self.scan_results['port_scan']['summary'] = self.port_scanner.get_scan_summary()
                
                # Merge findings into overall risk engine
                self._merge_findings(self.port_scanner.risk_engine)
            
            # 2. SSL/TLS Security Check
            if options.get('skip_ssl_check', False):
                logger.info("Skipping SSL check (disabled by user)")
            elif not self.scan_results['port_scan'].get('open_ports') or 443 not in self.scan_results['port_scan']['open_ports']:
                logger.info("Skipping SSL check (HTTPS port 443 not open)")
            else:
                logger.info("=" * 50)
                logger.info("PHASE 2: SSL/TLS SECURITY CHECK")
                logger.info("=" * 50)
                
                ssl_results = self.ssl_checker.check_ssl_security(target, 443)
                self.scan_results['ssl_check'] = ssl_results
                self.scan_results['ssl_check']['summary'] = self.ssl_checker.get_ssl_summary()
                
                # Merge findings
                self._merge_findings(self.ssl_checker.risk_engine)
            
            # 3. Software Version Check
            if options.get('skip_version_check', False):
                logger.info("Skipping version check (disabled by user)")
            else:
                logger.info("=" * 50)
                logger.info("PHASE 3: SOFTWARE VERSION ANALYSIS")
                logger.info("=" * 50)
                
                services = self.scan_results['port_scan'].get('services', {})
                if services:
                    version_results = self.version_checker.check_software_versions(services)
                    self.scan_results['version_check'] = version_results
                    self.scan_results['version_check']['summary'] = self.version_checker.get_version_summary()
                    
                    # Check web application versions if HTTP/HTTPS ports are open
                    open_ports = self.scan_results['port_scan'].get('open_ports', [])
                    for port in [80, 443, 8080, 8443]:
                        if port in open_ports:
                            web_version_results = self.version_checker.check_web_application_versions(target, port)
                            self.scan_results['version_check'][f'web_versions_{port}'] = web_version_results
                    
                    # Merge findings
                    self._merge_findings(self.version_checker.risk_engine)
                else:
                    logger.info("No services found for version checking")
            
            # 4. Web Vulnerability Scanning
            if options.get('skip_web_scan', False):
                logger.info("Skipping web vulnerability scan (disabled by user)")
            else:
                logger.info("=" * 50)
                logger.info("PHASE 4: WEB VULNERABILITY SCANNING")
                logger.info("=" * 50)
                
                open_ports = self.scan_results['port_scan'].get('open_ports', [])
                web_ports = [port for port in [80, 443, 8080, 8443] if port in open_ports]
                
                if web_ports:
                    # Scan each web port
                    for port in web_ports:
                        logger.info(f"Scanning web services on port {port}")
                        vuln_results = self.vuln_checker.scan_web_vulnerabilities(
                            target, port, options.get('web_paths', ['/'])
                        )
                        self.scan_results['vulnerability_scan'][f'port_{port}'] = vuln_results
                    
                    # Get overall vulnerability summary
                    self.scan_results['vulnerability_scan']['summary'] = self.vuln_checker.get_vulnerability_summary()
                    
                    # Merge findings
                    self._merge_findings(self.vuln_checker.risk_engine)
                else:
                    logger.info("No web services found for vulnerability scanning")
            
            # 5. Generate Overall Summary
            scan_duration = time.time() - start_time
            self.scan_results['scan_duration'] = scan_duration
            self.scan_results['overall_summary'] = self._generate_overall_summary()
            
            logger.scan_complete(target, scan_duration)
            self._print_scan_summary()
            
            return self.scan_results
            
        except KeyboardInterrupt:
            logger.warning("Scan interrupted by user")
            return self.scan_results
        except Exception as e:
            logger.error(f"Scan failed with error: {str(e)}")
            self.scan_results['error'] = str(e)
            return self.scan_results
    
    def _merge_findings(self, scanner_risk_engine: RiskEngine):
        """Merge findings from scanner into overall risk engine"""
        for finding in scanner_risk_engine.findings:
            self.overall_risk_engine.add_finding(finding)
    
    def _generate_overall_summary(self) -> Dict[str, Any]:
        """Generate overall scan summary"""
        return {
            'total_findings': len(self.overall_risk_engine.findings),
            'risk_summary': self.overall_risk_engine.get_risk_summary(),
            'overall_score': self.overall_risk_engine.calculate_overall_score(),
            'top_risks': [finding.to_dict() for finding in self.overall_risk_engine.get_top_risks(10)],
            'recommendations': self.overall_risk_engine.generate_recommendations()
        }
    
    def _print_scan_summary(self):
        """Print comprehensive scan summary to console"""
        logger.info("=" * 60)
        logger.info("SCAN SUMMARY")
        logger.info("=" * 60)
        
        summary = self.scan_results['overall_summary']
        risk_summary = summary['risk_summary']
        
        logger.info(f"Target: {self.target}")
        logger.info(f"Total Findings: {summary['total_findings']}")
        logger.info(f"Scan Duration: {self.scan_results['scan_duration']:.2f} seconds")
        logger.info("")
        
        # Risk breakdown
        logger.info("Risk Breakdown:")
        for risk_level, count in risk_summary.items():
            if count > 0:
                color_map = {
                    'Critical': 'vulnerability_found',
                    'High': 'vulnerability_found', 
                    'Medium': 'warning',
                    'Low': 'info',
                    'Info': 'info'
                }
                if risk_level in ['Critical', 'High']:
                    logger.vulnerability_found(f"{risk_level} Risk Issues", risk_level, f"{count} findings")
                else:
                    logger.info(f"  {risk_level}: {count}")
        
        logger.info("")
        
        # Top risks
        if summary['top_risks']:
            logger.info("Top Security Risks:")
            for i, risk in enumerate(summary['top_risks'][:5], 1):
                logger.vulnerability_found(f"{i}. {risk['type']}", risk['risk_level'], risk['description'])
        
        logger.info("=" * 60)
    
    def generate_reports(self, output_formats: List[str] = None, output_dir: str = ".") -> Dict[str, str]:
        """
        Generate security reports in specified formats
        
        Args:
            output_formats: List of formats ['pdf', 'html', 'json']
            output_dir: Directory to save reports
            
        Returns:
            Dictionary mapping format to file path
        """
        if output_formats is None:
            output_formats = ['html', 'pdf']
        
        if not self.scan_results:
            raise ValueError("No scan results available. Run scan first.")
        
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        generated_reports = {}
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        base_filename = f"CyberSentinel_{self.target}_{timestamp}"
        
        try:
            # Generate HTML report
            if 'html' in output_formats:
                html_path = output_dir / f"{base_filename}.html"
                self.html_generator.generate_report(self.scan_results, str(html_path))
                generated_reports['html'] = str(html_path)
            
            # Generate PDF report
            if 'pdf' in output_formats:
                pdf_path = output_dir / f"{base_filename}.pdf"
                self.pdf_generator.generate_report(self.scan_results, str(pdf_path))
                generated_reports['pdf'] = str(pdf_path)
            
            # Generate JSON report
            if 'json' in output_formats:
                json_path = output_dir / f"{base_filename}.json"
                self.html_generator.generate_json_report(self.scan_results, str(json_path))
                generated_reports['json'] = str(json_path)
            
            logger.info(f"Reports generated: {', '.join(generated_reports.keys())}")
            return generated_reports
            
        except Exception as e:
            logger.error(f"Report generation failed: {str(e)}")
            raise

def create_argument_parser() -> argparse.ArgumentParser:
    """Create command line argument parser"""
    parser = argparse.ArgumentParser(
        description="CyberSentinel - Automated Vulnerability Assessment Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py --target example.com
  python main.py --target 192.168.1.1 --ports 1-65535 --output pdf html
  python main.py --target example.com --skip-web-scan --output-dir reports/
        """
    )
    
    # Required arguments
    parser.add_argument('--target', '-t', required=True,
                       help='Target IP address or hostname to scan')
    
    # Scan options
    parser.add_argument('--ports', '-p', default='1-1000',
                       help='Port range to scan (default: 1-1000)')
    parser.add_argument('--web-paths', nargs='+', default=['/'],
                       help='Web paths to test for vulnerabilities')
    
    # Skip options
    parser.add_argument('--skip-port-scan', action='store_true',
                       help='Skip port scanning phase')
    parser.add_argument('--skip-ssl-check', action='store_true',
                       help='Skip SSL/TLS security check')
    parser.add_argument('--skip-version-check', action='store_true',
                       help='Skip software version checking')
    parser.add_argument('--skip-web-scan', action='store_true',
                       help='Skip web vulnerability scanning')
    
    # Output options
    parser.add_argument('--output', '-o', nargs='+', 
                       choices=['html', 'pdf', 'json'], default=['html'],
                       help='Output report formats (default: html)')
    parser.add_argument('--output-dir', default='.',
                       help='Directory to save reports (default: current directory)')
    
    # Verbosity
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Enable verbose logging')
    parser.add_argument('--quiet', '-q', action='store_true',
                       help='Suppress non-essential output')
    
    return parser

def main():
    """Main entry point"""
    parser = create_argument_parser()
    args = parser.parse_args()
    
    # Configure logging based on verbosity
    if args.quiet:
        logger.logger.setLevel(40)  # ERROR level
    elif args.verbose:
        logger.logger.setLevel(10)  # DEBUG level
    
    # Print banner
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                    🛡️  CyberSentinel 🛡️                    ║
    ║            Automated Vulnerability Assessment Tool        ║
    ║                                                           ║
    ║  ⚠️  FOR AUTHORIZED TESTING ONLY ⚠️                       ║
    ║  Only scan systems you own or have explicit permission   ║
    ╚═══════════════════════════════════════════════════════════╝
    """)
    
    try:
        # Initialize CyberSentinel
        sentinel = CyberSentinel()
        
        # Prepare scan options
        scan_options = {
            'port_range': args.ports,
            'web_paths': args.web_paths,
            'skip_port_scan': args.skip_port_scan,
            'skip_ssl_check': args.skip_ssl_check,
            'skip_version_check': args.skip_version_check,
            'skip_web_scan': args.skip_web_scan
        }
        
        # Run comprehensive scan
        logger.info(f"Starting comprehensive security assessment of {args.target}")
        scan_results = sentinel.run_comprehensive_scan(args.target, scan_options)
        
        # Generate reports
        if not args.quiet:
            logger.info("Generating security reports...")
        
        generated_reports = sentinel.generate_reports(args.output, args.output_dir)
        
        # Print report locations
        logger.info("Security assessment completed successfully!")
        logger.info("Generated reports:")
        for format_type, file_path in generated_reports.items():
            logger.info(f"  {format_type.upper()}: {file_path}")
        
        # Exit with appropriate code based on findings
        risk_summary = scan_results.get('overall_summary', {}).get('risk_summary', {})
        if risk_summary.get('Critical', 0) > 0:
            sys.exit(3)  # Critical vulnerabilities found
        elif risk_summary.get('High', 0) > 0:
            sys.exit(2)  # High-risk vulnerabilities found
        elif risk_summary.get('Medium', 0) > 0:
            sys.exit(1)  # Medium-risk issues found
        else:
            sys.exit(0)  # No significant issues
            
    except KeyboardInterrupt:
        logger.warning("Assessment interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Assessment failed: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
