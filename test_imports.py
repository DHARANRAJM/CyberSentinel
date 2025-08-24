#!/usr/bin/env python3
"""Test script to verify imports"""

try:
    from src.scanner.port_scanner import PortScanner
    from src.scanner.ssl_checker import SSLChecker
    from src.scanner.version_checker import VersionChecker
    from src.scanner.vuln_checker import VulnerabilityChecker
    from src.reports.pdf_report import PDFReportGenerator
    from src.reports.html_report import HTMLReportGenerator
    from src.utils.logger import logger
    from src.utils.risk_engine import RiskEngine, RiskLevel
    
    print("✅ All imports successful!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    raise
