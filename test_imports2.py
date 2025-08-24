#!/usr/bin/env python3
"""Test script to verify imports"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), 'src')))

try:
    from scanner.port_scanner import PortScanner
    from scanner.ssl_checker import SSLChecker
    from scanner.version_checker import VersionChecker
    from scanner.vuln_checker import VulnerabilityChecker
    from reports.pdf_report import PDFReportGenerator
    from reports.html_report import HTMLReportGenerator
    from utils.logger import logger
    from utils.risk_engine import RiskEngine, RiskLevel
    
    print("✅ All imports successful!")
    
except ImportError as e:
    print(f"❌ Import error: {e}")
    raise
