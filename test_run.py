#!/usr/bin/env python3
"""Simple test script to verify imports and basic functionality"""

import sys
import os

# Add the src directory to the Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

def test_imports():
    """Test if all required modules can be imported"""
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
        return True
        
    except ImportError as e:
        print(f"❌ Import error: {e}")
        import traceback
        traceback.print_exc()
        return False

def test_port_scanner():
    """Test basic port scanning functionality"""
    try:
        print("\n🔍 Testing PortScanner...")
        scanner = PortScanner()
        print("✅ PortScanner initialized successfully")
        return True
    except Exception as e:
        print(f"❌ PortScanner test failed: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    print("🚀 Starting CyberSentinel tests...")
    
    # Test imports
    if not test_imports():
        print("❌ Import tests failed")
        sys.exit(1)
    
    # Test port scanner
    if not test_port_scanner():
        print("❌ PortScanner test failed")
        sys.exit(1)
    
    print("\n🎉 All tests completed successfully!")
