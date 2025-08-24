# 🛡️ CyberSentinel - Automated Vulnerability Assessment Tool

**👨‍💻 Author: M DHARAN RAJ -- Web Developer ----- CISCO Trained & CISCO Certified Ethical Hacker ----- 🔒**

🌐 **Web Developer** | 🔐 **CISCO Certified** | ⚡ **Ethical Hacker** | 

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security](https://img.shields.io/badge/security-vulnerability%20scanner-red.svg)](https://github.com/yourusername/CyberSentinel)

CyberSentinel is a comprehensive Python-based security scanner inspired by industry-standard tools like Nessus and OpenVAS. It performs automated vulnerability assessments, generates risk-rated findings, and exports professional security reports in multiple formats.

## ⚡ Features

### 🔍 **Port & Service Scanning**
- **Nmap Integration**: Leverages nmap for comprehensive port discovery
- **Service Detection**: Identifies running services and versions
- **Fallback Scanning**: Custom socket-based scanning when nmap unavailable
- **Risk Assessment**: Automatic risk rating for discovered services

### 🔒 **SSL/TLS Security Analysis**
- **Certificate Validation**: Checks for expired, self-signed, or invalid certificates
- **Protocol Testing**: Detects weak SSL/TLS protocol versions (SSLv2/v3, TLS1.0)
- **Cipher Suite Analysis**: Identifies weak encryption algorithms
- **Vulnerability Detection**: Tests for Heartbleed, POODLE, and other SSL vulnerabilities

### 📦 **Software Version Assessment**
- **CVE Database Matching**: Maps service versions against known vulnerabilities
- **Outdated Software Detection**: Identifies software requiring updates
- **Web Technology Fingerprinting**: Detects CMS, frameworks, and libraries
- **Risk Scoring**: Prioritizes vulnerabilities by severity

### 🌐 **Web Application Security Testing**
- **SQL Injection Detection**: Tests for database injection vulnerabilities
- **Cross-Site Scripting (XSS)**: Identifies reflected and stored XSS issues
- **CSRF Protection**: Validates Cross-Site Request Forgery protections
- **Security Headers**: Analyzes HTTP security header implementation
- **Directory Traversal**: Tests for path traversal vulnerabilities
- **Information Disclosure**: Checks for exposed sensitive files

### 📊 **Professional Reporting**
- **PDF Reports**: Professional ReportLab-generated security assessments
- **Interactive HTML**: Modern, responsive web-based reports
- **JSON Export**: Machine-readable data for integration
- **Risk Prioritization**: Clear severity ratings (Critical/High/Medium/Low)
- **Executive Summaries**: Business-focused vulnerability overviews

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+**
- **nmap** (recommended for enhanced port scanning)
- **openssl** (recommended for SSL analysis)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/CyberSentinel.git
cd CyberSentinel

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt
```

### Basic Usage

```bash
# Quick scan with HTML report
python src/main.py --target example.com

# Comprehensive scan with multiple report formats
python src/main.py --target 192.168.1.1 --ports 1-65535 --output html pdf json

# Using the shell wrapper (Linux/Mac)
chmod +x run.sh
./run.sh example.com

# Skip specific scan phases
python src/main.py --target example.com --skip-web-scan --skip-ssl-check
```

## 📖 Detailed Usage

### Command Line Options

```bash
python src/main.py [OPTIONS]

Required Arguments:
  --target, -t          Target IP address or hostname to scan

Scan Configuration:
  --ports, -p           Port range to scan (default: 1-1000)
  --web-paths           Web paths to test for vulnerabilities

Skip Options:
  --skip-port-scan      Skip port scanning phase
  --skip-ssl-check      Skip SSL/TLS security check
  --skip-version-check  Skip software version checking
  --skip-web-scan       Skip web vulnerability scanning

Output Options:
  --output, -o          Report formats: html, pdf, json (default: html)
  --output-dir          Directory to save reports (default: current)
  --verbose, -v         Enable verbose logging
  --quiet, -q           Suppress non-essential output
```

### Example Scans

```bash
# Basic website security assessment
python src/main.py --target example.com --output html pdf

# Internal network scan
python src/main.py --target 192.168.1.100 --ports 1-10000

# Web application focus
python src/main.py --target webapp.com --web-paths / /admin /api /login

# Quick service discovery
python src/main.py --target server.local --skip-web-scan --skip-ssl-check
```

## 📂 Project Structure

```
CyberSentinel/
├── README.md                   # This file
├── requirements.txt            # Python dependencies
├── setup.py                    # Package setup
├── run.sh                      # Shell script runner
│
├── src/                        # Source code
│   ├── main.py                 # Main orchestrator
│   │
│   ├── scanner/                # Scanning modules
│   │   ├── port_scanner.py     # Nmap integration & port scanning
│   │   ├── ssl_checker.py      # SSL/TLS security analysis
│   │   ├── vuln_checker.py     # Web vulnerability testing
│   │   └── version_checker.py  # Software version & CVE checking
│   │
│   ├── reports/                # Report generation
│   │   ├── pdf_report.py       # PDF report generation
│   │   └── html_report.py      # HTML report generation
│   │
│   └── utils/                  # Utilities
│       ├── risk_engine.py      # Risk assessment & scoring
│       └── logger.py           # Logging & console output
│
├── data/                       # Data files
│   └── cve_db.json             # CVE database
│
├── docs/                       # Documentation
│   └── architecture.md         # Architecture overview
│
└── tests/                      # Test suite
    ├── test_ports.py           # Port scanner tests
    ├── test_ssl.py             # SSL checker tests
    └── test_vuln.py            # Vulnerability scanner tests
```

## 🔧 Configuration

### CVE Database

CyberSentinel includes a local CVE database (`data/cve_db.json`) with known vulnerabilities for common software. You can extend this database by adding entries in the following format:

```json
{
  "software_name": {
    "version": {
      "cves": ["CVE-2021-1234", "CVE-2021-5678"],
      "risk": "High",
      "description": "Description of vulnerabilities"
    }
  }
}
```

### Custom Scan Profiles

Create custom scanning profiles by modifying the scan options:

```python
scan_options = {
    'port_range': '1-65535',        # Full port range
    'web_paths': ['/', '/admin', '/api'],  # Custom paths
    'skip_ssl_check': False,        # Enable all checks
    'timeout': 30                   # Custom timeout
}
```

## 📊 Sample Output

### Console Output
```
[+] Starting vulnerability scan for example.com
[+] Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
[!] SSL Expired Certificate → High Risk
[!] Apache 2.2 Detected (Outdated) → High Risk
[!!] SQL Injection vulnerability at /login → Critical

SCAN SUMMARY
============
Target: example.com
Total Findings: 15
Critical: 1 | High: 3 | Medium: 8 | Low: 3
```

### Report Formats

- **HTML Report**: Interactive web-based report with charts and filtering
- **PDF Report**: Professional document suitable for executive presentation
- **JSON Report**: Machine-readable format for integration with other tools

## 🛡️ Security & Ethics

### ⚠️ **IMPORTANT DISCLAIMER**

CyberSentinel is designed for **authorized security testing only**. Users must:

- ✅ Only scan systems they own or have explicit written permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Use findings responsibly to improve security
- ❌ Never use for malicious purposes or unauthorized access

### Responsible Disclosure

If you discover vulnerabilities using CyberSentinel:

1. **Notify system owners immediately**
2. **Provide detailed remediation guidance**
3. **Allow reasonable time for fixes**
4. **Follow coordinated disclosure practices**

## 🧪 Testing

Run the test suite to verify functionality:

```bash
# Install test dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/

# Run with coverage
pytest --cov=src tests/
```

## 🤝 Contributing

We welcome contributions! Please see our contributing guidelines:

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit changes**: `git commit -m 'Add amazing feature'`
4. **Push to branch**: `git push origin feature/amazing-feature`
5. **Open a Pull Request**

### Development Setup

```bash
# Clone for development
git clone https://github.com/yourusername/CyberSentinel.git
cd CyberSentinel

# Install in development mode
pip install -e .

# Install development dependencies
pip install -r requirements-dev.txt
```

## 📋 Roadmap

### Upcoming Features

- [ ] **Database Integration**: PostgreSQL/MySQL support for large-scale scanning
- [ ] **API Server**: REST API for integration with security platforms
- [ ] **Plugin System**: Extensible architecture for custom scanners
- [ ] **Continuous Monitoring**: Scheduled scanning and alerting
- [ ] **Cloud Integration**: AWS, Azure, GCP security assessments
- [ ] **Machine Learning**: AI-powered vulnerability prioritization
- [ ] **Mobile App Testing**: Android/iOS application security scanning

### Version History

- **v1.0.0**: Initial release with core scanning capabilities
- **v0.9.0**: Beta release with PDF/HTML reporting
- **v0.8.0**: Alpha release with basic vulnerability detection

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Nmap Project**: For the excellent network discovery tool
- **OWASP**: For web application security guidance
- **CVE Database**: For vulnerability information
- **Python Security Community**: For libraries and best practices

## 📞 Support

- **Documentation**: [Wiki](https://github.com/yourusername/CyberSentinel/wiki)
- **Issues**: [GitHub Issues](https://github.com/yourusername/CyberSentinel/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/CyberSentinel/discussions)
- **Security**: Report security issues to security@cybersentinel.com

---

**Made with ❤️ for the cybersecurity community by M DHARAN RAJ -- Web Developer------CISCO Trained & CISCO Certified Ethical Hacker----- 🔒**

🌐 **Web Developer** | 🔐 **CISCO Certified** | ⚡ **Ethical Hacker** | 🛡️ **Security Expert**

*Remember: With great power comes great responsibility. Use CyberSentinel ethically and legally.*
