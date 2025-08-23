# 🚀 CyberSentinel Execution Guide

## Table of Contents
- [System Requirements](#system-requirements)
- [Installation Steps](#installation-steps)
- [Basic Usage](#basic-usage)
- [Advanced Usage](#advanced-usage)
- [Command Reference](#command-reference)
- [Output Examples](#output-examples)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## 📋 System Requirements

### Minimum Requirements
- **Operating System**: Windows 10+, macOS 10.15+, or Linux (Ubuntu 18.04+)
- **Python**: Version 3.8 or higher
- **RAM**: 2GB minimum, 4GB recommended
- **Disk Space**: 500MB for installation and reports
- **Network**: Internet connectivity for target scanning

### Recommended Tools
- **nmap**: For enhanced port scanning capabilities
- **openssl**: For advanced SSL/TLS analysis
- **Git**: For version control and updates

---

## 🔧 Installation Steps

### Step 1: Download and Setup
```bash
# Clone or download the CyberSentinel project
cd "d:\VS Code\CyberSentinel"

# Verify Python installation
python --version
# Should show Python 3.8.0 or higher
```

### Step 2: Install Dependencies
```bash
# Install required Python packages
pip install -r requirements.txt

# Alternative: Use virtual environment (recommended)
python -m venv cybersentinel-env
# Windows:
cybersentinel-env\Scripts\activate
# Linux/Mac:
source cybersentinel-env/bin/activate

# Then install dependencies
pip install -r requirements.txt
```

### Step 3: Install Optional Tools (Recommended)

#### Windows:
```bash
# Download and install nmap from: https://nmap.org/download.html
# Download and install OpenSSL from: https://slproweb.com/products/Win32OpenSSL.html
```

#### Linux (Ubuntu/Debian):
```bash
sudo apt-get update
sudo apt-get install nmap openssl
```

#### macOS:
```bash
# Using Homebrew
brew install nmap openssl
```

### Step 4: Verify Installation
```bash
# Test the installation
python src/main.py --help
```

---

## 🎯 Basic Usage

### Quick Start Examples

#### 1. Basic Website Scan
```bash
python src/main.py --target google.com
```
**What it does**: Scans ports 1-1000, checks SSL, analyzes versions, tests web vulnerabilities

#### 2. Generate PDF Report
```bash
python src/main.py --target example.com --output pdf
```
**What it does**: Same as basic scan but generates a professional PDF report

#### 3. Quiet Mode (Minimal Output)
```bash
python src/main.py --target example.com --quiet --output html
```
**What it does**: Runs scan with minimal console output

#### 4. Verbose Mode (Detailed Output)
```bash
python src/main.py --target example.com --verbose --output html pdf
```
**What it does**: Shows detailed debugging information during scan

---

## 🔥 Advanced Usage

### Comprehensive Security Assessment
```bash
python src/main.py \
  --target mywebsite.com \
  --ports 1-65535 \
  --web-paths / /admin /api /login /dashboard /config \
  --output html pdf json \
  --output-dir ./reports \
  --verbose
```

### Internal Network Scanning
```bash
python src/main.py \
  --target 192.168.1.100 \
  --ports 1-10000 \
  --skip-web-scan \
  --output pdf
```

### SSL/TLS Focus Assessment
```bash
python src/main.py \
  --target secure-banking-site.com \
  --ports 443,8443 \
  --skip-web-scan \
  --skip-version-check \
  --output html
```

### Web Application Security Focus
```bash
python src/main.py \
  --target webapp.company.com \
  --skip-port-scan \
  --web-paths / /login /admin /api /upload /search \
  --output html json
```

---

## 📖 Command Reference

### Required Parameters
| Parameter | Description | Example |
|-----------|-------------|---------|
| `--target`, `-t` | Target IP or hostname | `--target example.com` |

### Scan Configuration
| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--ports`, `-p` | Port range to scan | `1-1000` | `--ports 1-65535` |
| `--web-paths` | Web paths to test | `['/']` | `--web-paths / /admin /api` |

### Skip Options
| Parameter | Description |
|-----------|-------------|
| `--skip-port-scan` | Skip network port scanning |
| `--skip-ssl-check` | Skip SSL/TLS security analysis |
| `--skip-version-check` | Skip software version checking |
| `--skip-web-scan` | Skip web vulnerability testing |

### Output Options
| Parameter | Description | Default | Example |
|-----------|-------------|---------|---------|
| `--output`, `-o` | Report formats | `html` | `--output html pdf json` |
| `--output-dir` | Output directory | `.` | `--output-dir ./reports` |
| `--verbose`, `-v` | Detailed logging | `False` | `--verbose` |
| `--quiet`, `-q` | Minimal output | `False` | `--quiet` |

---

## 📊 Output Examples

### Console Output
```
    ╔═══════════════════════════════════════════════════════════╗
    ║                    🛡️  CyberSentinel 🛡️                    ║
    ║            Automated Vulnerability Assessment Tool        ║
    ║                                                           ║
    ║  ⚠️  FOR AUTHORIZED TESTING ONLY ⚠️                       ║
    ║  Only scan systems you own or have explicit permission   ║
    ╚═══════════════════════════════════════════════════════════╝

[+] Starting comprehensive security assessment of example.com
==================================================
PHASE 1: PORT SCANNING
==================================================
[+] Starting port scan for example.com
[+] Scanning ports 1-1000 on example.com
[+] Open Ports: 22 (SSH), 80 (HTTP), 443 (HTTPS)
[!] Open Port 22 (SSH) - Medium Risk
[+] Port scan completed. Found 3 open ports

==================================================
PHASE 2: SSL/TLS SECURITY CHECK
==================================================
[+] Starting SSL/TLS security check for example.com:443
[!] SSL Certificate Expiring Soon - Medium Risk
[+] SSL/TLS check completed. Grade: B+

==================================================
PHASE 3: SOFTWARE VERSION ANALYSIS
==================================================
[+] Starting software version vulnerability check
[!] Outdated Apache 2.2 - High Risk
[+] Version check completed. Found 1 vulnerable services

==================================================
PHASE 4: WEB VULNERABILITY SCANNING
==================================================
[+] Starting web vulnerability scan for example.com:80
[!] Missing Security Headers - Medium Risk
[+] Web vulnerability scan completed

============================================================
SCAN SUMMARY
============================================================
Target: example.com
Total Findings: 4
Scan Duration: 67.45 seconds

Risk Breakdown:
[!] High Risk Issues: 1 findings
[!] Medium Risk Issues: 3 findings

Top Security Risks:
[!] 1. Outdated Software - Apache - High - Apache 2.2 contains known vulnerabilities
[!] 2. SSL Certificate Expiring Soon - Medium - SSL certificate expires in 15 days
[!] 3. Open Port - SSH - Medium - Port 22/tcp (SSH) is open
[!] 4. Missing Security Headers - Medium - Missing security headers: X-Frame-Options, CSP
============================================================

Security assessment completed successfully!
Generated reports:
  HTML: CyberSentinel_example.com_20250823_182654.html
  PDF: CyberSentinel_example.com_20250823_182654.pdf
```

### Generated Files
After execution, you'll find these files in your output directory:
- `CyberSentinel_target_timestamp.html` - Interactive web report
- `CyberSentinel_target_timestamp.pdf` - Professional PDF report
- `CyberSentinel_target_timestamp.json` - Machine-readable data
- `cybersentinel.log` - Detailed execution log

---

## 🔧 Troubleshooting

### Common Issues and Solutions

#### 1. Import/Module Errors
```
Error: ModuleNotFoundError: No module named 'nmap'
```
**Solution:**
```bash
pip install -r requirements.txt
# Or install specific package:
pip install python-nmap
```

#### 2. Permission Denied
```
Error: [Errno 13] Permission denied
```
**Solution:**
```bash
# Windows: Run as Administrator
# Linux/Mac: Use sudo or check file permissions
chmod +x run.sh
```

#### 3. Network Connection Issues
```
Error: [Errno 11001] getaddrinfo failed
```
**Solution:**
- Check internet connectivity
- Verify target hostname/IP is correct
- Check firewall settings
- Try with `--verbose` for more details

#### 4. Nmap Not Found
```
Warning: nmap is not installed. Port scanning may use fallback method.
```
**Solution:**
- Install nmap (see installation steps above)
- Or continue with socket-based fallback (slower but functional)

#### 5. SSL Connection Errors
```
Error: SSL connection failed
```
**Solution:**
- Target may not support HTTPS
- Use `--skip-ssl-check` to bypass SSL scanning
- Check if port 443 is open

#### 6. Timeout Issues
```
Error: Request timed out
```
**Solution:**
- Target may be slow or blocking requests
- Increase timeout in code if needed
- Use `--skip-web-scan` for network-only scanning

### Debug Mode
For detailed troubleshooting, run with verbose mode:
```bash
python src/main.py --target example.com --verbose
```

---

## ✅ Best Practices

### Security and Ethics
1. **Authorization First**: Only scan systems you own or have explicit written permission
2. **Rate Limiting**: Tool includes built-in delays - don't modify to be more aggressive
3. **Responsible Disclosure**: Report findings to system owners responsibly
4. **Legal Compliance**: Ensure compliance with local laws and regulations

### Effective Scanning
1. **Start Small**: Begin with basic scans before comprehensive assessments
2. **Target Specific**: Use appropriate skip options for focused testing
3. **Multiple Formats**: Generate both HTML (for analysis) and PDF (for reporting)
4. **Regular Updates**: Keep CVE database and dependencies updated

### Performance Tips
1. **Reasonable Port Ranges**: Don't always use 1-65535 unless necessary
2. **Specific Web Paths**: Target known application paths rather than generic scanning
3. **Network Timing**: Run scans during appropriate hours
4. **Resource Management**: Monitor system resources during large scans

---

## 🎯 Example Execution Scenarios

### Scenario 1: Quick Security Check
```bash
# Goal: Quick assessment of a website
python src/main.py --target mysite.com --output html
# Time: ~30 seconds
# Use case: Regular security monitoring
```

### Scenario 2: Comprehensive Enterprise Assessment
```bash
# Goal: Full security audit of internal server
python src/main.py \
  --target 10.0.1.50 \
  --ports 1-65535 \
  --web-paths / /admin /api /management \
  --output html pdf json \
  --output-dir ./audit-reports \
  --verbose
# Time: 10-30 minutes
# Use case: Annual security audit
```

### Scenario 3: SSL/Certificate Focus
```bash
# Goal: SSL certificate and configuration review
python src/main.py \
  --target secure.company.com \
  --ports 443,8443 \
  --skip-web-scan \
  --skip-version-check \
  --output pdf
# Time: ~1 minute
# Use case: Certificate renewal planning
```

### Scenario 4: Web Application Penetration Test
```bash
# Goal: Web application vulnerability assessment
python src/main.py \
  --target webapp.target.com \
  --skip-port-scan \
  --web-paths / /login /admin /api /upload /search /profile \
  --output html json \
  --verbose
# Time: 5-15 minutes
# Use case: Application security testing
```

---

## 📞 Support and Resources

- **Documentation**: See README.md for detailed project information
- **Architecture**: See docs/architecture.md for technical details
- **Testing**: Run `pytest tests/` to verify installation
- **Issues**: Check logs and use verbose mode for debugging

---

**⚠️ IMPORTANT DISCLAIMER**

CyberSentinel is designed for authorized security testing only. Users must:
- ✅ Only scan systems they own or have explicit written permission to test
- ✅ Comply with all applicable laws and regulations
- ✅ Use findings responsibly to improve security
- ❌ Never use for malicious purposes or unauthorized access

**Remember: With great power comes great responsibility. Use CyberSentinel ethically and legally.**
