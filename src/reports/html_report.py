from jinja2 import Template, Environment, FileSystemLoader
from datetime import datetime
from typing import Dict, List, Any
import json
import os
from pathlib import Path

from ..utils.logger import logger

class HTMLReportGenerator:
    """Generate interactive HTML security reports using Jinja2"""
    
    def __init__(self):
        self.template_dir = Path(__file__).parent / "templates"
        self.template_dir.mkdir(exist_ok=True)
        
        # Create Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )
        
        # Create template if it doesn't exist
        self._create_html_template()
    
    def _create_html_template(self):
        """Create HTML template file"""
        template_path = self.template_dir / "report_template.html"
        
        if not template_path.exists():
            html_template = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CyberSentinel Security Report</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            padding: 20px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
        }
        
        .card h3 {
            margin-bottom: 10px;
            color: #555;
        }
        
        .card .number {
            font-size: 2em;
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .critical { color: #8b5cf6; }
        .high { color: #ef4444; }
        .medium { color: #f59e0b; }
        .low { color: #10b981; }
        .info { color: #3b82f6; }
        
        .section {
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .section-header {
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #e9ecef;
        }
        
        .section-header h2 {
            color: #495057;
            margin-bottom: 5px;
        }
        
        .section-content {
            padding: 20px;
        }
        
        .table-responsive {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        
        th {
            background-color: #f8f9fa;
            font-weight: 600;
            color: #495057;
        }
        
        tr:hover {
            background-color: #f8f9fa;
        }
        
        .vulnerability-item {
            background: #f8f9fa;
            border-left: 4px solid #dee2e6;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 0 5px 5px 0;
        }
        
        .vulnerability-item.critical {
            border-left-color: #8b5cf6;
        }
        
        .vulnerability-item.high {
            border-left-color: #ef4444;
        }
        
        .vulnerability-item.medium {
            border-left-color: #f59e0b;
        }
        
        .vulnerability-item.low {
            border-left-color: #10b981;
        }
        
        .vulnerability-title {
            font-weight: 600;
            margin-bottom: 5px;
        }
        
        .vulnerability-description {
            color: #666;
            margin-bottom: 10px;
        }
        
        .vulnerability-details {
            font-size: 0.9em;
            color: #888;
        }
        
        .recommendations {
            background: #e7f3ff;
            border: 1px solid #b3d9ff;
            border-radius: 5px;
            padding: 20px;
            margin-top: 20px;
        }
        
        .recommendations h3 {
            color: #0056b3;
            margin-bottom: 15px;
        }
        
        .recommendations ul {
            padding-left: 20px;
        }
        
        .recommendations li {
            margin-bottom: 8px;
        }
        
        .progress-bar {
            background-color: #e9ecef;
            border-radius: 10px;
            height: 20px;
            overflow: hidden;
            margin-bottom: 10px;
        }
        
        .progress-fill {
            height: 100%;
            border-radius: 10px;
            transition: width 0.3s ease;
        }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: #666;
            border-top: 1px solid #ddd;
            margin-top: 40px;
        }
        
        @media (max-width: 768px) {
            .container {
                padding: 10px;
            }
            
            .header h1 {
                font-size: 2em;
            }
            
            .summary-cards {
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ CyberSentinel</h1>
            <p>Automated Vulnerability Assessment Report</p>
            <p><strong>Target:</strong> {{ target }} | <strong>Scan Date:</strong> {{ scan_date }}</p>
        </div>
        
        <!-- Summary Cards -->
        <div class="summary-cards">
            <div class="card">
                <h3>Overall Risk</h3>
                <div class="number {{ overall_risk.lower() }}">{{ overall_risk }}</div>
                <p>Risk Level</p>
            </div>
            <div class="card">
                <h3>Critical</h3>
                <div class="number critical">{{ risk_summary.Critical or 0 }}</div>
                <p>Vulnerabilities</p>
            </div>
            <div class="card">
                <h3>High</h3>
                <div class="number high">{{ risk_summary.High or 0 }}</div>
                <p>Vulnerabilities</p>
            </div>
            <div class="card">
                <h3>Medium</h3>
                <div class="number medium">{{ risk_summary.Medium or 0 }}</div>
                <p>Vulnerabilities</p>
            </div>
            <div class="card">
                <h3>Low</h3>
                <div class="number low">{{ risk_summary.Low or 0 }}</div>
                <p>Vulnerabilities</p>
            </div>
        </div>
        
        <!-- Port Scan Results -->
        {% if port_scan %}
        <div class="section">
            <div class="section-header">
                <h2>🔍 Port Scan Results</h2>
                <p>Open ports and running services discovered</p>
            </div>
            <div class="section-content">
                <p><strong>Open Ports:</strong> {{ port_scan.open_ports|length }}</p>
                {% if port_scan.open_ports %}
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Port</th>
                                <th>Service</th>
                                <th>Version</th>
                                <th>Risk Level</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for port in port_scan.open_ports %}
                            {% set service = port_scan.services[port] %}
                            <tr>
                                <td>{{ port }}</td>
                                <td>{{ service.service or 'Unknown' }}</td>
                                <td>{{ service.version or 'N/A' }}</td>
                                <td><span class="{{ 'high' if port in [21, 23, 135, 139, 445, 1433, 3389, 5432] else 'medium' if port < 1024 else 'low' }}">
                                    {{ 'High' if port in [21, 23, 135, 139, 445, 1433, 3389, 5432] else 'Medium' if port < 1024 else 'Low' }}
                                </span></td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}
        
        <!-- SSL/TLS Analysis -->
        {% if ssl_check %}
        <div class="section">
            <div class="section-header">
                <h2>🔒 SSL/TLS Security Analysis</h2>
                <p>Certificate and encryption security assessment</p>
            </div>
            <div class="section-content">
                {% if ssl_check.overall_grade %}
                <p><strong>SSL Grade:</strong> <span class="{{ 'low' if ssl_check.overall_grade in ['A+', 'A'] else 'medium' if ssl_check.overall_grade in ['A-', 'B+', 'B'] else 'high' }}">{{ ssl_check.overall_grade }}</span></p>
                {% endif %}
                
                {% if ssl_check.certificate_info %}
                <h4>Certificate Information:</h4>
                <ul>
                    {% if ssl_check.certificate_info.subject %}
                    <li><strong>Subject:</strong> {{ ssl_check.certificate_info.subject.get('commonName', 'N/A') }}</li>
                    {% endif %}
                    {% if ssl_check.certificate_info.not_valid_after %}
                    <li><strong>Expires:</strong> {{ ssl_check.certificate_info.not_valid_after }}</li>
                    {% endif %}
                    {% if ssl_check.certificate_info.signature_algorithm %}
                    <li><strong>Signature Algorithm:</strong> {{ ssl_check.certificate_info.signature_algorithm }}</li>
                    {% endif %}
                </ul>
                {% endif %}
            </div>
        </div>
        {% endif %}
        
        <!-- Version Check Results -->
        {% if version_check and version_check.vulnerable_services %}
        <div class="section">
            <div class="section-header">
                <h2>📦 Software Version Analysis</h2>
                <p>Outdated software and known vulnerabilities</p>
            </div>
            <div class="section-content">
                <p><strong>Vulnerable Services:</strong> {{ version_check.vulnerable_services|length }}</p>
                
                {% for service in version_check.vulnerable_services %}
                <div class="vulnerability-item {{ service.vulnerabilities[0].risk.lower() if service.vulnerabilities else 'medium' }}">
                    <div class="vulnerability-title">{{ service.service|title }} {{ service.version }}</div>
                    <div class="vulnerability-description">
                        {% if service.vulnerabilities %}
                        {{ service.vulnerabilities[0].description }}
                        {% endif %}
                    </div>
                    <div class="vulnerability-details">
                        <strong>CVEs:</strong> 
                        {% if service.vulnerabilities and service.vulnerabilities[0].cves %}
                        {{ service.vulnerabilities[0].cves[:3]|join(', ') }}
                        {% else %}
                        N/A
                        {% endif %}
                    </div>
                </div>
                {% endfor %}
            </div>
        </div>
        {% endif %}
        
        <!-- Web Vulnerabilities -->
        {% if vulnerability_scan %}
        <div class="section">
            <div class="section-header">
                <h2>🌐 Web Application Vulnerabilities</h2>
                <p>Web application security assessment results</p>
            </div>
            <div class="section-content">
                {% if vulnerability_scan.vulnerabilities_found %}
                <p><strong>Vulnerabilities Found:</strong> {{ vulnerability_scan.vulnerabilities_found|length }}</p>
                
                {% for vuln in vulnerability_scan.vulnerabilities_found %}
                <div class="vulnerability-item {{ vuln.risk_level.lower() if vuln.risk_level else 'medium' }}">
                    <div class="vulnerability-title">{{ vuln.type or vuln.vuln_type }}</div>
                    <div class="vulnerability-description">{{ vuln.description }}</div>
                    {% if vuln.details %}
                    <div class="vulnerability-details">
                        <strong>Details:</strong> {{ vuln.details.url or vuln.details.parameter or 'See full report' }}
                    </div>
                    {% endif %}
                </div>
                {% endfor %}
                {% endif %}
                
                <!-- Security Headers -->
                {% if vulnerability_scan.security_headers %}
                <h4>Security Headers Analysis:</h4>
                <div class="table-responsive">
                    <table>
                        <thead>
                            <tr>
                                <th>Header</th>
                                <th>Status</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for header, value in vulnerability_scan.security_headers.items() %}
                            <tr>
                                <td>{{ header }}</td>
                                <td>
                                    {% if value %}
                                    <span class="low">✓ Present</span>
                                    {% else %}
                                    <span class="high">✗ Missing</span>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% endif %}
            </div>
        </div>
        {% endif %}
        
        <!-- Recommendations -->
        {% if recommendations %}
        <div class="recommendations">
            <h3>🔧 Security Recommendations</h3>
            <ul>
                {% for recommendation in recommendations[:10] %}
                <li>{{ recommendation }}</li>
                {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <!-- Footer -->
        <div class="footer">
            <p>Generated by CyberSentinel - Automated Vulnerability Assessment Tool</p>
            <p>Report generated on {{ scan_date }}</p>
        </div>
    </div>
    
    <script>
        // Add some interactivity
        document.addEventListener('DOMContentLoaded', function() {
            // Animate progress bars if any
            const progressBars = document.querySelectorAll('.progress-fill');
            progressBars.forEach(bar => {
                const width = bar.style.width;
                bar.style.width = '0%';
                setTimeout(() => {
                    bar.style.width = width;
                }, 100);
            });
            
            // Add click handlers for expandable sections
            const vulnerabilityItems = document.querySelectorAll('.vulnerability-item');
            vulnerabilityItems.forEach(item => {
                item.style.cursor = 'pointer';
                item.addEventListener('click', function() {
                    const details = this.querySelector('.vulnerability-details');
                    if (details) {
                        details.style.display = details.style.display === 'none' ? 'block' : 'none';
                    }
                });
            });
        });
    </script>
</body>
</html>
            """
            
            with open(template_path, 'w', encoding='utf-8') as f:
                f.write(html_template)
    
    def generate_report(self, scan_results: Dict[str, Any], output_path: str = "CyberSentinel_Report.html") -> str:
        """
        Generate interactive HTML security report
        
        Args:
            scan_results: Combined results from all scanners
            output_path: Path to save the HTML report
            
        Returns:
            Path to generated HTML file
        """
        logger.info(f"Generating HTML report: {output_path}")
        
        try:
            # Load template
            template = self.env.get_template("report_template.html")
            
            # Prepare template data
            template_data = self._prepare_template_data(scan_results)
            
            # Render template
            html_content = template.render(**template_data)
            
            # Write to file
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            logger.info(f"HTML report generated successfully: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate HTML report: {str(e)}")
            raise
    
    def _prepare_template_data(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Prepare data for template rendering"""
        
        # Calculate overall statistics
        total_findings = 0
        risk_summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        all_recommendations = []
        
        # Aggregate data from all scanners
        for scan_type, results in scan_results.items():
            if isinstance(results, dict) and 'summary' in results:
                summary = results['summary']
                if 'total_findings' in summary:
                    total_findings += summary['total_findings']
                if 'risk_summary' in summary:
                    for risk, count in summary['risk_summary'].items():
                        if risk in risk_summary:
                            risk_summary[risk] += count
                if 'recommendations' in summary:
                    all_recommendations.extend(summary['recommendations'])
        
        # Remove duplicate recommendations
        unique_recommendations = []
        for rec in all_recommendations:
            if rec not in unique_recommendations:
                unique_recommendations.append(rec)
        
        # Calculate overall risk
        overall_risk = self._calculate_overall_risk(risk_summary)
        
        # Prepare template data
        template_data = {
            'target': scan_results.get('target', 'Unknown'),
            'scan_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'overall_risk': overall_risk,
            'risk_summary': risk_summary,
            'total_findings': total_findings,
            'recommendations': unique_recommendations,
            'port_scan': scan_results.get('port_scan'),
            'ssl_check': scan_results.get('ssl_check'),
            'version_check': scan_results.get('version_check'),
            'vulnerability_scan': scan_results.get('vulnerability_scan')
        }
        
        return template_data
    
    def _calculate_overall_risk(self, risk_summary: Dict[str, int]) -> str:
        """Calculate overall risk level"""
        if risk_summary.get('Critical', 0) > 0:
            return "Critical"
        elif risk_summary.get('High', 0) > 2:
            return "High"
        elif risk_summary.get('High', 0) > 0 or risk_summary.get('Medium', 0) > 5:
            return "Medium"
        else:
            return "Low"
    
    def generate_json_report(self, scan_results: Dict[str, Any], output_path: str = "CyberSentinel_Report.json") -> str:
        """Generate JSON report for API consumption"""
        logger.info(f"Generating JSON report: {output_path}")
        
        try:
            # Prepare JSON data
            json_data = {
                'metadata': {
                    'target': scan_results.get('target', 'Unknown'),
                    'scan_date': datetime.now().isoformat(),
                    'tool': 'CyberSentinel',
                    'version': '1.0.0'
                },
                'summary': self._prepare_template_data(scan_results),
                'detailed_results': scan_results
            }
            
            # Write JSON file
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(json_data, f, indent=2, default=str)
            
            logger.info(f"JSON report generated successfully: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate JSON report: {str(e)}")
            raise
