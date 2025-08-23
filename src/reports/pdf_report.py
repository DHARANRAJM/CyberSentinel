from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.platypus import Image as ReportLabImage
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from datetime import datetime
from typing import Dict, List, Any
import os
from pathlib import Path

from ..utils.logger import logger

class PDFReportGenerator:
    """Generate professional PDF security reports using ReportLab"""
    
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.darkblue,
            alignment=TA_CENTER
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='CustomSubtitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=20,
            textColor=colors.darkred,
            alignment=TA_CENTER
        ))
        
        # Section header style
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            spaceBefore=20,
            spaceAfter=10,
            textColor=colors.darkblue,
            borderWidth=1,
            borderColor=colors.darkblue,
            borderPadding=5
        ))
        
        # Risk level styles
        self.styles.add(ParagraphStyle(
            name='CriticalRisk',
            parent=self.styles['Normal'],
            textColor=colors.purple,
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='HighRisk',
            parent=self.styles['Normal'],
            textColor=colors.red,
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='MediumRisk',
            parent=self.styles['Normal'],
            textColor=colors.orange,
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
        
        self.styles.add(ParagraphStyle(
            name='LowRisk',
            parent=self.styles['Normal'],
            textColor=colors.green,
            fontSize=12,
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, scan_results: Dict[str, Any], output_path: str = "CyberSentinel_Report.pdf") -> str:
        """
        Generate comprehensive PDF security report
        
        Args:
            scan_results: Combined results from all scanners
            output_path: Path to save the PDF report
            
        Returns:
            Path to generated PDF file
        """
        logger.info(f"Generating PDF report: {output_path}")
        
        try:
            # Create PDF document
            doc = SimpleDocTemplate(output_path, pagesize=A4, topMargin=1*inch, bottomMargin=1*inch)
            story = []
            
            # Title page
            story.extend(self._create_title_page(scan_results))
            story.append(PageBreak())
            
            # Executive summary
            story.extend(self._create_executive_summary(scan_results))
            story.append(PageBreak())
            
            # Scan results sections
            if 'port_scan' in scan_results:
                story.extend(self._create_port_scan_section(scan_results['port_scan']))
                story.append(PageBreak())
            
            if 'ssl_check' in scan_results:
                story.extend(self._create_ssl_section(scan_results['ssl_check']))
                story.append(PageBreak())
            
            if 'version_check' in scan_results:
                story.extend(self._create_version_section(scan_results['version_check']))
                story.append(PageBreak())
            
            if 'vulnerability_scan' in scan_results:
                story.extend(self._create_vulnerability_section(scan_results['vulnerability_scan']))
                story.append(PageBreak())
            
            # Recommendations
            story.extend(self._create_recommendations_section(scan_results))
            
            # Build PDF
            doc.build(story)
            logger.info(f"PDF report generated successfully: {output_path}")
            return output_path
            
        except Exception as e:
            logger.error(f"Failed to generate PDF report: {str(e)}")
            raise
    
    def _create_title_page(self, scan_results: Dict[str, Any]) -> List:
        """Create title page"""
        story = []
        
        # Main title
        story.append(Paragraph("CyberSentinel", self.styles['CustomTitle']))
        story.append(Spacer(1, 20))
        
        # Subtitle
        story.append(Paragraph("Automated Vulnerability Assessment Report", self.styles['CustomSubtitle']))
        story.append(Spacer(1, 40))
        
        # Target information
        target = scan_results.get('target', 'Unknown')
        story.append(Paragraph(f"<b>Target:</b> {target}", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Scan date
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        story.append(Paragraph(f"<b>Scan Date:</b> {scan_date}", self.styles['Normal']))
        story.append(Spacer(1, 10))
        
        # Overall risk assessment
        overall_risk = self._calculate_overall_risk(scan_results)
        risk_color = self._get_risk_color(overall_risk)
        story.append(Paragraph(f"<b>Overall Risk Level:</b> <font color='{risk_color}'>{overall_risk}</font>", 
                              self.styles['Normal']))
        story.append(Spacer(1, 40))
        
        # Disclaimer
        disclaimer = """
        <b>DISCLAIMER:</b> This report is generated by CyberSentinel for security assessment purposes. 
        The findings should be verified by qualified security professionals. This tool is intended for 
        authorized testing only on systems you own or have explicit permission to test.
        """
        story.append(Paragraph(disclaimer, self.styles['Normal']))
        
        return story
    
    def _create_executive_summary(self, scan_results: Dict[str, Any]) -> List:
        """Create executive summary section"""
        story = []
        
        story.append(Paragraph("Executive Summary", self.styles['SectionHeader']))
        story.append(Spacer(1, 20))
        
        # Summary statistics
        total_findings = 0
        risk_summary = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        # Aggregate findings from all scanners
        for scan_type, results in scan_results.items():
            if isinstance(results, dict) and 'summary' in results:
                summary = results['summary']
                if 'total_findings' in summary:
                    total_findings += summary['total_findings']
                if 'risk_summary' in summary:
                    for risk, count in summary['risk_summary'].items():
                        if risk in risk_summary:
                            risk_summary[risk] += count
        
        # Summary table
        summary_data = [
            ['Risk Level', 'Count', 'Percentage'],
            ['Critical', str(risk_summary['Critical']), f"{self._calculate_percentage(risk_summary['Critical'], total_findings):.1f}%"],
            ['High', str(risk_summary['High']), f"{self._calculate_percentage(risk_summary['High'], total_findings):.1f}%"],
            ['Medium', str(risk_summary['Medium']), f"{self._calculate_percentage(risk_summary['Medium'], total_findings):.1f}%"],
            ['Low', str(risk_summary['Low']), f"{self._calculate_percentage(risk_summary['Low'], total_findings):.1f}%"],
            ['Info', str(risk_summary['Info']), f"{self._calculate_percentage(risk_summary['Info'], total_findings):.1f}%"],
            ['Total', str(total_findings), '100.0%']
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -2), colors.beige),
            ('BACKGROUND', (0, -1), (-1, -1), colors.lightgrey),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Key findings
        story.append(Paragraph("Key Findings:", self.styles['Heading3']))
        
        if risk_summary['Critical'] > 0:
            story.append(Paragraph(f"🚨 <b>{risk_summary['Critical']} Critical vulnerabilities</b> require immediate attention", 
                                  self.styles['CriticalRisk']))
        
        if risk_summary['High'] > 0:
            story.append(Paragraph(f"⚠️ <b>{risk_summary['High']} High-risk vulnerabilities</b> should be addressed urgently", 
                                  self.styles['HighRisk']))
        
        if risk_summary['Medium'] > 0:
            story.append(Paragraph(f"📋 <b>{risk_summary['Medium']} Medium-risk issues</b> should be planned for remediation", 
                                  self.styles['MediumRisk']))
        
        return story
    
    def _create_port_scan_section(self, port_results: Dict[str, Any]) -> List:
        """Create port scan results section"""
        story = []
        
        story.append(Paragraph("Port Scan Results", self.styles['SectionHeader']))
        story.append(Spacer(1, 10))
        
        if 'open_ports' in port_results:
            story.append(Paragraph(f"<b>Open Ports Found:</b> {len(port_results['open_ports'])}", 
                                  self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Create ports table
            if port_results['open_ports']:
                port_data = [['Port', 'Service', 'Version', 'Risk Level']]
                
                for port in port_results['open_ports']:
                    service_info = port_results.get('services', {}).get(port, {})
                    service = service_info.get('service', 'unknown')
                    version = service_info.get('version', 'N/A')
                    
                    # Determine risk level (simplified)
                    high_risk_ports = [21, 23, 135, 139, 445, 1433, 3389, 5432]
                    risk_level = "High" if port in high_risk_ports else "Medium" if port < 1024 else "Low"
                    
                    port_data.append([str(port), service, version, risk_level])
                
                port_table = Table(port_data)
                port_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(port_table)
        
        return story
    
    def _create_ssl_section(self, ssl_results: Dict[str, Any]) -> List:
        """Create SSL/TLS analysis section"""
        story = []
        
        story.append(Paragraph("SSL/TLS Security Analysis", self.styles['SectionHeader']))
        story.append(Spacer(1, 10))
        
        if 'overall_grade' in ssl_results:
            grade = ssl_results['overall_grade']
            grade_color = self._get_ssl_grade_color(grade)
            story.append(Paragraph(f"<b>SSL Grade:</b> <font color='{grade_color}'>{grade}</font>", 
                                  self.styles['Normal']))
            story.append(Spacer(1, 10))
        
        # Certificate information
        if 'certificate_info' in ssl_results:
            cert_info = ssl_results['certificate_info']
            story.append(Paragraph("<b>Certificate Information:</b>", self.styles['Heading3']))
            
            if 'subject' in cert_info:
                story.append(Paragraph(f"Subject: {cert_info.get('subject', {}).get('commonName', 'N/A')}", 
                                      self.styles['Normal']))
            
            if 'not_valid_after' in cert_info:
                story.append(Paragraph(f"Expires: {cert_info['not_valid_after']}", self.styles['Normal']))
            
            if 'signature_algorithm' in cert_info:
                story.append(Paragraph(f"Signature Algorithm: {cert_info['signature_algorithm']}", 
                                      self.styles['Normal']))
        
        return story
    
    def _create_version_section(self, version_results: Dict[str, Any]) -> List:
        """Create version check section"""
        story = []
        
        story.append(Paragraph("Software Version Analysis", self.styles['SectionHeader']))
        story.append(Spacer(1, 10))
        
        if 'vulnerable_services' in version_results:
            vuln_services = version_results['vulnerable_services']
            if vuln_services:
                story.append(Paragraph(f"<b>Vulnerable Services Found:</b> {len(vuln_services)}", 
                                      self.styles['Normal']))
                story.append(Spacer(1, 10))
                
                # Create vulnerable services table
                vuln_data = [['Service', 'Version', 'CVEs', 'Risk Level']]
                
                for service in vuln_services:
                    cves = ', '.join(service.get('vulnerabilities', [{}])[0].get('cves', [])[:3])
                    risk = service.get('vulnerabilities', [{}])[0].get('risk', 'Medium')
                    
                    vuln_data.append([
                        service.get('service', 'Unknown'),
                        service.get('version', 'N/A'),
                        cves,
                        risk
                    ])
                
                vuln_table = Table(vuln_data)
                vuln_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                story.append(vuln_table)
        
        return story
    
    def _create_vulnerability_section(self, vuln_results: Dict[str, Any]) -> List:
        """Create web vulnerability section"""
        story = []
        
        story.append(Paragraph("Web Application Vulnerabilities", self.styles['SectionHeader']))
        story.append(Spacer(1, 10))
        
        if 'vulnerabilities_found' in vuln_results:
            vulns = vuln_results['vulnerabilities_found']
            story.append(Paragraph(f"<b>Vulnerabilities Found:</b> {len(vulns)}", self.styles['Normal']))
            story.append(Spacer(1, 10))
            
            # Group vulnerabilities by type
            vuln_types = {}
            for vuln in vulns:
                vuln_type = vuln.get('type', 'Unknown')
                if vuln_type not in vuln_types:
                    vuln_types[vuln_type] = []
                vuln_types[vuln_type].append(vuln)
            
            for vuln_type, vuln_list in vuln_types.items():
                story.append(Paragraph(f"<b>{vuln_type}:</b> {len(vuln_list)} instances", 
                                      self.styles['Normal']))
        
        # Security headers analysis
        if 'security_headers' in vuln_results:
            story.append(Spacer(1, 10))
            story.append(Paragraph("<b>Security Headers Analysis:</b>", self.styles['Heading3']))
            
            headers = vuln_results['security_headers']
            for header, value in headers.items():
                status = "✓ Present" if value else "✗ Missing"
                color = "green" if value else "red"
                story.append(Paragraph(f"<font color='{color}'>{header}: {status}</font>", 
                                      self.styles['Normal']))
        
        return story
    
    def _create_recommendations_section(self, scan_results: Dict[str, Any]) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("Security Recommendations", self.styles['SectionHeader']))
        story.append(Spacer(1, 10))
        
        # Collect recommendations from all scanners
        all_recommendations = []
        
        for scan_type, results in scan_results.items():
            if isinstance(results, dict) and 'summary' in results:
                recommendations = results['summary'].get('recommendations', [])
                all_recommendations.extend(recommendations)
        
        # Remove duplicates while preserving order
        unique_recommendations = []
        for rec in all_recommendations:
            if rec not in unique_recommendations:
                unique_recommendations.append(rec)
        
        # Add recommendations as bullet points
        for i, recommendation in enumerate(unique_recommendations[:10], 1):  # Limit to top 10
            story.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
            story.append(Spacer(1, 5))
        
        return story
    
    def _calculate_overall_risk(self, scan_results: Dict[str, Any]) -> str:
        """Calculate overall risk level"""
        total_critical = 0
        total_high = 0
        total_medium = 0
        
        for scan_type, results in scan_results.items():
            if isinstance(results, dict) and 'summary' in results:
                risk_summary = results['summary'].get('risk_summary', {})
                total_critical += risk_summary.get('Critical', 0)
                total_high += risk_summary.get('High', 0)
                total_medium += risk_summary.get('Medium', 0)
        
        if total_critical > 0:
            return "Critical"
        elif total_high > 2:
            return "High"
        elif total_high > 0 or total_medium > 5:
            return "Medium"
        else:
            return "Low"
    
    def _get_risk_color(self, risk_level: str) -> str:
        """Get color for risk level"""
        colors_map = {
            'Critical': 'purple',
            'High': 'red',
            'Medium': 'orange',
            'Low': 'green',
            'Info': 'blue'
        }
        return colors_map.get(risk_level, 'black')
    
    def _get_ssl_grade_color(self, grade: str) -> str:
        """Get color for SSL grade"""
        if grade in ['A+', 'A']:
            return 'green'
        elif grade in ['A-', 'B+', 'B']:
            return 'orange'
        elif grade in ['B-', 'C+', 'C']:
            return 'red'
        else:
            return 'purple'
    
    def _calculate_percentage(self, count: int, total: int) -> float:
        """Calculate percentage"""
        return (count / total * 100) if total > 0 else 0.0
