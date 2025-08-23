from enum import Enum
from typing import Dict, List, Any
import json

class RiskLevel(Enum):
    """Risk severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"

class VulnerabilityFinding:
    """Represents a single vulnerability finding"""
    
    def __init__(self, vuln_type: str, description: str, risk_level: RiskLevel, 
                 details: Dict[str, Any] = None, remediation: str = ""):
        self.vuln_type = vuln_type
        self.description = description
        self.risk_level = risk_level
        self.details = details or {}
        self.remediation = remediation
        self.timestamp = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert finding to dictionary for reporting"""
        return {
            'type': self.vuln_type,
            'description': self.description,
            'risk_level': self.risk_level.value,
            'details': self.details,
            'remediation': self.remediation,
            'timestamp': self.timestamp
        }

class RiskEngine:
    """Risk assessment and scoring engine"""
    
    # Risk scoring weights
    RISK_SCORES = {
        RiskLevel.CRITICAL: 10,
        RiskLevel.HIGH: 7,
        RiskLevel.MEDIUM: 4,
        RiskLevel.LOW: 2,
        RiskLevel.INFO: 0
    }
    
    # Port risk mappings
    HIGH_RISK_PORTS = [21, 23, 135, 139, 445, 1433, 3389, 5432]
    MEDIUM_RISK_PORTS = [22, 25, 53, 110, 143, 993, 995]
    
    def __init__(self):
        self.findings: List[VulnerabilityFinding] = []
    
    def add_finding(self, finding: VulnerabilityFinding):
        """Add a vulnerability finding"""
        self.findings.append(finding)
    
    def assess_port_risk(self, port: int, service: str = "") -> RiskLevel:
        """Assess risk level for an open port"""
        if port in self.HIGH_RISK_PORTS:
            return RiskLevel.HIGH
        elif port in self.MEDIUM_RISK_PORTS:
            return RiskLevel.MEDIUM
        elif port < 1024:  # Well-known ports
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def assess_ssl_risk(self, ssl_info: Dict[str, Any]) -> RiskLevel:
        """Assess SSL/TLS configuration risk"""
        if ssl_info.get('expired', False):
            return RiskLevel.HIGH
        elif ssl_info.get('self_signed', False):
            return RiskLevel.MEDIUM
        elif ssl_info.get('weak_cipher', False):
            return RiskLevel.MEDIUM
        elif ssl_info.get('protocol_version') in ['SSLv2', 'SSLv3', 'TLSv1.0']:
            return RiskLevel.HIGH
        else:
            return RiskLevel.LOW
    
    def assess_version_risk(self, software: str, version: str, cve_data: Dict) -> RiskLevel:
        """Assess risk based on software version and CVE data"""
        software_lower = software.lower()
        if software_lower in cve_data:
            if version in cve_data[software_lower]:
                risk_str = cve_data[software_lower][version].get('risk', 'Low')
                return RiskLevel(risk_str)
        return RiskLevel.INFO
    
    def assess_web_vuln_risk(self, vuln_type: str) -> RiskLevel:
        """Assess risk for web vulnerabilities"""
        critical_vulns = ['sql_injection', 'command_injection', 'rce']
        high_vulns = ['xss_stored', 'csrf', 'lfi', 'rfi']
        medium_vulns = ['xss_reflected', 'information_disclosure']
        
        vuln_lower = vuln_type.lower()
        if any(v in vuln_lower for v in critical_vulns):
            return RiskLevel.CRITICAL
        elif any(v in vuln_lower for v in high_vulns):
            return RiskLevel.HIGH
        elif any(v in vuln_lower for v in medium_vulns):
            return RiskLevel.MEDIUM
        else:
            return RiskLevel.LOW
    
    def calculate_overall_score(self) -> float:
        """Calculate overall risk score"""
        if not self.findings:
            return 0.0
        
        total_score = sum(self.RISK_SCORES[finding.risk_level] for finding in self.findings)
        return total_score / len(self.findings)
    
    def get_risk_summary(self) -> Dict[str, int]:
        """Get summary of findings by risk level"""
        summary = {level.value: 0 for level in RiskLevel}
        for finding in self.findings:
            summary[finding.risk_level.value] += 1
        return summary
    
    def get_top_risks(self, limit: int = 5) -> List[VulnerabilityFinding]:
        """Get top risk findings sorted by severity"""
        severity_order = [RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM, RiskLevel.LOW, RiskLevel.INFO]
        sorted_findings = sorted(self.findings, key=lambda x: severity_order.index(x.risk_level))
        return sorted_findings[:limit]
    
    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []
        risk_summary = self.get_risk_summary()
        
        if risk_summary['Critical'] > 0:
            recommendations.append("🚨 IMMEDIATE ACTION REQUIRED: Critical vulnerabilities detected")
            recommendations.append("• Patch all critical vulnerabilities immediately")
            recommendations.append("• Consider taking affected systems offline until patched")
        
        if risk_summary['High'] > 0:
            recommendations.append("⚠️  High-risk vulnerabilities require urgent attention")
            recommendations.append("• Schedule emergency patching within 24-48 hours")
            recommendations.append("• Implement additional monitoring for affected services")
        
        if risk_summary['Medium'] > 0:
            recommendations.append("📋 Medium-risk issues should be addressed in next maintenance window")
            recommendations.append("• Plan patches and configuration changes")
            recommendations.append("• Review security configurations")
        
        # General recommendations
        recommendations.extend([
            "🔒 Implement network segmentation and access controls",
            "📊 Regular vulnerability scanning and security assessments",
            "🛡️  Deploy intrusion detection and prevention systems",
            "📚 Security awareness training for staff",
            "💾 Regular security backups and incident response planning"
        ])
        
        return recommendations
    
    def export_findings(self) -> List[Dict[str, Any]]:
        """Export all findings as dictionaries"""
        return [finding.to_dict() for finding in self.findings]
