#!/usr/bin/env python3

"""
CyberSentinel Pro - Celery Worker
Background task processing and rule engine
Author: CyberSentinel Team
Version: 2.0
"""

from celery import Celery
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
import logging
import json

from ..database import SessionLocal
from ..models import Event, Finding, Alert, Rule, Agent
from ..config import settings

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Celery app
celery_app = Celery(
    "cybersentinel_worker",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.workers.worker"]
)

# Celery configuration
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_routes={
        "app.workers.worker.process_events": {"queue": "events"},
        "app.workers.worker.process_findings": {"queue": "findings"},
        "app.workers.worker.evaluate_rules": {"queue": "rules"},
    }
)

def get_db() -> Session:
    """Get database session"""
    db = SessionLocal()
    try:
        return db
    except Exception:
        db.close()
        raise

@celery_app.task(name="app.workers.worker.process_events")
def process_events(event_ids: list):
    """Process events and generate findings"""
    db = get_db()
    try:
        events = db.query(Event).filter(Event.id.in_(event_ids)).all()
        findings_created = 0
        
        for event in events:
            # Simple rule engine - detect suspicious activities
            findings = analyze_event(event, db)
            
            for finding_data in findings:
                finding = Finding(**finding_data)
                db.add(finding)
                findings_created += 1
        
        db.commit()
        logger.info(f"Processed {len(events)} events, created {findings_created} findings")
        
        return {"processed": len(events), "findings_created": findings_created}
        
    except Exception as e:
        logger.error(f"Error processing events: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def analyze_event(event: Event, db: Session) -> list:
    """Analyze event and generate findings"""
    findings = []
    
    try:
        # Rule 1: Multiple failed login attempts
        if event.event_type == "auth.fail":
            # Count recent failed attempts from same IP
            if "ip" in event.payload:
                ip_address = event.payload["ip"]
                recent_failures = db.query(Event).filter(
                    Event.event_type == "auth.fail",
                    Event.timestamp >= datetime.utcnow() - timedelta(minutes=10),
                    Event.payload.contains({"ip": ip_address})
                ).count()
                
                if recent_failures >= 5:
                    findings.append({
                        "agent_id": event.agent_id,
                        "timestamp": event.timestamp,
                        "finding_type": "brute_force_attack",
                        "title": f"Brute force attack detected from {ip_address}",
                        "description": f"Multiple failed login attempts ({recent_failures}) from IP {ip_address}",
                        "severity": 4,
                        "confidence": 90,
                        "data": {
                            "ip_address": ip_address,
                            "failed_attempts": recent_failures,
                            "time_window": "10 minutes"
                        },
                        "mitre_tactics": ["Credential Access"],
                        "mitre_techniques": ["T1110 - Brute Force"]
                    })
        
        # Rule 2: Suspicious port activity
        elif event.event_type == "port.snapshot":
            if "listening_ports" in event.payload:
                suspicious_ports = [21, 23, 135, 139, 445, 1433, 3389]
                exposed_ports = []
                
                for port_info in event.payload["listening_ports"]:
                    if port_info["port"] in suspicious_ports and port_info["address"] == "0.0.0.0":
                        exposed_ports.append(port_info["port"])
                
                if exposed_ports:
                    findings.append({
                        "agent_id": event.agent_id,
                        "timestamp": event.timestamp,
                        "finding_type": "suspicious_ports",
                        "title": f"Suspicious ports exposed: {', '.join(map(str, exposed_ports))}",
                        "description": f"High-risk ports are exposed on all interfaces",
                        "severity": 3,
                        "confidence": 80,
                        "data": {
                            "exposed_ports": exposed_ports,
                            "total_listening": len(event.payload["listening_ports"])
                        },
                        "mitre_tactics": ["Discovery"],
                        "mitre_techniques": ["T1046 - Network Service Scanning"]
                    })
        
        # Rule 3: Process anomalies
        elif event.event_type == "process.snapshot":
            if "processes" in event.payload:
                suspicious_processes = ["nc", "netcat", "ncat", "socat", "wget", "curl"]
                found_suspicious = []
                
                for proc in event.payload["processes"]:
                    if proc["name"].lower() in suspicious_processes:
                        found_suspicious.append(proc["name"])
                
                if found_suspicious:
                    findings.append({
                        "agent_id": event.agent_id,
                        "timestamp": event.timestamp,
                        "finding_type": "suspicious_processes",
                        "title": f"Suspicious processes detected: {', '.join(found_suspicious)}",
                        "description": "Potentially malicious processes are running",
                        "severity": 3,
                        "confidence": 70,
                        "data": {
                            "suspicious_processes": found_suspicious,
                            "total_processes": len(event.payload["processes"])
                        },
                        "mitre_tactics": ["Execution"],
                        "mitre_techniques": ["T1059 - Command and Scripting Interpreter"]
                    })
        
    except Exception as e:
        logger.error(f"Error analyzing event {event.id}: {e}")
    
    return findings

@celery_app.task(name="app.workers.worker.process_findings")
def process_findings(finding_ids: list):
    """Process findings and create alerts"""
    db = get_db()
    try:
        findings = db.query(Finding).filter(Finding.id.in_(finding_ids)).all()
        alerts_created = 0
        
        for finding in findings:
            # Create alert for high severity findings
            if finding.severity >= 3:
                alert = Alert(
                    finding_id=finding.id,
                    status="open",
                    priority=get_priority_from_severity(finding.severity)
                )
                db.add(alert)
                alerts_created += 1
        
        db.commit()
        logger.info(f"Processed {len(findings)} findings, created {alerts_created} alerts")
        
        return {"processed": len(findings), "alerts_created": alerts_created}
        
    except Exception as e:
        logger.error(f"Error processing findings: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def get_priority_from_severity(severity: int) -> str:
    """Convert severity to priority"""
    if severity >= 5:
        return "critical"
    elif severity >= 4:
        return "high"
    elif severity >= 3:
        return "medium"
    else:
        return "low"

@celery_app.task(name="app.workers.worker.evaluate_rules")
def evaluate_rules():
    """Evaluate custom rules against recent events"""
    db = get_db()
    try:
        # Get active rules
        rules = db.query(Rule).filter(Rule.enabled == True).all()
        
        # Get recent events (last hour)
        recent_events = db.query(Event).filter(
            Event.timestamp >= datetime.utcnow() - timedelta(hours=1)
        ).all()
        
        alerts_created = 0
        
        for rule in rules:
            # Simple rule evaluation (can be extended with more complex DSL)
            matching_events = evaluate_rule_conditions(rule, recent_events)
            
            if matching_events:
                # Create findings and alerts based on rule
                for event in matching_events:
                    finding = Finding(
                        agent_id=event.agent_id,
                        timestamp=event.timestamp,
                        finding_type=f"rule_{rule.name.lower().replace(' ', '_')}",
                        title=f"Rule triggered: {rule.name}",
                        description=rule.description or f"Custom rule {rule.name} was triggered",
                        severity=rule.severity,
                        confidence=95,
                        data={"rule_id": str(rule.id), "event_id": event.id}
                    )
                    db.add(finding)
                    db.flush()
                    
                    alert = Alert(
                        finding_id=finding.id,
                        rule_id=rule.id,
                        status="open",
                        priority=get_priority_from_severity(rule.severity)
                    )
                    db.add(alert)
                    alerts_created += 1
        
        db.commit()
        logger.info(f"Evaluated {len(rules)} rules, created {alerts_created} alerts")
        
        return {"rules_evaluated": len(rules), "alerts_created": alerts_created}
        
    except Exception as e:
        logger.error(f"Error evaluating rules: {e}")
        db.rollback()
        raise
    finally:
        db.close()

def evaluate_rule_conditions(rule: Rule, events: list) -> list:
    """Evaluate rule conditions against events"""
    matching_events = []
    
    try:
        conditions = rule.conditions
        
        # Simple threshold rule evaluation
        if rule.rule_type == "threshold":
            event_type = conditions.get("event_type")
            threshold = conditions.get("threshold", 1)
            window_minutes = conditions.get("window_minutes", 60)
            
            if event_type:
                # Count matching events in time window
                matching_count = sum(1 for event in events 
                                   if event.event_type == event_type and
                                   event.timestamp >= datetime.utcnow() - timedelta(minutes=window_minutes))
                
                if matching_count >= threshold:
                    matching_events = [event for event in events if event.event_type == event_type]
        
        # Pattern matching rule evaluation
        elif rule.rule_type == "pattern":
            pattern = conditions.get("pattern")
            field = conditions.get("field", "payload")
            
            if pattern:
                for event in events:
                    if field == "payload" and pattern in str(event.payload):
                        matching_events.append(event)
                    elif field == "event_type" and pattern in event.event_type:
                        matching_events.append(event)
        
    except Exception as e:
        logger.error(f"Error evaluating rule {rule.id}: {e}")
    
    return matching_events

# Periodic tasks
@celery_app.task(name="app.workers.worker.cleanup_old_events")
def cleanup_old_events():
    """Clean up old events and findings"""
    db = get_db()
    try:
        # Delete events older than 30 days
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        old_events = db.query(Event).filter(Event.timestamp < cutoff_date).count()
        db.query(Event).filter(Event.timestamp < cutoff_date).delete()
        
        old_findings = db.query(Finding).filter(Finding.timestamp < cutoff_date).count()
        db.query(Finding).filter(Finding.timestamp < cutoff_date).delete()
        
        db.commit()
        logger.info(f"Cleaned up {old_events} old events and {old_findings} old findings")
        
        return {"events_deleted": old_events, "findings_deleted": old_findings}
        
    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        db.rollback()
        raise
    finally:
        db.close()

# Configure periodic tasks
celery_app.conf.beat_schedule = {
    "evaluate-rules": {
        "task": "app.workers.worker.evaluate_rules",
        "schedule": 300.0,  # Every 5 minutes
    },
    "cleanup-old-events": {
        "task": "app.workers.worker.cleanup_old_events",
        "schedule": 86400.0,  # Every 24 hours
    },
}

if __name__ == "__main__":
    celery_app.start()
