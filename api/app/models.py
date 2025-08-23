#!/usr/bin/env python3

"""
CyberSentinel Pro - Database Models
SQLAlchemy models for the application
"""

from sqlalchemy import Column, String, Integer, DateTime, Boolean, Text, JSON, ForeignKey, BigInteger
from sqlalchemy.dialects.postgresql import UUID, INET
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
import uuid

Base = declarative_base()

class User(Base):
    """User accounts for web dashboard"""
    __tablename__ = "users"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default="viewer")  # admin, analyst, viewer
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    is_active = Column(Boolean, default=True)
    last_login = Column(DateTime(timezone=True))

class Agent(Base):
    """Endpoint agents"""
    __tablename__ = "agents"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False, index=True)
    hostname = Column(String(255))
    os_type = Column(String(50))  # linux, windows
    os_version = Column(String(255))
    ip_address = Column(INET)
    version = Column(String(50))
    last_seen = Column(DateTime(timezone=True))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    enabled = Column(Boolean, default=True)
    config = Column(JSON)
    
    # Relationships
    events = relationship("Event", back_populates="agent")
    findings = relationship("Finding", back_populates="agent")

class ApiKey(Base):
    """API keys for agent authentication"""
    __tablename__ = "api_keys"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    key_hash = Column(String(255), nullable=False, unique=True, index=True)
    name = Column(String(255), nullable=False)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"))
    role = Column(String(50), default="agent")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))
    is_active = Column(Boolean, default=True)
    last_used = Column(DateTime(timezone=True))

class Event(Base):
    """Raw events from agents (time-series)"""
    __tablename__ = "events"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    event_type = Column(String(100), nullable=False, index=True)
    severity = Column(Integer, default=1)  # 1=info, 2=low, 3=medium, 4=high, 5=critical
    source = Column(String(100))
    payload = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    agent = relationship("Agent", back_populates="events")

class Finding(Base):
    """Processed security findings"""
    __tablename__ = "findings"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, index=True)
    finding_type = Column(String(100), nullable=False, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text)
    severity = Column(Integer, nullable=False, index=True)
    confidence = Column(Integer, default=100)  # 0-100
    data = Column(JSON)
    mitre_tactics = Column(JSON)  # MITRE ATT&CK tactics
    mitre_techniques = Column(JSON)  # MITRE ATT&CK techniques
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    # Relationships
    agent = relationship("Agent", back_populates="findings")
    alerts = relationship("Alert", back_populates="finding")

class Alert(Base):
    """Security alerts generated from findings"""
    __tablename__ = "alerts"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    finding_id = Column(BigInteger, ForeignKey("findings.id"), nullable=False, index=True)
    rule_id = Column(UUID(as_uuid=True), ForeignKey("rules.id"), index=True)
    status = Column(String(20), default="open", index=True)  # open, acknowledged, closed, false_positive
    priority = Column(String(20), default="medium")  # low, medium, high, critical
    assigned_to = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    acknowledged_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    acknowledged_at = Column(DateTime(timezone=True))
    closed_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    closed_at = Column(DateTime(timezone=True))
    notes = Column(Text)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    finding = relationship("Finding", back_populates="alerts")
    rule = relationship("Rule", back_populates="alerts")

class Rule(Base):
    """Detection rules"""
    __tablename__ = "rules"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    rule_type = Column(String(50), nullable=False)  # threshold, pattern, anomaly
    conditions = Column(JSON, nullable=False)  # Rule DSL
    actions = Column(JSON)  # Actions to take when rule matches
    severity = Column(Integer, default=3)
    enabled = Column(Boolean, default=True)
    created_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    
    # Relationships
    alerts = relationship("Alert", back_populates="rule")

class Asset(Base):
    """Logical assets/hosts"""
    __tablename__ = "assets"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    hostname = Column(String(255), nullable=False, index=True)
    ip_address = Column(INET, index=True)
    asset_type = Column(String(50))  # server, workstation, network_device
    os_type = Column(String(50))
    os_version = Column(String(255))
    environment = Column(String(50))  # production, staging, development
    owner = Column(String(255))
    tags = Column(JSON)
    metadata = Column(JSON)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Baseline(Base):
    """File integrity baselines"""
    __tablename__ = "baselines"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    agent_id = Column(UUID(as_uuid=True), ForeignKey("agents.id"), nullable=False, index=True)
    file_path = Column(String(1000), nullable=False)
    sha256_hash = Column(String(64), nullable=False)
    file_size = Column(BigInteger)
    permissions = Column(String(10))
    owner = Column(String(100))
    group = Column(String(100))
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

class Report(Base):
    """Generated reports"""
    __tablename__ = "reports"
    
    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)  # security_summary, compliance, incident
    format = Column(String(10), default="pdf")  # pdf, html, json
    file_path = Column(String(1000))
    file_size = Column(BigInteger)
    parameters = Column(JSON)  # Report generation parameters
    generated_by = Column(UUID(as_uuid=True), ForeignKey("users.id"))
    generated_at = Column(DateTime(timezone=True), server_default=func.now())
    expires_at = Column(DateTime(timezone=True))

class AuditLog(Base):
    """Audit trail for user actions"""
    __tablename__ = "audit_logs"
    
    id = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), index=True)
    action = Column(String(100), nullable=False, index=True)
    resource_type = Column(String(50))
    resource_id = Column(String(100))
    details = Column(JSON)
    ip_address = Column(INET)
    user_agent = Column(String(500))
    timestamp = Column(DateTime(timezone=True), server_default=func.now(), index=True)
