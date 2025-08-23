#!/usr/bin/env python3

"""
CyberSentinel Pro - Pydantic Schemas
Request/response models for API validation
"""

from pydantic import BaseModel, Field, validator
from typing import Optional, Dict, List, Any
from datetime import datetime
from uuid import UUID
import ipaddress

# Base schemas
class BaseSchema(BaseModel):
    class Config:
        orm_mode = True

# Authentication schemas
class UserLogin(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")

class UserCreate(BaseModel):
    email: str = Field(..., description="User email address")
    password: str = Field(..., min_length=8, description="User password")
    role: str = Field(default="viewer", description="User role")

class UserResponse(BaseSchema):
    id: UUID
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime]

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse

# Agent schemas
class HeartbeatData(BaseModel):
    agent_id: UUID
    hostname: str
    os_type: str
    os_version: str
    ip_address: str
    version: str
    config: Optional[Dict[str, Any]] = None
    
    @validator('ip_address')
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError('Invalid IP address')

class AgentResponse(BaseSchema):
    id: UUID
    name: str
    hostname: Optional[str]
    os_type: Optional[str]
    os_version: Optional[str]
    ip_address: Optional[str]
    version: Optional[str]
    last_seen: Optional[datetime]
    created_at: datetime
    enabled: bool

# Event schemas
class EventCreate(BaseModel):
    agent_id: UUID
    timestamp: datetime
    event_type: str = Field(..., description="Type of event (e.g., auth.fail, port.scan)")
    severity: int = Field(default=1, ge=1, le=5, description="Severity level 1-5")
    source: Optional[str] = Field(None, description="Source of the event")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Event data")

class EventResponse(BaseSchema):
    id: int
    agent_id: UUID
    timestamp: datetime
    event_type: str
    severity: int
    source: Optional[str]
    payload: Dict[str, Any]
    created_at: datetime

# Finding schemas
class FindingCreate(BaseModel):
    agent_id: UUID
    timestamp: datetime
    finding_type: str = Field(..., description="Type of finding")
    title: str = Field(..., max_length=500, description="Finding title")
    description: Optional[str] = Field(None, description="Detailed description")
    severity: int = Field(..., ge=1, le=5, description="Severity level 1-5")
    confidence: int = Field(default=100, ge=0, le=100, description="Confidence level 0-100")
    data: Dict[str, Any] = Field(default_factory=dict, description="Finding data")
    mitre_tactics: Optional[List[str]] = Field(None, description="MITRE ATT&CK tactics")
    mitre_techniques: Optional[List[str]] = Field(None, description="MITRE ATT&CK techniques")

class FindingResponse(BaseSchema):
    id: int
    agent_id: UUID
    timestamp: datetime
    finding_type: str
    title: str
    description: Optional[str]
    severity: int
    confidence: int
    data: Dict[str, Any]
    mitre_tactics: Optional[List[str]]
    mitre_techniques: Optional[List[str]]
    created_at: datetime

# Alert schemas
class AlertCreate(BaseModel):
    finding_id: int
    rule_id: Optional[UUID] = None
    priority: str = Field(default="medium", description="Alert priority")
    notes: Optional[str] = None

class AlertUpdate(BaseModel):
    status: Optional[str] = Field(None, regex="^(open|acknowledged|closed|false_positive)$")
    priority: Optional[str] = Field(None, regex="^(low|medium|high|critical)$")
    assigned_to: Optional[UUID] = None
    notes: Optional[str] = None

class AlertResponse(BaseSchema):
    id: int
    finding_id: int
    rule_id: Optional[UUID]
    status: str
    priority: str
    assigned_to: Optional[UUID]
    acknowledged_by: Optional[UUID]
    acknowledged_at: Optional[datetime]
    closed_by: Optional[UUID]
    closed_at: Optional[datetime]
    notes: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]
    finding: FindingResponse

# Rule schemas
class RuleCreate(BaseModel):
    name: str = Field(..., max_length=255, description="Rule name")
    description: Optional[str] = Field(None, description="Rule description")
    rule_type: str = Field(..., description="Rule type (threshold, pattern, anomaly)")
    conditions: Dict[str, Any] = Field(..., description="Rule conditions (DSL)")
    actions: Optional[Dict[str, Any]] = Field(None, description="Actions to take")
    severity: int = Field(default=3, ge=1, le=5, description="Rule severity")
    enabled: bool = Field(default=True, description="Rule enabled status")

class RuleUpdate(BaseModel):
    name: Optional[str] = Field(None, max_length=255)
    description: Optional[str] = None
    rule_type: Optional[str] = None
    conditions: Optional[Dict[str, Any]] = None
    actions: Optional[Dict[str, Any]] = None
    severity: Optional[int] = Field(None, ge=1, le=5)
    enabled: Optional[bool] = None

class RuleResponse(BaseSchema):
    id: UUID
    name: str
    description: Optional[str]
    rule_type: str
    conditions: Dict[str, Any]
    actions: Optional[Dict[str, Any]]
    severity: int
    enabled: bool
    created_by: Optional[UUID]
    created_at: datetime
    updated_at: Optional[datetime]

# Report schemas
class ReportCreate(BaseModel):
    name: str = Field(..., max_length=255, description="Report name")
    report_type: str = Field(..., description="Report type")
    format: str = Field(default="pdf", regex="^(pdf|html|json)$")
    parameters: Optional[Dict[str, Any]] = Field(None, description="Report parameters")

class ReportResponse(BaseSchema):
    id: UUID
    name: str
    report_type: str
    format: str
    file_path: Optional[str]
    file_size: Optional[int]
    parameters: Optional[Dict[str, Any]]
    generated_by: Optional[UUID]
    generated_at: datetime
    expires_at: Optional[datetime]

# API Key schemas
class ApiKeyCreate(BaseModel):
    name: str = Field(..., max_length=255, description="API key name")
    agent_id: Optional[UUID] = Field(None, description="Associated agent ID")
    expires_at: Optional[datetime] = Field(None, description="Expiration date")

class ApiKeyResponse(BaseSchema):
    id: UUID
    name: str
    agent_id: Optional[UUID]
    role: str
    created_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    last_used: Optional[datetime]
    # Note: Never return the actual key or hash

# Dashboard schemas
class DashboardStats(BaseModel):
    total_agents: int
    active_agents: int
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    events_last_24h: int
    findings_last_24h: int

class AlertSummary(BaseModel):
    severity_breakdown: Dict[str, int]
    status_breakdown: Dict[str, int]
    recent_alerts: List[AlertResponse]

class AgentStatus(BaseModel):
    agent_id: UUID
    hostname: str
    status: str  # online, offline, warning
    last_seen: Optional[datetime]
    events_count: int
    findings_count: int

# Search and filter schemas
class EventFilter(BaseModel):
    agent_id: Optional[UUID] = None
    event_type: Optional[str] = None
    severity: Optional[int] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=100, le=1000)
    offset: int = Field(default=0, ge=0)

class AlertFilter(BaseModel):
    status: Optional[str] = None
    priority: Optional[str] = None
    assigned_to: Optional[UUID] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    limit: int = Field(default=50, le=500)
    offset: int = Field(default=0, ge=0)
