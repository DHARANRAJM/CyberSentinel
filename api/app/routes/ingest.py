#!/usr/bin/env python3

"""
CyberSentinel Pro - Ingestion Routes
API endpoints for agent data ingestion
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.orm import Session
from typing import List
from datetime import datetime
import logging

from ..database import get_db
from ..models import Agent, Event, Finding, ApiKey
from ..schemas import EventCreate, FindingCreate, HeartbeatData
from ..auth import authenticate_agent

logger = logging.getLogger(__name__)
router = APIRouter()

@router.post("/events", status_code=status.HTTP_201_CREATED)
async def ingest_events(
    events: List[EventCreate],
    request: Request,
    api_key: ApiKey = Depends(authenticate_agent),
    db: Session = Depends(get_db)
):
    """
    Ingest security events from agents
    """
    try:
        created_events = []
        
        for event_data in events:
            # Create event record
            event = Event(
                agent_id=event_data.agent_id,
                timestamp=event_data.timestamp,
                event_type=event_data.event_type,
                severity=event_data.severity,
                source=event_data.source,
                payload=event_data.payload
            )
            
            db.add(event)
            created_events.append(event)
        
        db.commit()
        
        logger.info(f"Ingested {len(created_events)} events from agent {api_key.agent_id}")
        
        return {
            "status": "success",
            "accepted": len(created_events),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error ingesting events: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest events"
        )

@router.post("/findings", status_code=status.HTTP_201_CREATED)
async def ingest_findings(
    findings: List[FindingCreate],
    request: Request,
    api_key: ApiKey = Depends(authenticate_agent),
    db: Session = Depends(get_db)
):
    """
    Ingest security findings from agents
    """
    try:
        created_findings = []
        
        for finding_data in findings:
            # Create finding record
            finding = Finding(
                agent_id=finding_data.agent_id,
                timestamp=finding_data.timestamp,
                finding_type=finding_data.finding_type,
                title=finding_data.title,
                description=finding_data.description,
                severity=finding_data.severity,
                confidence=finding_data.confidence,
                data=finding_data.data,
                mitre_tactics=finding_data.mitre_tactics,
                mitre_techniques=finding_data.mitre_techniques
            )
            
            db.add(finding)
            created_findings.append(finding)
        
        db.commit()
        
        logger.info(f"Ingested {len(created_findings)} findings from agent {api_key.agent_id}")
        
        # TODO: Trigger rule engine to process findings
        
        return {
            "status": "success",
            "accepted": len(created_findings),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error ingesting findings: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to ingest findings"
        )

@router.post("/heartbeat", status_code=status.HTTP_200_OK)
async def agent_heartbeat(
    heartbeat: HeartbeatData,
    request: Request,
    api_key: ApiKey = Depends(authenticate_agent),
    db: Session = Depends(get_db)
):
    """
    Agent heartbeat endpoint
    """
    try:
        # Update agent last seen timestamp
        agent = db.query(Agent).filter(Agent.id == heartbeat.agent_id).first()
        
        if not agent:
            # Create new agent if it doesn't exist
            agent = Agent(
                id=heartbeat.agent_id,
                name=heartbeat.hostname,
                hostname=heartbeat.hostname,
                os_type=heartbeat.os_type,
                os_version=heartbeat.os_version,
                ip_address=heartbeat.ip_address,
                version=heartbeat.version,
                last_seen=datetime.utcnow(),
                config=heartbeat.config
            )
            db.add(agent)
        else:
            # Update existing agent
            agent.last_seen = datetime.utcnow()
            agent.hostname = heartbeat.hostname
            agent.os_type = heartbeat.os_type
            agent.os_version = heartbeat.os_version
            agent.ip_address = heartbeat.ip_address
            agent.version = heartbeat.version
            agent.config = heartbeat.config
        
        db.commit()
        
        return {
            "status": "success",
            "agent_id": str(agent.id),
            "timestamp": datetime.utcnow().isoformat(),
            "config_updated": False  # TODO: Implement config updates
        }
        
    except Exception as e:
        logger.error(f"Error processing heartbeat: {e}")
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to process heartbeat"
        )
