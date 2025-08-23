#!/usr/bin/env python3

"""
CyberSentinel Pro - Events Routes
API endpoints for event management
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from ..database import get_db
from ..models import Event, User
from ..schemas import EventResponse
from ..auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[EventResponse])
async def get_events(
    event_type: Optional[str] = Query(None),
    severity: Optional[int] = Query(None, ge=1, le=5),
    limit: int = Query(100, le=1000),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get events with optional filtering"""
    query = db.query(Event)
    
    if event_type:
        query = query.filter(Event.event_type == event_type)
    
    if severity:
        query = query.filter(Event.severity == severity)
    
    events = query.order_by(Event.timestamp.desc()).offset(offset).limit(limit).all()
    
    return [EventResponse.from_orm(event) for event in events]
