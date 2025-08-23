#!/usr/bin/env python3

"""
CyberSentinel Pro - Alerts Routes
API endpoints for alert management
"""

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime

from ..database import get_db
from ..models import Alert, Finding, User
from ..schemas import AlertResponse, AlertUpdate, AlertFilter
from ..auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[AlertResponse])
async def get_alerts(
    status_filter: Optional[str] = Query(None, alias="status"),
    priority: Optional[str] = Query(None),
    limit: int = Query(50, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get alerts with optional filtering"""
    query = db.query(Alert).join(Finding)
    
    if status_filter:
        query = query.filter(Alert.status == status_filter)
    
    if priority:
        query = query.filter(Alert.priority == priority)
    
    alerts = query.order_by(Alert.created_at.desc()).offset(offset).limit(limit).all()
    
    return [AlertResponse.from_orm(alert) for alert in alerts]

@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: int,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get specific alert by ID"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    return AlertResponse.from_orm(alert)

@router.patch("/{alert_id}", response_model=AlertResponse)
async def update_alert(
    alert_id: int,
    alert_update: AlertUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Update alert status and properties"""
    alert = db.query(Alert).filter(Alert.id == alert_id).first()
    
    if not alert:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found"
        )
    
    # Update fields
    update_data = alert_update.dict(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(alert, field, value)
    
    # Handle status changes
    if alert_update.status == "acknowledged" and alert.status != "acknowledged":
        alert.acknowledged_by = current_user.id
        alert.acknowledged_at = datetime.utcnow()
    elif alert_update.status == "closed" and alert.status != "closed":
        alert.closed_by = current_user.id
        alert.closed_at = datetime.utcnow()
    
    alert.updated_at = datetime.utcnow()
    
    db.commit()
    db.refresh(alert)
    
    return AlertResponse.from_orm(alert)
