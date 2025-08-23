#!/usr/bin/env python3

"""
CyberSentinel Pro - Agents Routes
API endpoints for agent management
"""

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import Agent, User
from ..schemas import AgentResponse
from ..auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[AgentResponse])
async def get_agents(
    limit: int = Query(100, le=500),
    offset: int = Query(0, ge=0),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all agents"""
    agents = db.query(Agent).order_by(Agent.last_seen.desc()).offset(offset).limit(limit).all()
    return [AgentResponse.from_orm(agent) for agent in agents]
