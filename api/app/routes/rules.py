#!/usr/bin/env python3

"""
CyberSentinel Pro - Rules Routes
API endpoints for detection rule management
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import Rule, User
from ..schemas import RuleResponse
from ..auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[RuleResponse])
async def get_rules(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all detection rules"""
    rules = db.query(Rule).order_by(Rule.created_at.desc()).all()
    return [RuleResponse.from_orm(rule) for rule in rules]
