#!/usr/bin/env python3

"""
CyberSentinel Pro - Reports Routes
API endpoints for report management
"""

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from typing import List

from ..database import get_db
from ..models import Report, User
from ..schemas import ReportResponse
from ..auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[ReportResponse])
async def get_reports(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get all reports"""
    reports = db.query(Report).order_by(Report.generated_at.desc()).all()
    return [ReportResponse.from_orm(report) for report in reports]
