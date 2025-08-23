#!/usr/bin/env python3

"""
CyberSentinel Pro - FastAPI Backend
Main application entry point
Author: CyberSentinel Team
Version: 2.0
"""

from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.security import HTTPBearer
from contextlib import asynccontextmanager
import uvicorn
import os
from datetime import datetime

from .routes import ingest, alerts, events, agents, rules, reports, auth
from .database import engine, Base
from .auth import get_current_user
from .config import settings

# Security
security = HTTPBearer()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan events"""
    # Startup
    print("🚀 CyberSentinel Pro API starting up...")
    
    # Create database tables
    Base.metadata.create_all(bind=engine)
    print("📊 Database tables created")
    
    yield
    
    # Shutdown
    print("🛑 CyberSentinel Pro API shutting down...")

# Create FastAPI app
app = FastAPI(
    title="CyberSentinel Pro API",
    description="Production-grade cybersecurity monitoring platform",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Security middleware
app.add_middleware(
    TrustedHostMiddleware,
    allowed_hosts=settings.ALLOWED_HOSTS
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH"],
    allow_headers=["*"],
)

# Health check endpoint
@app.get("/health", tags=["System"])
async def health_check():
    """System health check endpoint"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "2.0.0",
        "service": "CyberSentinel Pro API"
    }

# Root endpoint
@app.get("/", tags=["System"])
async def root():
    """API root endpoint"""
    return {
        "message": "CyberSentinel Pro API",
        "version": "2.0.0",
        "docs": "/docs",
        "health": "/health"
    }

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["Authentication"])
app.include_router(ingest.router, prefix="/ingest", tags=["Ingestion"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(events.router, prefix="/api/events", tags=["Events"])
app.include_router(agents.router, prefix="/api/agents", tags=["Agents"])
app.include_router(rules.router, prefix="/api/rules", tags=["Rules"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])

# Protected endpoint example
@app.get("/api/profile", tags=["User"])
async def get_profile(current_user = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "role": current_user.role,
        "created_at": current_user.created_at
    }

if __name__ == "__main__":
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.DEBUG,
        log_level="info"
    )
