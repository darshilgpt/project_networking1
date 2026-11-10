"""Pydantic schemas for health checks and status responses."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SubsystemStatus(BaseModel):
    """Status details for an individual component."""
    status: str
    operational: bool
    details: Optional[Dict[str, Any]] = None


class HealthResponse(BaseModel):
    """Contract for GET /api/v1/health."""
    api_status: str = Field(default="operational", description="FastAPI service status")
    version: str = Field(default="1.0.0", description="Backend application version")
    dpi_pipeline: SubsystemStatus = Field(description="DPI/IDS pipeline status")
    ml_runtime: SubsystemStatus = Field(description="Machine Learning runtime engine status")
    email_notification: SubsystemStatus = Field(description="Security email notification subsystem status")

