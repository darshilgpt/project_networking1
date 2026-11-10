"""Alerts REST API endpoints."""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import get_alert_service
from backend.api.schemas.rest_schemas import AlertItem, AlertListResponse, PaginationMeta
from backend.services.alert_service import AlertService

logger = logging.getLogger("dpi_ids_ips.backend.routes.alerts")

router = APIRouter(prefix="/alerts", tags=["Alerts"])


@router.get("", response_model=AlertListResponse)
def list_alerts(
    limit: int = Query(default=50, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset index"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    category: Optional[str] = Query(default=None, description="Filter by category (e.g. PORT_SCAN, SQLI, XSS)"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP address"),
    date_from: Optional[float] = Query(default=None, description="Filter from timestamp"),
    date_to: Optional[float] = Query(default=None, description="Filter to timestamp"),
    alert_service: AlertService = Depends(get_alert_service),
) -> AlertListResponse:
    """
    Returns a paginated list of security alerts with filtering.
    """
    alerts, total = alert_service.get_alerts(
        limit=limit,
        offset=offset,
        severity=severity,
        category=category,
        source_ip=source_ip,
        date_from=date_from,
        date_to=date_to,
    )

    alert_items = [AlertItem(**a) for a in alerts]
    pagination = PaginationMeta(
        total=total,
        limit=limit,
        offset=offset,
        returned=len(alert_items),
    )

    return AlertListResponse(alerts=alert_items, pagination=pagination)


@router.get("/{alert_id}", response_model=AlertItem)
def get_alert_by_id(
    alert_id: int,
    alert_service: AlertService = Depends(get_alert_service),
) -> AlertItem:
    """
    Retrieves detailed information for a specific alert by its ID.
    Returns 404 if not found.
    """
    alert_data = alert_service.get_alert_by_id(alert_id)
    if not alert_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Alert with ID {alert_id} not found in recent alerts.",
        )
    return AlertItem(**alert_data)

