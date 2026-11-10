"""Flows REST API endpoints."""

from __future__ import annotations

import logging
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from backend.api.dependencies import get_flow_service
from backend.api.schemas.rest_schemas import FlowItem, FlowListResponse, PaginationMeta
from backend.services.flow_service import FlowService

logger = logging.getLogger("dpi_ids_ips.backend.routes.flows")

router = APIRouter(prefix="/flows", tags=["Flows"])


@router.get("", response_model=FlowListResponse)
def list_flows(
    limit: int = Query(default=50, ge=1, le=500, description="Page limit"),
    offset: int = Query(default=0, ge=0, description="Offset index"),
    protocol: Optional[str] = Query(default=None, description="Filter by protocol (TCP, UDP, ICMP)"),
    source_ip: Optional[str] = Query(default=None, description="Filter by source IP"),
    destination_ip: Optional[str] = Query(default=None, description="Filter by destination IP"),
    is_active: Optional[bool] = Query(default=None, description="Filter by active status"),
    flow_service: FlowService = Depends(get_flow_service),
) -> FlowListResponse:
    """
    Returns a paginated list of network connection flows across all active clients.
    """
    flows, total = flow_service.get_flows(
        limit=limit,
        offset=offset,
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        is_active=is_active,
    )

    flow_items = [FlowItem(**f) for f in flows]
    pagination = PaginationMeta(
        total=total,
        limit=limit,
        offset=offset,
        returned=len(flow_items),
    )

    return FlowListResponse(flows=flow_items, pagination=pagination)


@router.get("/{flow_id}", response_model=FlowItem)
def get_flow_by_id(
    flow_id: int,
    flow_service: FlowService = Depends(get_flow_service),
) -> FlowItem:
    """
    Retrieves flow details for a specific flow ID.
    Returns 404 if not found.
    """
    flow_data = flow_service.get_flow_by_id(flow_id)
    if not flow_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Flow with ID {flow_id} not found.",
        )
    return FlowItem(**flow_data)

