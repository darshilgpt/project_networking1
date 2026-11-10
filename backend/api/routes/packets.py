"""Packets REST API endpoints (strictly bounded metadata, no raw payload exposure)."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, Query

from backend.api.dependencies import get_traffic_service
from backend.api.schemas.rest_schemas import PacketItem, PacketListResponse, PaginationMeta
from backend.services.traffic_service import TrafficService

logger = logging.getLogger("dpi_ids_ips.backend.routes.packets")

router = APIRouter(prefix="/packets", tags=["Packets"])


@router.get("", response_model=PacketListResponse)
def list_recent_packets(
    limit: int = Query(default=50, ge=1, le=100, description="Page limit (max 100)"),
    offset: int = Query(default=0, ge=0, description="Offset index"),
    traffic_service: TrafficService = Depends(get_traffic_service),
) -> PacketListResponse:
    """
    Returns bounded packet metadata from recent inspections.
    Strictly excludes raw packet payload bytes for privacy and security.
    """
    packets, total = traffic_service.get_recent_packets(limit=limit, offset=offset)

    packet_items = [PacketItem(**p) for p in packets]
    pagination = PaginationMeta(
        total=total,
        limit=limit,
        offset=offset,
        returned=len(packet_items),
    )

    return PacketListResponse(packets=packet_items, pagination=pagination)

