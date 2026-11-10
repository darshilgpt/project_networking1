"""Firewall and IPS rule management REST API endpoints."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends, HTTPException, status

from backend.api.dependencies import get_firewall_service, get_ws_manager, verify_admin_key
from backend.api.schemas.rest_schemas import (
    FirewallBlockRequest,
    FirewallOperationResponse,
    FirewallRuleItem,
    FirewallRulesListResponse,
)
from backend.api.websocket.events import WebSocketEventType
from backend.api.websocket.manager import WebSocketConnectionManager
from backend.services.firewall_service import FirewallService

logger = logging.getLogger("dpi_ids_ips.backend.routes.firewall")

router = APIRouter(prefix="/firewall", tags=["Firewall"])


@router.get("/rules", response_model=FirewallRulesListResponse)
def list_firewall_rules(
    firewall_service: FirewallService = Depends(get_firewall_service),
) -> FirewallRulesListResponse:
    """
    Returns list of active dynamic and firewall block rules.
    """
    res = firewall_service.list_active_rules()
    rules = [FirewallRuleItem(**r) for r in res.get("rules", [])]

    return FirewallRulesListResponse(
        active_prevention_enabled=res.get("active_prevention_enabled", False),
        enforcement_mechanism=res.get("enforcement_mechanism", "None"),
        total_active_rules=res.get("total_active_rules", len(rules)),
        rules=rules,
    )


@router.post("/block", response_model=FirewallOperationResponse)
def block_ip(
    req: FirewallBlockRequest,
    firewall_service: FirewallService = Depends(get_firewall_service),
    ws_mgr: Optional[WebSocketConnectionManager] = None,
    authorized: bool = Depends(verify_admin_key),
) -> FirewallOperationResponse:
    """
    Adds a temporary or dynamic block for the specified IP address.
    Requires administrative API key authorization (X-API-Key or Authorization: Bearer).
    """
    manager = ws_mgr if isinstance(ws_mgr, WebSocketConnectionManager) else get_ws_manager()
    result = firewall_service.block_ip(
        ip_address=req.ip_address,
        duration_seconds=req.duration_seconds or 300.0,
        reason=req.reason or "Manual Administrator Block",
    )

    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.get("message", "Failed to block IP."),
        )

    # Broadcast real-time firewall_event to connected WebSocket clients
    manager.publish_event_threadsafe(
        event_type=WebSocketEventType.FIREWALL_EVENT,
        data={
            "operation": "BLOCK",
            "ip_address": req.ip_address,
            "duration_seconds": req.duration_seconds or 300.0,
            "effective_mode": result.get("effective_mode", "SIMULATION"),
            "reason": req.reason or "Manual Administrator Block",
            "rule_id": result.get("rule_id"),
        },
    )

    return FirewallOperationResponse(**result)


@router.delete("/block/{rule_id}", response_model=FirewallOperationResponse)
def unblock_ip_or_rule(
    rule_id: str,
    firewall_service: FirewallService = Depends(get_firewall_service),
    ws_mgr: Optional[WebSocketConnectionManager] = None,
    authorized: bool = Depends(verify_admin_key),
) -> FirewallOperationResponse:
    """
    Removes an active block rule by IP or Rule ID.
    Requires administrative API key authorization (X-API-Key or Authorization: Bearer).
    """
    manager = ws_mgr if isinstance(ws_mgr, WebSocketConnectionManager) else get_ws_manager()
    clean_ip = rule_id.replace("DYN_", "").replace("WFW_", "").strip()
    result = firewall_service.unblock_ip(clean_ip)

    if not result.get("success", False):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=result.get("message", f"Rule or IP '{rule_id}' not found."),
        )

    # Broadcast real-time firewall_event to connected WebSocket clients
    manager.publish_event_threadsafe(
        event_type=WebSocketEventType.FIREWALL_EVENT,
        data={
            "operation": "UNBLOCK",
            "ip_address": clean_ip,
            "effective_mode": result.get("effective_mode", "SIMULATION"),
            "rule_id": result.get("rule_id"),
        },
    )

    return FirewallOperationResponse(**result)
