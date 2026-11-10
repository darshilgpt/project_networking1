"""WebSocket router providing real-time events at /ws/monitor."""

from __future__ import annotations

import asyncio
import logging
import os
import secrets
from typing import Optional
from fastapi import APIRouter, Query, WebSocket, WebSocketDisconnect, status

from backend.api.dependencies import get_pipeline_adapter, get_service_container
from backend.api.websocket.events import WebSocketEventType, WebSocketMessage
from backend.api.websocket.manager import ws_manager

logger = logging.getLogger("dpi_ids_ips.backend.websocket.router")

router = APIRouter(tags=["WebSocket"])


def _authenticate_ws(token: Optional[str]) -> bool:
    """
    Validates token query parameter, Authorization header, or WebSocket subprotocol.
    Accepts ADMIN_API_KEY, DASHBOARD_WS_TOKEN, or defaults to valid during local dev if unset.
    """
    expected_token = os.getenv("DASHBOARD_WS_TOKEN", os.getenv("ADMIN_API_KEY", "dpi-admin-secret-key")).strip()
    allow_dev_no_auth = os.getenv("WS_ALLOW_ANONYMOUS_DEV", "false").lower() in ("true", "1", "yes")

    if not expected_token and allow_dev_no_auth:
        return True

    if not token or not secrets.compare_digest(token.strip(), expected_token):
        return False
    return True


@router.websocket("/ws/monitor")
async def websocket_monitor_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(default=None),
) -> None:
    """
    WebSocket endpoint streaming real-time security events, traffic metrics,
    alerts, ML detections, and firewall operations.

    Authentication is resolved with priority:
    1. WebSocket Subprotocol: `Sec-WebSocket-Protocol` header (dpi-auth, <token>)
    2. Authorization Header: `Authorization: Bearer <token>`
    3. Query parameter: `?token=<token>` (backward-compatible fallback for CLI/curl clients)
    """
    auth_token = None
    subprotocol_to_accept: Optional[str] = None

    # Check WebSocket subprotocol first (preferred secure mechanism for browser clients)
    ws_protocols = websocket.headers.get("sec-websocket-protocol", "")
    if ws_protocols:
        # Protocols can be comma-separated list, e.g. "dpi-auth, dpi-admin-secret-key"
        parts = [p.strip() for p in ws_protocols.split(",") if p.strip()]
        if len(parts) >= 2 and parts[0] == "dpi-auth":
            auth_token = parts[1]
            subprotocol_to_accept = "dpi-auth"
        elif len(parts) == 1 and parts[0] != "dpi-auth":
            auth_token = parts[0]

    # Check Authorization header next
    if not auth_token:
        auth_header = websocket.headers.get("authorization")
        if auth_header and auth_header.lower().startswith("bearer "):
            auth_token = auth_header.split(" ", 1)[1].strip()

    # Fallback to query parameter (backward compatibility)
    if not auth_token and token:
        auth_token = token.strip()

    if not _authenticate_ws(auth_token):
        logger.warning(f"Rejecting unauthorized WebSocket connection from {websocket.client}")
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION, reason="Unauthorized")
        return

    # Accept connection with negotiated subprotocol and register client
    client = await ws_manager.connect(websocket, subprotocol=subprotocol_to_accept)

    # Immediately push initial system_status event upon connection
    container = get_service_container()
    pipeline_stats = container.pipeline_adapter.get_pipeline_stats()
    ml_status = container.pipeline_adapter.get_ml_status()
    notif_stats = container.notification_manager.get_stats()

    init_msg = WebSocketMessage(
        event=WebSocketEventType.SYSTEM_STATUS.value,
        data={
            "api_status": "operational",
            "pipeline_status": pipeline_stats.get("status", "uninitialized"),
            "ml_status": ml_status.get("status", "uninitialized"),
            "notification_status": "operational" if notif_stats.get("email_enabled") else "disabled",
            "active_clients": len(ws_manager._clients),
        },
    )
    try:
        await client.queue.put(init_msg.model_dump())
    except Exception:
        pass

    try:
        # Keep client connection alive and process incoming messages (e.g. ping/heartbeat)
        while True:
            data = await websocket.receive_text()
            # Handle client-side ping or keep-alive message
            if data.strip().lower() in ("ping", '{"type":"ping"}', '{"event":"ping"}'):
                pong_msg = WebSocketMessage(
                    event="pong",
                    data={"client_time": data.strip()},
                )
                try:
                    await client.queue.put(pong_msg.model_dump())
                except Exception:
                    pass
    except WebSocketDisconnect:
        logger.info(f"WebSocket client disconnected normally: {websocket.client}")
    except Exception as e:
        logger.debug(f"WebSocket client exception: {e}")
    finally:
        await ws_manager.disconnect(client)

