"""WebSocket real-time event definitions and schemas for Phase 7.3."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class WebSocketEventType(str, Enum):
    """Standardized event types broadcast over WebSocket."""
    NEW_ALERT = "new_alert"
    TRAFFIC_UPDATE = "traffic_update"
    NEW_FLOW = "new_flow"
    ML_EVENT = "ml_event"
    FIREWALL_EVENT = "firewall_event"
    NOTIFICATION_EVENT = "notification_event"
    SYSTEM_STATUS = "system_status"


class WebSocketMessage(BaseModel):
    """Standardized contract for all outgoing WebSocket messages."""
    event: str = Field(description="Event name matching WebSocketEventType")
    timestamp: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(),
        description="ISO-8601 formatted event generation timestamp",
    )
    data: Dict[str, Any] = Field(default_factory=dict, description="Structured event payload")
