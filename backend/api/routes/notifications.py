"""Notification status REST API endpoint (excluding all secrets)."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends

from backend.api.dependencies import get_notification_manager
from backend.api.schemas.rest_schemas import NotificationStatusResponse
from backend.services.notification.notification_manager import NotificationManager

logger = logging.getLogger("dpi_ids_ips.backend.routes.notifications")

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get("/status", response_model=NotificationStatusResponse)
def get_notification_status(
    notification_mgr: NotificationManager = Depends(get_notification_manager),
) -> NotificationStatusResponse:
    """
    Returns notification subsystem metrics and health.
    Strictly excludes SMTP credentials, usernames, and passwords.
    """
    stats = notification_mgr.get_stats()
    worker_stats = stats.get("worker", {})

    # Check smtp status safely without exposing host or pass
    smtp_configured = bool(
        notification_mgr.config.smtp_host and notification_mgr.config.smtp_port > 0
    )

    total_suppressed = stats.get("total_suppressed_cooldown", 0) + stats.get("total_suppressed_unqualified", 0)
    queue_cap = getattr(notification_mgr.config, "max_queue_size", 500)

    return NotificationStatusResponse(
        enabled=stats.get("email_enabled", False),
        smtp_status="configured" if smtp_configured else "not_configured",
        recipients_count=len(stats.get("recipients", [])),
        cooldown_seconds=stats.get("cooldown_seconds", 300.0),
        queue_depth=worker_stats.get("queue_depth", 0),
        queue_capacity=queue_cap,
        emails_submitted=worker_stats.get("total_enqueued", 0),
        emails_delivered=worker_stats.get("total_delivered", 0),
        emails_failed=worker_stats.get("total_failed", 0),
        emails_suppressed=total_suppressed,
        queue_full_drops=worker_stats.get("total_dropped", 0),
    )
