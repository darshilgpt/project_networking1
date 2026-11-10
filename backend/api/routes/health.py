"""Health check route exposing backend, DPI pipeline, ML, and notification service status."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from backend.api.dependencies import get_notification_manager, get_pipeline_adapter
from backend.api.schemas.health_schema import HealthResponse, SubsystemStatus
from backend.integrations.pipeline_adapter import PipelineAdapter
from backend.services.notification.notification_manager import NotificationManager

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=HealthResponse)
def check_health(
    pipeline_adapter: PipelineAdapter = Depends(get_pipeline_adapter),
    notification_mgr: NotificationManager = Depends(get_notification_manager),
) -> HealthResponse:
    """
    Returns system operational status.
    Accurately reflects whether DPI pipeline, ML, and Email services are active,
    disabled, or uninitialized without masking status.
    """
    # 1. Pipeline status
    pipe_stats = pipeline_adapter.get_pipeline_stats()
    pipe_op = pipe_stats.get("status") == "active"
    pipe_status = SubsystemStatus(
        status=pipe_stats.get("status", "uninitialized"),
        operational=pipe_op,
        details={
            "total_processed": pipe_stats.get("total_processed", 0),
            "total_alerts": pipe_stats.get("total_alerts", 0),
            "active_workers": pipe_stats.get("active_workers", 0),
        } if pipe_op else None,
    )

    # 2. ML runtime status
    ml_info = pipeline_adapter.get_ml_status()
    ml_op = ml_info.get("status") == "operational"
    ml_status = SubsystemStatus(
        status=ml_info.get("status", "uninitialized"),
        operational=ml_op,
        details={
            "enabled": ml_info.get("enabled", False),
            "rf_loaded": ml_info.get("rf_loaded", False),
            "if_loaded": ml_info.get("if_loaded", False),
            "queue_depth": ml_info.get("queue_depth", 0),
        } if ml_info.get("status") != "uninitialized" else None,
    )

    # 3. Email notification status
    notif_stats = notification_mgr.get_stats()
    email_enabled = notif_stats.get("email_enabled", False)
    email_op = email_enabled and notif_stats.get("worker", {}).get("is_running", False)
    email_status = SubsystemStatus(
        status="operational" if email_op else ("disabled" if not email_enabled else "degraded"),
        operational=email_op,
        details={
            "enabled": email_enabled,
            "recipients_count": len(notif_stats.get("recipients", [])),
            "cooldown_seconds": notif_stats.get("cooldown_seconds", 300),
            "total_enqueued": notif_stats.get("worker", {}).get("total_enqueued", 0),
            "total_delivered": notif_stats.get("worker", {}).get("total_delivered", 0),
            "total_failed": notif_stats.get("worker", {}).get("total_failed", 0),
        },
    )

    return HealthResponse(
        api_status="operational",
        version="1.0.0",
        dpi_pipeline=pipe_status,
        ml_runtime=ml_status,
        email_notification=email_status,
    )

