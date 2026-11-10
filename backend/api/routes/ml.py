"""Machine Learning telemetry and runtime status REST API endpoints."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends

from backend.api.dependencies import get_ml_service
from backend.api.schemas.rest_schemas import MLMetricsResponse, MLStatusResponse
from backend.services.ml_service import MLService

logger = logging.getLogger("dpi_ids_ips.backend.routes.ml")

router = APIRouter(prefix="/ml", tags=["Machine Learning"])


def _extract_metrics_model(metrics_data: dict) -> MLMetricsResponse:
    """Safely extracts MLMetricsResponse with zero-defaults if metrics are empty."""
    return MLMetricsResponse(
        jobs_submitted=metrics_data.get("jobs_submitted", 0),
        jobs_processed=metrics_data.get("jobs_processed", 0),
        queue_drops=metrics_data.get("queue_drops", 0),
        inference_failures=metrics_data.get("inference_failures", 0),
        rf_classifications=metrics_data.get("rf_classifications", 0),
        if_anomalies=metrics_data.get("if_anomalies", 0),
        avg_inference_latency_ms=round(metrics_data.get("avg_inference_latency_ms", 0.0), 3),
    )


@router.get("/metrics", response_model=MLMetricsResponse)
def get_ml_metrics(
    ml_service: MLService = Depends(get_ml_service),
) -> MLMetricsResponse:
    """
    Returns current telemetry metrics for the runtime ML engine
    (jobs submitted, processed, drops, inference latency, model detections).
    """
    telemetry = ml_service.get_telemetry()
    metrics_data = telemetry.get("metrics", {})
    return _extract_metrics_model(metrics_data)


@router.get("/status", response_model=MLStatusResponse)
def get_ml_status(
    ml_service: MLService = Depends(get_ml_service),
) -> MLStatusResponse:
    """
    Returns the operational status, model availability, queue depth,
    and capacity for the ML subsystem.
    """
    telemetry = ml_service.get_telemetry()
    metrics_data = telemetry.get("metrics", {})

    return MLStatusResponse(
        status=telemetry.get("status", "uninitialized"),
        enabled=telemetry.get("enabled", False),
        random_forest_loaded=telemetry.get("rf_loaded", False),
        isolation_forest_loaded=telemetry.get("if_loaded", False),
        queue_depth=telemetry.get("queue_depth", 0),
        queue_capacity=telemetry.get("queue_capacity", 0),
        metrics=_extract_metrics_model(metrics_data),
    )
