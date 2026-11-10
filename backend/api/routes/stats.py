"""System Statistics REST API endpoint."""

from __future__ import annotations

import logging
from fastapi import APIRouter, Depends

from backend.api.dependencies import get_pipeline_adapter
from backend.api.schemas.rest_schemas import StatisticsResponse
from backend.integrations.pipeline_adapter import PipelineAdapter

logger = logging.getLogger("dpi_ids_ips.backend.routes.stats")

router = APIRouter(prefix="/stats", tags=["Statistics"])


@router.get("", response_model=StatisticsResponse)
def get_aggregate_statistics(
    pipeline_adapter: PipelineAdapter = Depends(get_pipeline_adapter),
) -> StatisticsResponse:
    """
    Returns aggregated real-time statistics across DPI, IDS, flow tracking,
    and alert distributions.
    """
    stats_data = pipeline_adapter.get_aggregate_stats()
    return StatisticsResponse(**stats_data)

