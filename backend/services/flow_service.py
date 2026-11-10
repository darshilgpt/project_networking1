"""Flow service providing business logic for active network flows."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from backend.integrations.pipeline_adapter import PipelineAdapter


class FlowService:
    """Encapsulates connection flow queries, filtering, and summary metrics."""

    def __init__(self, pipeline_adapter: PipelineAdapter) -> None:
        self.pipeline_adapter = pipeline_adapter

    def get_flows(
        self,
        limit: int = 50,
        offset: int = 0,
        protocol: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Queries paginated and filtered active flows."""
        return self.pipeline_adapter.get_flows(
            limit=limit,
            offset=offset,
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            is_active=is_active,
        )

    def get_flow_by_id(self, flow_id: int) -> Optional[Dict[str, Any]]:
        """Queries a single flow by its unique identifier."""
        return self.pipeline_adapter.get_flow_by_id(flow_id)

    def get_flow_summary(self) -> Dict[str, Any]:
        """Provides flow volume and active flow counts."""
        stats = self.pipeline_adapter.get_pipeline_stats()
        return {
            "total_processed": stats.get("total_processed", 0),
            "packets_per_sec": stats.get("packets_per_sec", 0.0),
            "bytes_per_sec": stats.get("bytes_per_sec", 0.0),
        }
