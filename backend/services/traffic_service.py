"""Traffic service providing bandwidth, throughput, and bounded packet metadata."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple
from backend.integrations.pipeline_adapter import PipelineAdapter


class TrafficService:
    """Encapsulates traffic aggregation and bounded packet inspection."""

    def __init__(self, pipeline_adapter: PipelineAdapter) -> None:
        self.pipeline_adapter = pipeline_adapter

    def get_recent_packets(self, limit: int = 50, offset: int = 0) -> Tuple[List[Dict[str, Any]], int]:
        """Queries recent packet metadata without exposing raw payloads."""
        return self.pipeline_adapter.get_recent_packets(limit=limit, offset=offset)

    def get_traffic_metrics(self) -> Dict[str, Any]:
        """Provides aggregate throughput and client metrics."""
        stats = self.pipeline_adapter.get_pipeline_stats()
        clients = self.pipeline_adapter.get_registered_clients()
        return {
            "total_bytes": stats.get("total_bytes", 0),
            "bytes_per_sec": stats.get("bytes_per_sec", 0.0),
            "total_clients": len(clients),
            "clients": clients,
        }
