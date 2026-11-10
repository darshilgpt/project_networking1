"""Alert service providing business logic for security alerts."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
from backend.integrations.pipeline_adapter import PipelineAdapter


class AlertService:
    """Encapsulates alert query, filtering, pagination, and aggregation logic."""

    def __init__(self, pipeline_adapter: PipelineAdapter) -> None:
        self.pipeline_adapter = pipeline_adapter

    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        source_ip: Optional[str] = None,
        date_from: Optional[float] = None,
        date_to: Optional[float] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Queries paginated and filtered alerts."""
        return self.pipeline_adapter.get_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            category=category,
            source_ip=source_ip,
            date_from=date_from,
            date_to=date_to,
        )

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Queries single alert by ID."""
        return self.pipeline_adapter.get_alert_by_id(alert_id)
