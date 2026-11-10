"""ML service providing model status and telemetry metrics."""

from __future__ import annotations

from typing import Any, Dict
from backend.integrations.pipeline_adapter import PipelineAdapter


class MLService:
    """Encapsulates ML telemetry and model runtime status."""

    def __init__(self, pipeline_adapter: PipelineAdapter) -> None:
        self.pipeline_adapter = pipeline_adapter

    def get_telemetry(self) -> Dict[str, Any]:
        """Provides ML inference statistics and queue dynamics."""
        return self.pipeline_adapter.get_ml_status()
