"""DPI and Protocol inspection integration adapter."""

from __future__ import annotations

from typing import Any, Dict, Optional
from server.worker_pool import PipelineWorkerPool


class DPIAdapter:
    """Read-only adapter for protocol counts and deep inspection statistics."""

    def __init__(self, worker_pool: Optional[PipelineWorkerPool] = None) -> None:
        self.worker_pool = worker_pool

    def get_protocol_breakdown(self) -> Dict[str, Any]:
        """Queries protocol breakdown counts from DPIEngine."""
        if not self.worker_pool or not getattr(self.worker_pool, "dpi_engine", None):
            return {"status": "uninitialized", "protocols": {}}

        dpi = self.worker_pool.dpi_engine
        return {
            "status": "operational",
            "total_inspections": dpi.total_inspections,
            "signature_matches": dpi.signature_matches_count,
            "protocol_counts": dict(dpi.protocol_counts),
        }

