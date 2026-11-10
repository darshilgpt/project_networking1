"""Background periodic publisher for real-time WebSocket traffic updates."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional
from backend.api.websocket.events import WebSocketEventType
from backend.api.websocket.manager import WebSocketConnectionManager
from backend.integrations.pipeline_adapter import PipelineAdapter

logger = logging.getLogger("dpi_ids_ips.backend.websocket.traffic_broadcaster")


class PeriodicTrafficBroadcaster:
    """
    Publishes periodic aggregate traffic and telemetry updates to connected WebSocket clients.
    Does not inspect individual packets or calculate heavy per-packet metrics.
    """

    def __init__(
        self,
        ws_manager: WebSocketConnectionManager,
        pipeline_adapter: PipelineAdapter,
        interval_seconds: float = 1.0,
    ) -> None:
        self.ws_manager = ws_manager
        self.pipeline_adapter = pipeline_adapter
        self.interval_seconds = interval_seconds
        self._task: Optional[asyncio.Task] = None
        self._is_running = False

    def start(self) -> None:
        """Starts background broadcasting loop in active asyncio event loop if available."""
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            logger.debug("No active asyncio event loop; skipping periodic broadcaster start.")
            return

        if self._task is None or self._task.done():
            self._is_running = True
            self._task = loop.create_task(self._run_loop())
            logger.info(f"Periodic traffic broadcaster started (interval: {self.interval_seconds}s).")

    def stop(self) -> None:
        """Stops the broadcaster task."""
        self._is_running = False
        if self._task and not self._task.done():
            self._task.cancel()
            logger.info("Periodic traffic broadcaster stopped.")

    async def _run_loop(self) -> None:
        """Broadcasts snapshot metrics at the configured cadence."""
        while self._is_running:
            try:
                await asyncio.sleep(self.interval_seconds)

                # Skip if no clients are connected
                if not self.ws_manager._clients:
                    continue

                stats = self.pipeline_adapter.get_aggregate_stats()
                ml_status = self.pipeline_adapter.get_ml_status()

                traffic_data = {
                    "total_packets": stats.get("total_packets_processed", 0),
                    "packet_rate": stats.get("packets_per_sec", 0.0),
                    "bytes_rate": stats.get("bytes_per_sec", 0.0),
                    "traffic_volume_bytes": stats.get("total_bytes_processed", 0),
                    "active_flows": stats.get("active_flows", 0),
                    "total_flows": stats.get("total_flows", 0),
                    "total_alerts": stats.get("total_alerts", 0),
                    "protocol_distribution": stats.get("protocol_distribution", {}),
                    "ml_queue_depth": ml_status.get("queue_depth", 0),
                    "active_workers": stats.get("active_workers", 0),
                    "active_prevention": stats.get("active_prevention", False),
                }

                # Publish threadsafe event
                self.ws_manager.publish_event_threadsafe(
                    event_type=WebSocketEventType.TRAFFIC_UPDATE,
                    data=traffic_data,
                )
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in traffic broadcaster loop: {e}")
                await asyncio.sleep(self.interval_seconds)
