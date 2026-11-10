"""Centralized backend dependencies and service container."""

from __future__ import annotations

import os
import secrets
from typing import Optional
from fastapi import Header, HTTPException, Security, status
from fastapi.security import APIKeyHeader

from backend.api.websocket.events import WebSocketEventType
from backend.api.websocket.manager import WebSocketConnectionManager, ws_manager
from backend.api.websocket.traffic_broadcaster import PeriodicTrafficBroadcaster
from backend.integrations.dpi_adapter import DPIAdapter
from backend.integrations.firewall_adapter import FirewallAdapter
from backend.integrations.pipeline_adapter import PipelineAdapter
from backend.services.alert_service import AlertService
from backend.services.firewall_service import FirewallService
from backend.services.flow_service import FlowService
from backend.services.ml_service import MLService
from backend.services.notification.notification_config import NotificationConfig
from backend.services.notification.notification_manager import NotificationManager
from backend.services.traffic_service import TrafficService


class ServiceContainer:
    """Singleton container managing backend services, pipeline adapters, and WebSocket broadcaster."""

    def __init__(self) -> None:
        self.pipeline_adapter: PipelineAdapter = PipelineAdapter()
        self.firewall_adapter: FirewallAdapter = FirewallAdapter()
        self.dpi_adapter: DPIAdapter = DPIAdapter()
        self.notification_config: NotificationConfig = NotificationConfig.from_env()
        self.notification_manager: NotificationManager = NotificationManager(self.notification_config)
        self.ws_manager: WebSocketConnectionManager = ws_manager
        self.traffic_broadcaster: PeriodicTrafficBroadcaster = PeriodicTrafficBroadcaster(
            ws_manager=self.ws_manager,
            pipeline_adapter=self.pipeline_adapter,
            interval_seconds=float(os.getenv("WS_TRAFFIC_INTERVAL", "1.0")),
        )

        # Services
        self.alert_service: AlertService = AlertService(self.pipeline_adapter)
        self.flow_service: FlowService = FlowService(self.pipeline_adapter)
        self.traffic_service: TrafficService = TrafficService(self.pipeline_adapter)
        self.firewall_service: FirewallService = FirewallService(self.firewall_adapter)
        self.ml_service: MLService = MLService(self.pipeline_adapter)

    def initialize(
        self,
        pipeline_adapter: Optional[PipelineAdapter] = None,
        firewall_adapter: Optional[FirewallAdapter] = None,
        notification_manager: Optional[NotificationManager] = None,
    ) -> None:
        """Initializes or binds active pipeline instances to backend."""
        if pipeline_adapter is not None:
            self.pipeline_adapter = pipeline_adapter
            self.alert_service = AlertService(self.pipeline_adapter)
            self.flow_service = FlowService(self.pipeline_adapter)
            self.traffic_service = TrafficService(self.pipeline_adapter)
            self.ml_service = MLService(self.pipeline_adapter)
            self.dpi_adapter = DPIAdapter(pipeline_adapter.worker_pool)
            self.traffic_broadcaster.pipeline_adapter = self.pipeline_adapter

            # Hook real-time alert handoff from existing worker pool if available
            if pipeline_adapter.worker_pool:
                existing_alert_cb = pipeline_adapter.worker_pool.on_alert_generated

                def _ws_alert_hook(alert, client_ctx):
                    # Invoke prior callback first
                    if existing_alert_cb:
                        try:
                            existing_alert_cb(alert, client_ctx)
                        except Exception:
                            pass
                    # Thread-safe event handoff to WebSocket
                    self.ws_manager.publish_event_threadsafe(
                        event_type=WebSocketEventType.NEW_ALERT,
                        data={
                            "alert_id": alert.alert_id,
                            "timestamp": alert.timestamp,
                            "source_ip": alert.source_ip,
                            "destination_ip": alert.destination_ip,
                            "source_port": alert.source_port,
                            "destination_port": alert.destination_port,
                            "protocol": alert.protocol,
                            "category": getattr(alert.category, "value", str(alert.category)),
                            "severity": getattr(alert.severity, "value", str(alert.severity)),
                            "matched_rule": alert.matched_rule,
                            "action": getattr(alert.recommended_action, "value", "ALERT") if alert.recommended_action else "ALERT",
                            "evidence": getattr(alert, "evidence", None),
                            "client_tag": getattr(client_ctx, "client_name", None),
                        },
                    )

                pipeline_adapter.worker_pool.on_alert_generated = _ws_alert_hook

        if firewall_adapter is not None:
            self.firewall_adapter = firewall_adapter
            self.firewall_service = FirewallService(self.firewall_adapter)
        elif pipeline_adapter is not None:
            self.firewall_adapter = FirewallAdapter(pipeline_adapter.worker_pool)
            self.firewall_service = FirewallService(self.firewall_adapter)

        if notification_manager is not None:
            self.notification_manager = notification_manager
        else:
            self.notification_manager.start()

        # Start periodic traffic broadcaster
        self.traffic_broadcaster.start()

    def shutdown(self) -> None:
        """Gracefully halts backend services."""
        if self.traffic_broadcaster:
            self.traffic_broadcaster.stop()
        if self.notification_manager:
            self.notification_manager.stop()


# Global service container instance
_container = ServiceContainer()


def get_service_container() -> ServiceContainer:
    """FastAPI dependency for accessing the service container."""
    return _container


def get_pipeline_adapter() -> PipelineAdapter:
    """FastAPI dependency for accessing the pipeline adapter."""
    return _container.pipeline_adapter


def get_firewall_adapter() -> FirewallAdapter:
    """FastAPI dependency for accessing the firewall adapter."""
    return _container.firewall_adapter


def get_notification_manager() -> NotificationManager:
    """FastAPI dependency for accessing the notification manager."""
    return _container.notification_manager


def get_ws_manager() -> WebSocketConnectionManager:
    """FastAPI dependency for accessing the WebSocket manager."""
    return _container.ws_manager


def get_alert_service() -> AlertService:
    """FastAPI dependency for alert business logic."""
    return _container.alert_service


def get_flow_service() -> FlowService:
    """FastAPI dependency for flow business logic."""
    return _container.flow_service


def get_traffic_service() -> TrafficService:
    """FastAPI dependency for packet and traffic business logic."""
    return _container.traffic_service


def get_firewall_service() -> FirewallService:
    """FastAPI dependency for firewall operations."""
    return _container.firewall_service


def get_ml_service() -> MLService:
    """FastAPI dependency for ML service queries."""
    return _container.ml_service


# API Key Security for administrative mutations (Firewall block/unblock)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_admin_key(
    x_api_key: Optional[str] = Security(api_key_header),
    authorization: Optional[str] = Header(default=None),
) -> bool:
    """
    Enforces authorization check for administrative write operations.
    Accepts X-API-Key header or Authorization: Bearer <ADMIN_API_KEY>.
    """
    expected_key = os.getenv("ADMIN_API_KEY", "dpi-admin-secret-key").strip()

    provided_key = None
    if x_api_key:
        provided_key = x_api_key.strip()
    elif authorization:
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            provided_key = parts[1].strip()

    if not provided_key or not secrets.compare_digest(provided_key, expected_key):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing administrative API key. Provide 'X-API-Key' or 'Authorization: Bearer <key>'.",
        )
    return True
