"""Unit and integration tests for Phase 7.3 WebSocket Integration, Real-Time Events, and Backend Finalization."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json
import os
import time
from unittest.mock import AsyncMock, MagicMock
import pytest
from fastapi import WebSocket, WebSocketDisconnect

from backend.api.dependencies import ServiceContainer, verify_admin_key
from backend.api.routes.websocket import _authenticate_ws, websocket_monitor_endpoint
from backend.api.websocket.events import WebSocketEventType, WebSocketMessage
from backend.api.websocket.manager import ClientConnection, WebSocketConnectionManager
from backend.api.websocket.traffic_broadcaster import PeriodicTrafficBroadcaster
from backend.integrations.pipeline_adapter import PipelineAdapter
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from server.client_manager import ClientManager
from server.worker_pool import PipelineWorkerPool


# ==============================================================================
# 1. WebSocket Event Model & Message Schema Tests
# ==============================================================================

def test_websocket_message_schema():
    """Verify WebSocketMessage conforms to required JSON contract."""
    msg = WebSocketMessage(
        event=WebSocketEventType.NEW_ALERT.value,
        data={"alert_id": 1, "severity": "HIGH"},
    )
    dumped = msg.model_dump()
    assert dumped["event"] == "new_alert"
    assert "timestamp" in dumped
    assert dumped["data"]["alert_id"] == 1
    assert dumped["data"]["severity"] == "HIGH"


# ==============================================================================
# 2. WebSocket Authentication Tests
# ==============================================================================

def test_websocket_authentication(monkeypatch):
    """Verify WebSocket authentication against token configuration."""
    monkeypatch.setenv("ADMIN_API_KEY", "admin-secret-test-key")
    monkeypatch.delenv("DASHBOARD_WS_TOKEN", raising=False)

    # Valid token
    assert _authenticate_ws("admin-secret-test-key") is True

    # Invalid token
    assert _authenticate_ws("wrong-token") is False

    # Empty token
    assert _authenticate_ws(None) is False
    assert _authenticate_ws("") is False


# ==============================================================================
# 3. Connection Manager & Multiple Clients Tests
# ==============================================================================

@pytest.mark.anyio
async def test_ws_connection_and_broadcast():
    """Verify client connection registration, threadsafe event dispatch, and delivery."""
    mgr = WebSocketConnectionManager(bridge_queue_size=50, client_queue_size=10)
    loop = asyncio.get_running_loop()
    mgr.set_event_loop(loop)

    mock_ws = AsyncMock(spec=WebSocket)
    client = await mgr.connect(mock_ws)

    assert len(mgr._clients) == 1
    assert client in mgr._clients

    # Publish threadsafe event
    success = mgr.publish_event_threadsafe(
        event_type=WebSocketEventType.NEW_ALERT,
        data={"alert_id": 99, "category": "PORT_SCAN"},
    )
    assert success is True

    # Allow dispatcher loop to process
    await asyncio.sleep(0.05)

    assert mock_ws.send_json.called
    sent_payload = mock_ws.send_json.call_args[0][0]
    assert sent_payload["event"] == "new_alert"
    assert sent_payload["data"]["alert_id"] == 99

    # Clean disconnect
    await mgr.disconnect(client)
    assert len(mgr._clients) == 0
    await mgr.shutdown()


@pytest.mark.anyio
async def test_multiple_simultaneous_clients():
    """Verify event broadcasting delivers to multiple concurrent clients."""
    mgr = WebSocketConnectionManager(bridge_queue_size=50, client_queue_size=10)
    loop = asyncio.get_running_loop()
    mgr.set_event_loop(loop)

    mock_ws1 = AsyncMock(spec=WebSocket)
    mock_ws2 = AsyncMock(spec=WebSocket)

    c1 = await mgr.connect(mock_ws1)
    c2 = await mgr.connect(mock_ws2)
    assert len(mgr._clients) == 2

    # Broadcast event
    mgr.publish_event_threadsafe(
        event_type=WebSocketEventType.ML_EVENT,
        data={"rf_classifications": 5, "latency_ms": 1.2},
    )

    await asyncio.sleep(0.05)

    assert mock_ws1.send_json.called
    assert mock_ws2.send_json.called

    await mgr.shutdown()
    assert len(mgr._clients) == 0


# ==============================================================================
# 4. Slow Client Handling & Queue Saturation Drop Policy
# ==============================================================================

@pytest.mark.anyio
async def test_slow_client_queue_saturation_drop_policy():
    """Verify that when a client's outgoing queue saturates, events are safely dropped without blocking."""
    # Extremely small queue size (capacity = 2)
    mgr = WebSocketConnectionManager(bridge_queue_size=50, client_queue_size=2)
    loop = asyncio.get_running_loop()
    mgr.set_event_loop(loop)

    mock_ws = AsyncMock(spec=WebSocket)
    # Simulate a stuck/slow client that takes 5 seconds per send
    async def slow_send(msg):
        await asyncio.sleep(5.0)

    mock_ws.send_json.side_effect = slow_send
    client = await mgr.connect(mock_ws)

    # Publish multiple events rapidly to saturate client queue
    for i in range(10):
        mgr.publish_event_threadsafe(
            event_type=WebSocketEventType.TRAFFIC_UPDATE,
            data={"counter": i},
        )

    # Allow dispatcher loop to attempt enqueueing
    await asyncio.sleep(0.05)

    # Verify messages were dropped for the slow client rather than blocking the pipeline
    metrics = mgr.get_connection_metrics()
    assert metrics["total_events_published"] == 10
    assert client.messages_dropped > 0
    assert metrics["total_client_drops"] > 0

    await mgr.shutdown()


# ==============================================================================
# 5. Periodic Traffic Broadcaster Tests
# ==============================================================================

@pytest.mark.anyio
async def test_periodic_traffic_broadcaster():
    """Verify PeriodicTrafficBroadcaster publishes periodic traffic updates to active clients."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)

    mgr = WebSocketConnectionManager(bridge_queue_size=50, client_queue_size=10)
    loop = asyncio.get_running_loop()
    mgr.set_event_loop(loop)

    mock_ws = AsyncMock(spec=WebSocket)
    client = await mgr.connect(mock_ws)

    broadcaster = PeriodicTrafficBroadcaster(
        ws_manager=mgr,
        pipeline_adapter=adapter,
        interval_seconds=0.05,
    )
    broadcaster.start()

    # Wait for at least one broadcast cycle
    await asyncio.sleep(0.12)

    broadcaster.stop()
    await mgr.shutdown()

    # Confirm traffic_update was sent
    assert mock_ws.send_json.called
    calls = [call[0][0]["event"] for call in mock_ws.send_json.call_args_list]
    assert "traffic_update" in calls


# ==============================================================================
# 6. Pipeline Alert Handoff to WebSocket Integration
# ==============================================================================

def test_pipeline_alert_hook_threadsafe_handoff():
    """Verify that alerts generated in worker pool trigger threadsafe WebSocket handoff."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)

    container = ServiceContainer()
    container.initialize(pipeline_adapter=adapter)

    # Mock publish_event_threadsafe
    container.ws_manager.publish_event_threadsafe = MagicMock()

    # Create synthetic alert
    alert = IDSAlert(
        alert_id=777,
        timestamp=time.time(),
        datetime_str="12:00:00",
        source_ip="10.10.0.99",
        destination_ip="10.10.0.1",
        source_port=12345,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.PORT_SCAN,
        severity=Severity.HIGH,
        matched_rule="Test Scan",
        evidence="SYN probes to 20 ports",
        recommended_action=DecisionAction.BLOCK,
        packet_id=1,
    )

    client_ctx = cm._get_or_create_client("10.10.0.99")
    wp.on_alert_generated(alert, client_ctx)

    # Verify publish_event_threadsafe was called with new_alert
    assert container.ws_manager.publish_event_threadsafe.called
    call_args = container.ws_manager.publish_event_threadsafe.call_args
    assert call_args[1]["event_type"] == WebSocketEventType.NEW_ALERT
    assert call_args[1]["data"]["alert_id"] == 777
    assert call_args[1]["data"]["source_ip"] == "10.10.0.99"

    container.shutdown()


# ==============================================================================
# 7. Endpoint Disconnect and Ping/Pong Support
# ==============================================================================

@pytest.mark.anyio
async def test_websocket_endpoint_ping_pong_and_disconnect(monkeypatch):
    """Verify endpoint handles client ping messages and closes on disconnect."""
    monkeypatch.setenv("ADMIN_API_KEY", "test-token")

    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.client = ("127.0.0.1", 54321)
    mock_ws.headers = {}
    mock_ws.accept = AsyncMock()
    mock_ws.close = AsyncMock()

    # Simulate client sending 'ping' then disconnecting
    mock_ws.receive_text = AsyncMock(side_effect=["ping", WebSocketDisconnect(1000)])

    await websocket_monitor_endpoint(websocket=mock_ws, token="test-token")

    # Verify initial accept
    assert mock_ws.accept.called


@pytest.mark.anyio
async def test_websocket_endpoint_unauthorized_rejection(monkeypatch):
    """Verify endpoint closes unauthorized connection with WS_1008_POLICY_VIOLATION."""
    monkeypatch.setenv("ADMIN_API_KEY", "secret-token")

    mock_ws = AsyncMock(spec=WebSocket)
    mock_ws.client = ("10.0.0.1", 12345)
    mock_ws.headers = {}
    mock_ws.close = AsyncMock()

    # Connect with wrong token
    await websocket_monitor_endpoint(websocket=mock_ws, token="invalid-token")

    assert mock_ws.close.called
    code = mock_ws.close.call_args[1]["code"]
    assert code == 1008
