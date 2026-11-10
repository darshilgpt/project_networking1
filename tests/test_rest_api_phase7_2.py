"""Unit and integration tests for Phase 7.2 REST API Endpoints and Service Integration."""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock
import pytest
from fastapi import HTTPException

from backend.api.dependencies import ServiceContainer, verify_admin_key
from backend.api.routes.alerts import get_alert_by_id, list_alerts
from backend.api.routes.firewall import block_ip, list_firewall_rules, unblock_ip_or_rule
from backend.api.routes.flows import get_flow_by_id, list_flows
from backend.api.routes.ml import get_ml_metrics, get_ml_status
from backend.api.routes.notifications import get_notification_status
from backend.api.routes.packets import list_recent_packets
from backend.api.routes.stats import get_aggregate_statistics
from backend.api.schemas.rest_schemas import FirewallBlockRequest
from backend.integrations.firewall_adapter import FirewallAdapter
from backend.integrations.pipeline_adapter import PipelineAdapter
from backend.services.alert_service import AlertService
from backend.services.firewall_service import FirewallService
from backend.services.flow_service import FlowService
from backend.services.ml_service import MLService
from backend.services.notification.notification_config import NotificationConfig
from backend.services.notification.notification_manager import NotificationManager
from backend.services.traffic_service import TrafficService
from flow.flow_manager import FlowManager
from flow.flow_tracker import FlowTracker
from ips.blocking_manager import BlockingManager
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.flow_model import Flow, FlowKey, FlowStats, TCPState
from models.packet_models import IPv4Header, ParsedPacket, TCPFlags, TCPHeader
from server.client_manager import ClientContext, ClientManager
from server.worker_pool import PipelineWorkerPool, ProcessedPacketResult


# ==============================================================================
# Helper Factories
# ==============================================================================

def make_test_alert(
    alert_id: int = 1,
    source_ip: str = "10.10.0.50",
    category: DetectionCategory = DetectionCategory.PORT_SCAN,
    severity: Severity = Severity.HIGH,
    action: DecisionAction = DecisionAction.BLOCK,
    evidence: str = "SYN probes to 20 ports",
) -> IDSAlert:
    return IDSAlert(
        alert_id=alert_id,
        timestamp=time.time(),
        datetime_str="12:00:00",
        source_ip=source_ip,
        destination_ip="10.10.0.1",
        source_port=45678,
        destination_port=80,
        protocol="TCP",
        category=category,
        severity=severity,
        matched_rule="Test Rule",
        evidence=evidence,
        recommended_action=action,
        packet_id=100 + alert_id,
    )


def make_test_flow(flow_id: int = 1, src_ip: str = "10.10.0.50", dst_ip: str = "10.10.0.1", proto: str = "TCP") -> Flow:
    key = FlowKey(ip_a=src_ip, port_a=50000 + flow_id, ip_b=dst_ip, port_b=80, protocol=proto)
    stats = FlowStats(packets_forward=5, packets_reverse=3, bytes_forward=500, bytes_reverse=300, first_seen=100.0, last_seen=110.0)
    return Flow(
        flow_id=flow_id,
        key=key,
        initiator_ip=src_ip,
        initiator_port=50000 + flow_id,
        responder_ip=dst_ip,
        responder_port=80,
        protocol=proto,
        stats=stats,
        tcp_state=TCPState.ESTABLISHED,
        application_protocol="HTTP",
        is_active=True,
    )


def make_test_packet_result(packet_id: int = 1) -> ProcessedPacketResult:
    ipv4 = IPv4Header(
        version=4,
        ihl=5,
        header_length=20,
        dscp=0,
        ecn=0,
        total_length=60,
        identification=1234,
        flags_raw=2,
        flag_df=True,
        flag_mf=False,
        fragment_offset=0,
        ttl=64,
        protocol_code=6,
        protocol_name="TCP",
        checksum=0,
        checksum_valid=True,
        src_ip="10.10.0.50",
        dst_ip="10.10.0.1",
    )
    tcp_flags = TCPFlags(syn=True, ack=False)
    tcp = TCPHeader(
        src_port=54321,
        dst_port=80,
        seq_num=100,
        ack_num=200,
        data_offset=5,
        header_length=20,
        flags=tcp_flags,
        window_size=65535,
        checksum=0,
        urgent_pointer=0,
    )
    packet = ParsedPacket(
        packet_id=packet_id,
        timestamp=time.time(),
        datetime_str="12:00:01",
        raw_length=60,
        network_type="IPv4",
        transport_type="TCP",
        ipv4=ipv4,
        tcp=tcp,
        payload=b"SECRET_PAYLOAD_DO_NOT_EXPOSE",
    )
    client = ClientContext(client_ip="10.10.0.50")
    return ProcessedPacketResult(
        packet=packet,
        client=client,
        is_outbound=True,
        flow=None,
        dpi_result=None,
        alerts=[],
        decision=DecisionAction.ALLOW,
        status_msg="Allowed",
        processing_time_ms=0.5,
    )


# ==============================================================================
# 1. Alert REST APIs
# ==============================================================================

def test_alerts_endpoint_pagination_and_filtering():
    """Verify GET /api/v1/alerts supports limit, offset, and severity/category filtering."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)
    alert_service = AlertService(adapter)

    # Populate alerts
    a1 = make_test_alert(1, source_ip="10.10.0.50", category=DetectionCategory.PORT_SCAN, severity=Severity.HIGH)
    a2 = make_test_alert(2, source_ip="10.10.0.51", category=DetectionCategory.SQL_INJECTION, severity=Severity.CRITICAL)
    a3 = make_test_alert(3, source_ip="10.10.0.52", category=DetectionCategory.PORT_SCAN, severity=Severity.LOW)
    wp.recent_alerts.append((a1, "Client-50"))
    wp.recent_alerts.append((a2, "Client-51"))
    wp.recent_alerts.append((a3, "Client-52"))

    # 1. All alerts
    res = list_alerts(limit=50, offset=0, alert_service=alert_service)
    assert res.pagination.total == 3
    assert res.pagination.returned == 3
    assert len(res.alerts) == 3

    # 2. Filter by category
    res_sqli = list_alerts(limit=50, offset=0, category="SQL_INJECTION", alert_service=alert_service)
    assert res_sqli.pagination.total == 1
    assert res_sqli.alerts[0].alert_id == 2
    assert res_sqli.alerts[0].category == "SQL_INJECTION"

    # 3. Filter by severity
    res_high = list_alerts(limit=50, offset=0, severity="HIGH", alert_service=alert_service)
    assert res_high.pagination.total == 1
    assert res_high.alerts[0].alert_id == 1

    # 4. Pagination slicing
    res_paged = list_alerts(limit=1, offset=1, alert_service=alert_service)
    assert res_paged.pagination.total == 3
    assert res_paged.pagination.returned == 1
    assert res_paged.pagination.offset == 1


def test_alert_by_id_endpoint_and_404():
    """Verify GET /api/v1/alerts/{alert_id} returns exact item or raises 404."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)
    alert_service = AlertService(adapter)

    a1 = make_test_alert(42, source_ip="10.10.0.99")
    wp.recent_alerts.append((a1, "Client-99"))

    item = get_alert_by_id(alert_id=42, alert_service=alert_service)
    assert item.alert_id == 42
    assert item.source_ip == "10.10.0.99"
    assert item.action == "BLOCK"

    with pytest.raises(HTTPException) as exc_info:
        get_alert_by_id(alert_id=9999, alert_service=alert_service)
    assert exc_info.value.status_code == 404


# ==============================================================================
# 2. Flow REST APIs
# ==============================================================================

def test_flows_endpoint_listing_and_filtering():
    """Verify GET /api/v1/flows aggregates flows across clients and applies filters."""
    cm = ClientManager()
    client1 = cm._get_or_create_client("10.10.0.50")
    client2 = cm._get_or_create_client("10.10.0.60")

    flow1 = make_test_flow(101, src_ip="10.10.0.50", proto="TCP")
    flow2 = make_test_flow(102, src_ip="10.10.0.60", proto="UDP")

    # Insert flows into client flow managers
    client1.flow_manager.tracker._flows[flow1.key] = flow1
    client2.flow_manager.tracker._flows[flow2.key] = flow2

    adapter = PipelineAdapter(client_manager=cm)
    flow_service = FlowService(adapter)

    # 1. All flows
    res = list_flows(limit=50, offset=0, flow_service=flow_service)
    assert res.pagination.total == 2
    assert len(res.flows) == 2

    # 2. Filter by protocol
    res_tcp = list_flows(limit=50, offset=0, protocol="TCP", flow_service=flow_service)
    assert res_tcp.pagination.total == 1
    assert res_tcp.flows[0].protocol == "TCP"
    assert res_tcp.flows[0].flow_id == 101

    # 3. Flow details by ID
    flow_detail = get_flow_by_id(flow_id=101, flow_service=flow_service)
    assert flow_detail.flow_id == 101
    assert flow_detail.source_ip == "10.10.0.50"
    assert flow_detail.application_protocol == "HTTP"

    # 4. Non-existent flow 404
    with pytest.raises(HTTPException) as exc_info:
        get_flow_by_id(flow_id=9999, flow_service=flow_service)
    assert exc_info.value.status_code == 404


# ==============================================================================
# 3. Packet Metadata REST APIs (Zero Raw Payload Leakage)
# ==============================================================================

def test_packets_endpoint_safety_and_no_payload_exposure():
    """Verify GET /api/v1/packets returns packet metadata while strictly redacting raw payload bytes."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)
    traffic_service = TrafficService(adapter)

    p_res = make_test_packet_result(packet_id=555)
    wp.recent_packets.append(p_res)

    res = list_recent_packets(limit=50, offset=0, traffic_service=traffic_service)
    assert res.pagination.total == 1
    assert res.pagination.returned == 1

    packet_item = res.packets[0]
    assert packet_item.packet_id == 555
    assert packet_item.source_ip == "10.10.0.50"
    assert packet_item.packet_length_bytes == 60
    assert "SYN" in (packet_item.flags or "")

    # Strict Guarantee: Pydantic model does not have 'payload' field
    assert not hasattr(packet_item, "payload")
    packet_dict = packet_item.model_dump()
    assert "payload" not in packet_dict
    assert "SECRET_PAYLOAD_DO_NOT_EXPOSE" not in str(packet_dict)


# ==============================================================================
# 4. System Statistics Endpoint
# ==============================================================================

def test_system_statistics_endpoint():
    """Verify GET /api/v1/stats aggregates DPI, IDS, and Flow metrics accurately."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)

    # Populate sample metrics
    wp.stats.total_processed = 1200
    wp.stats.total_bytes = 650000
    wp.stats.total_alerts = 8
    wp.stats.total_blocks = 2
    wp.dpi_engine.protocol_counts["HTTP"] = 400
    wp.dpi_engine.protocol_counts["DNS"] = 250

    a1 = make_test_alert(1, category=DetectionCategory.PORT_SCAN, severity=Severity.HIGH)
    wp.recent_alerts.append((a1, "Client-50"))

    stats_resp = get_aggregate_statistics(pipeline_adapter=adapter)
    assert stats_resp.pipeline_status == "active"
    assert stats_resp.total_packets_processed == 1200
    assert stats_resp.total_bytes_processed == 650000
    assert stats_resp.protocol_distribution.get("HTTP") == 400
    assert stats_resp.alerts_by_severity.get("HIGH") == 1
    assert stats_resp.alerts_by_category.get("PORT_SCAN") == 1


# ==============================================================================
# 5. Machine Learning Telemetry & Status APIs
# ==============================================================================

def test_ml_metrics_and_status_endpoints():
    """Verify GET /api/v1/ml/metrics and GET /api/v1/ml/status."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)
    ml_service = MLService(adapter)

    # Telemetry
    metrics = get_ml_metrics(ml_service=ml_service)
    assert metrics.jobs_submitted >= 0
    assert metrics.jobs_processed >= 0
    assert metrics.avg_inference_latency_ms >= 0.0

    # Status
    status_resp = get_ml_status(ml_service=ml_service)
    assert status_resp.status in ("operational", "disabled")
    assert status_resp.queue_capacity >= 0
    assert status_resp.metrics.jobs_submitted == metrics.jobs_submitted


# ==============================================================================
# 6. Firewall APIs & Security Authorization
# ==============================================================================

def test_firewall_authorization_enforcement(monkeypatch):
    """Verify verify_admin_key checks X-API-Key and Bearer header, rejecting unauthorized requests."""
    monkeypatch.setenv("ADMIN_API_KEY", "test-secret-12345")

    # 1. Correct X-API-Key
    assert verify_admin_key(x_api_key="test-secret-12345", authorization=None) is True

    # 2. Correct Authorization: Bearer
    assert verify_admin_key(x_api_key=None, authorization="Bearer test-secret-12345") is True

    # 3. Invalid key raises 401
    with pytest.raises(HTTPException) as exc1:
        verify_admin_key(x_api_key="wrong-key", authorization=None)
    assert exc1.value.status_code == 401

    # 4. Missing key raises 401
    with pytest.raises(HTTPException) as exc2:
        verify_admin_key(x_api_key=None, authorization=None)
    assert exc2.value.status_code == 401


def test_firewall_rule_listing_and_block_unblock_cycle(monkeypatch):
    """Verify GET /api/v1/firewall/rules, POST /api/v1/firewall/block, and DELETE /api/v1/firewall/block/{rule_id}."""
    monkeypatch.setenv("ENABLE_FIREWALL_MANAGEMENT", "false")  # Strict simulation mode

    bm = BlockingManager(active_prevention=False)
    wp = MagicMock()
    wp.blocking_manager = bm
    adapter = FirewallAdapter(worker_pool=wp)
    fw_service = FirewallService(adapter)

    # 1. Initially empty rules
    initial_rules = list_firewall_rules(firewall_service=fw_service)
    assert initial_rules.total_active_rules == 0
    assert len(initial_rules.rules) == 0

    # 2. Add block
    req = FirewallBlockRequest(ip_address="10.10.0.75", duration_seconds=120.0, reason="Suspicious port sweep")
    block_resp = block_ip(req=req, firewall_service=fw_service, authorized=True)
    assert block_resp.success is True
    assert block_resp.operation == "BLOCK"
    assert block_resp.ip_address == "10.10.0.75"
    assert block_resp.effective_mode == "SIMULATION"

    # 3. Rule should now appear in listing
    updated_rules = list_firewall_rules(firewall_service=fw_service)
    assert updated_rules.total_active_rules == 1
    assert updated_rules.rules[0].ip_address == "10.10.0.75"
    assert updated_rules.rules[0].duration_seconds == 120.0
    assert updated_rules.rules[0].is_simulated is True

    # 4. Unblock rule
    unblock_resp = unblock_ip_or_rule(rule_id="DYN_10.10.0.75", firewall_service=fw_service, authorized=True)
    assert unblock_resp.success is True
    assert unblock_resp.operation == "UNBLOCK"

    # 5. Rule listing empty again
    cleared_rules = list_firewall_rules(firewall_service=fw_service)
    assert cleared_rules.total_active_rules == 0

    # 6. Unblocking non-existent IP raises 404
    with pytest.raises(HTTPException) as exc_info:
        unblock_ip_or_rule(rule_id="10.10.0.99", firewall_service=fw_service, authorized=True)
    assert exc_info.value.status_code == 404


def test_firewall_block_safety_allowlist_protection():
    """Verify system-critical IPs (loopback, server gateway) cannot be blocked via the API."""
    bm = BlockingManager(active_prevention=False)
    wp = MagicMock()
    wp.blocking_manager = bm
    adapter = FirewallAdapter(worker_pool=wp)
    fw_service = FirewallService(adapter)

    # Attempt to block server gateway
    req = FirewallBlockRequest(ip_address="10.10.0.1", duration_seconds=60.0)
    with pytest.raises(HTTPException) as exc_info:
        block_ip(req=req, firewall_service=fw_service, authorized=True)
    assert exc_info.value.status_code == 400
    assert "allowlist" in exc_info.value.detail.lower()


# ==============================================================================
# 7. Notification Status REST API
# ==============================================================================

def test_notification_status_endpoint_excludes_secrets():
    """Verify GET /api/v1/notifications/status returns metrics while excluding SMTP secrets."""
    cfg = NotificationConfig(
        email_enabled=True,
        smtp_host="smtp.gmail.com",
        smtp_port=587,
        smtp_username="confidential_user@gmail.com",
        smtp_password="super_secret_password_123",
        alert_email_to=["kanvav.ec23@bmsce.ac.in"],
        email_cooldown_seconds=300.0,
    )
    notif_mgr = NotificationManager(cfg)

    status_resp = get_notification_status(notification_mgr=notif_mgr)
    assert status_resp.enabled is True
    assert status_resp.smtp_status == "configured"
    assert status_resp.recipients_count == 1
    assert status_resp.cooldown_seconds == 300.0

    # Verify absence of secrets in schema and dict dump
    resp_dict = status_resp.model_dump()
    assert "smtp_username" not in resp_dict
    assert "smtp_password" not in resp_dict
    assert "super_secret_password_123" not in str(resp_dict)
    assert "confidential_user@gmail.com" not in str(resp_dict)


# ==============================================================================
# 8. Uninitialized Pipeline Graceful Fallback
# ==============================================================================

def test_uninitialized_pipeline_graceful_fallbacks():
    """Verify REST endpoints handle uninitialized adapters gracefully without unhandled exceptions."""
    empty_adapter = PipelineAdapter(worker_pool=None)
    alert_service = AlertService(empty_adapter)
    flow_service = FlowService(empty_adapter)
    traffic_service = TrafficService(empty_adapter)
    ml_service = MLService(empty_adapter)
    fw_adapter = FirewallAdapter(worker_pool=None)
    fw_service = FirewallService(fw_adapter)

    # Alerts
    alerts = list_alerts(limit=10, offset=0, alert_service=alert_service)
    assert alerts.pagination.total == 0

    # Flows
    flows = list_flows(limit=10, offset=0, flow_service=flow_service)
    assert flows.pagination.total == 0

    # Packets
    packets = list_recent_packets(limit=10, offset=0, traffic_service=traffic_service)
    assert packets.pagination.total == 0

    # Stats
    stats = get_aggregate_statistics(pipeline_adapter=empty_adapter)
    assert stats.pipeline_status == "uninitialized"

    # ML Status
    ml_stat = get_ml_status(ml_service=ml_service)
    assert ml_stat.status == "uninitialized"

    # Firewall
    fw_rules = list_firewall_rules(firewall_service=fw_service)
    assert fw_rules.total_active_rules == 0
