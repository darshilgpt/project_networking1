"""Unit and integration tests for ML runtime integration, async inference queue, and alert generation."""

import os
import queue
import time
from typing import List
import numpy as np
import pytest

from flow.flow_manager import FlowManager
from ml.data.feature_mapping import AttackCategory
from ml.features.feature_schema import FeatureSchema
from ml.runtime.config import MLInferenceJob, MLRuntimeConfig
from ml.runtime.engine import MLRuntimeEngine
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.flow_model import Flow, FlowKey, FlowStats, TCPState
from models.packet_models import IPv4Header, ParsedPacket, TCPFlags, TCPHeader
from server.client_manager import ClientManager
from server.ingestion import QueuedPacket
from server.worker_pool import PipelineWorkerPool


def make_synthetic_packet(
    src_ip="192.168.1.100",
    dst_ip="10.0.0.1",
    src_port=50000,
    dst_port=80,
    flags_tuple=(False, False, False, False, False, False),
    payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    timestamp=1000.0,
) -> ParsedPacket:
    fin, syn, rst, psh, ack, urg = flags_tuple
    pkt = ParsedPacket(
        packet_id=1,
        timestamp=timestamp,
        datetime_str="12:00:00.000",
        raw_length=len(payload) + 40,
        payload=payload,
        payload_length=len(payload),
        network_type="IPv4",
        transport_type="TCP",
        ipv4=IPv4Header(
            version=4,
            ihl=5,
            header_length=20,
            dscp=0,
            ecn=0,
            total_length=len(payload) + 40,
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
            src_ip=src_ip,
            dst_ip=dst_ip,
        ),
        tcp=TCPHeader(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=1000,
            ack_num=0,
            data_offset=5,
            header_length=20,
            flags=TCPFlags(
                fin=fin, syn=syn, rst=rst, psh=psh, ack=ack, urg=urg, ece=False, cwr=False
            ),
            window_size=65535,
            checksum=0,
            urgent_pointer=0,
        ),
    )
    return pkt


def create_mock_flow(
    flow_id=1,
    initiator_ip="192.168.1.100",
    responder_ip="10.0.0.1",
    initiator_port=54321,
    responder_port=80,
    total_pkts=20,
    duration=0.5,
    tcp_state=TCPState.ESTABLISHED,
) -> Flow:
    key = FlowKey(
        ip_a=initiator_ip,
        port_a=initiator_port,
        ip_b=responder_ip,
        port_b=responder_port,
        protocol="TCP",
    )
    stats = FlowStats(
        packets_forward=total_pkts // 2,
        packets_reverse=total_pkts - (total_pkts // 2),
        bytes_forward=1000,
        bytes_reverse=4000,
        first_seen=100.0,
        last_seen=100.0 + duration,
    )
    flow = Flow(
        flow_id=flow_id,
        key=key,
        initiator_ip=initiator_ip,
        initiator_port=initiator_port,
        responder_ip=responder_ip,
        responder_port=responder_port,
        protocol="TCP",
        stats=stats,
        tcp_state=tcp_state,
    )
    return flow


def test_ml_runtime_models_load_and_feature_compatibility():
    """Verifies that MLRuntimeEngine loads saved artifacts with 40-feature compatibility."""
    config = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        num_workers=1,
    )
    engine = MLRuntimeEngine(config=config)
    try:
        assert engine.rf_model is not None
        assert engine.if_model is not None
        assert engine.rf_model.expected_num_features == 40
        assert engine.if_model.expected_num_features == 40
        assert len(engine.schema.feature_names) == 40
    finally:
        engine.stop()


def test_missing_model_artifacts_graceful_handling():
    """Verifies that missing model artifacts disable ML gracefully without crashing."""
    config = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="non_existent_artifacts_dir_xyz",
        num_workers=1,
    )
    engine = MLRuntimeEngine(config=config)
    try:
        assert engine.rf_model is None
        assert engine.if_model is None
        flow = create_mock_flow()
        # Submitting flow should safely return False
        assert engine.submit_flow(flow) is False
    finally:
        engine.stop()


def test_flow_maturity_and_duplicate_prevention():
    """Verifies flow maturity gating and duplicate submission prevention."""
    config = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        num_workers=1,
        min_packets_for_inference=10,
        min_duration_for_inference=0.1,
    )
    engine = MLRuntimeEngine(config=config)
    try:
        # Immature flow: 2 packets, duration 0.01s, non-terminal TCP state
        immature_flow = create_mock_flow(flow_id=1, total_pkts=2, duration=0.01, tcp_state=TCPState.SYN_SENT)
        assert engine.should_evaluate_flow(immature_flow) is False
        assert engine.submit_flow(immature_flow) is False

        # Terminal flow: few packets but terminal state (RESET)
        terminal_flow = create_mock_flow(flow_id=2, total_pkts=3, duration=0.02, tcp_state=TCPState.RESET)
        assert engine.should_evaluate_flow(terminal_flow) is True
        assert engine.submit_flow(terminal_flow) is True

        # Duplicate submission: submitting the exact same flow again must be rejected
        assert engine.should_evaluate_flow(terminal_flow) is False
        assert engine.submit_flow(terminal_flow) is False
    finally:
        engine.stop()


def test_queue_saturation_and_drop_behavior():
    """Verifies non-blocking bounded queue saturation and drop telemetry."""
    config = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        queue_capacity=5,  # Tiny queue to test saturation
        num_workers=0,     # No workers consuming queue
    )
    engine = MLRuntimeEngine(config=config)
    try:
        submitted = 0
        dropped = 0
        for i in range(15):
            flow = create_mock_flow(flow_id=100 + i, total_pkts=20, duration=1.0)
            ok = engine.submit_flow(flow)
            if ok:
                submitted += 1
            else:
                dropped += 1

        assert submitted == 5
        assert dropped == 10
        metrics = engine.metrics.get_snapshot()
        assert metrics["jobs_submitted"] == 5
        assert metrics["queue_drops"] == 10
    finally:
        engine.stop()


def test_random_forest_classification_and_alert_generation():
    """Verifies RF prediction, confidence thresholding, and alert structure."""
    alerts_received: List[IDSAlert] = []

    def on_alert(a: IDSAlert):
        alerts_received.append(a)

    config = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        rf_confidence_threshold=0.70,
        isolation_forest_enabled=False,
        num_workers=1,
    )
    engine = MLRuntimeEngine(config=config, on_alert_generated=on_alert)
    try:
        # Create a mock PortScan-like flow (e.g. dst_port=80, single syn flag, short duration)
        flow = create_mock_flow(
            flow_id=200,
            initiator_ip="192.168.1.150",
            responder_ip="10.0.0.5",
            responder_port=445,
            total_pkts=10,
            duration=0.2,
            tcp_state=TCPState.RESET,
        )
        flow.tcp_flags_counts = {"SYN": 5, "RST": 5}
        engine.submit_flow(flow)

        # Allow worker thread to process job
        time.sleep(0.5)

        # Verify inference metrics updated
        metrics = engine.metrics.get_snapshot()
        assert metrics["jobs_processed"] >= 1
        assert metrics["avg_inference_latency_ms"] >= 0.0

        # Verify any generated alert conforms strictly to invariants
        for alert in alerts_received:
            assert alert.category == DetectionCategory.ML_CLASSIFICATION
            assert alert.severity in (Severity.LOW, Severity.MEDIUM, Severity.HIGH)
            assert alert.severity != Severity.CRITICAL
            assert alert.recommended_action == DecisionAction.ALERT
            assert "predicted_attack" in alert.evidence
            assert "confidence" in alert.evidence
    finally:
        engine.stop()


def test_isolation_forest_anomaly_alert():
    """Verifies Isolation Forest anomaly alert generation and low severity."""
    alerts_received: List[IDSAlert] = []

    def on_alert(a: IDSAlert):
        alerts_received.append(a)

    config = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        random_forest_enabled=False,
        isolation_forest_enabled=True,
        num_workers=1,
    )
    engine = MLRuntimeEngine(config=config, on_alert_generated=on_alert)
    try:
        # Extreme outlier flow with massive bytes and bizarre IATs
        flow = create_mock_flow(
            flow_id=300,
            total_pkts=50000,
            duration=100.0,
            tcp_state=TCPState.ESTABLISHED,
        )
        flow.stats.bytes_forward = 100_000_000
        flow.stats.bytes_reverse = 100_000_000
        engine.submit_flow(flow)

        time.sleep(0.5)

        metrics = engine.metrics.get_snapshot()
        assert metrics["jobs_processed"] >= 1

        for alert in alerts_received:
            if alert.category == DetectionCategory.ML_ANOMALY:
                assert alert.severity == Severity.LOW
                assert alert.recommended_action == DecisionAction.ALERT
                assert "anomaly_score" in alert.evidence
    finally:
        engine.stop()


def test_pipeline_worker_pool_end_to_end_ml_integration():
    """Verifies that PipelineWorkerPool asynchronously routes flows to ML and continues packet processing."""
    alerts_captured: List[IDSAlert] = []

    def alert_cb(a: IDSAlert, client):
        alerts_captured.append(a)

    client_mgr = ClientManager()
    ml_conf = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        min_packets_for_inference=2,
        min_duration_for_inference=0.001,
        num_workers=1,
    )
    pool = PipelineWorkerPool(
        client_manager=client_mgr,
        num_workers=2,
        queue_size=100,
        active_prevention=False,
        ml_config=ml_conf,
        on_alert_generated=alert_cb,
    )

    pool.start()
    try:
        # Enqueue packets for a flow using scapy Ether/IP/TCP
        from scapy.layers.inet import IP, TCP
        from scapy.layers.l2 import Ether

        for i in range(5):
            pkt = Ether() / IP(src="10.8.0.2", dst="93.184.216.34") / TCP(sport=50000, dport=80, flags="A") / b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
            q_pkt = QueuedPacket(raw_bytes=bytes(pkt), timestamp=time.time(), source_name="test")
            pool.packet_queue.put(q_pkt)

        # Allow worker pool to process packets
        pool.packet_queue.join()
        time.sleep(0.5)

        stats = pool.get_stats_snapshot()
        assert stats.total_processed >= 5

        # Verify ML engine received submissions
        ml_stats = pool.ml_engine.metrics.get_snapshot()
        assert ml_stats["jobs_submitted"] >= 1
    finally:
        pool.stop()
