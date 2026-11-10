"""Dedicated unit and integration tests for Phase 6.2 — Runtime Hardening and ML Telemetry."""

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
from server.dashboard import LiveTerminalDashboard
from server.ingestion import PacketSource, QueuedPacket
from server.worker_pool import PipelineWorkerPool


def make_dummy_flow(flow_id: int = 100, packets: int = 10, bytes_val: int = 1000, duration: float = 1.0) -> Flow:
    """Creates a synthetic flow with configured packet/byte counts."""
    fk = FlowKey(
        ip_a="192.168.1.50",
        port_a=54321,
        ip_b="10.0.0.1",
        port_b=80,
        protocol="TCP",
    )
    fwd_pkts = packets // 2
    rev_pkts = packets - fwd_pkts
    fwd_bytes = bytes_val // 2
    rev_bytes = bytes_val - fwd_bytes

    stats = FlowStats(
        packets_forward=fwd_pkts,
        packets_reverse=rev_pkts,
        bytes_forward=fwd_bytes,
        bytes_reverse=rev_bytes,
        first_seen=1000.0,
        last_seen=1000.0 + duration,
    )
    return Flow(
        flow_id=flow_id,
        key=fk,
        initiator_ip="192.168.1.50",
        initiator_port=54321,
        responder_ip="10.0.0.1",
        responder_port=80,
        protocol="TCP",
        tcp_state=TCPState.ESTABLISHED,
        stats=stats,
    )


class MockPacketSource(PacketSource):
    """Dummy packet source for dashboard testing."""
    def __init__(self, name: str = "MockSource"):
        super().__init__(name=name)

    def start(self, packet_queue=None) -> None:
        pass

    def stop(self) -> None:
        pass

    def get_stats(self):
        return {"total_ingested": 100, "dropped_queue_full": 0}


def test_initial_flow_maturity_evaluation():
    """Verify that a flow meeting initial maturity criteria is evaluated at milestone 0."""
    cfg = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="ml/artifacts",
        min_packets_for_inference=5,
        min_duration_for_inference=0.05,
        packet_milestones=[100, 1000],
    )
    engine = MLRuntimeEngine(config=cfg)
    try:
        # Immature flow: 3 packets, 0.01s duration
        immature = make_dummy_flow(flow_id=1, packets=3, duration=0.01)
        assert not engine.should_evaluate_flow(immature)

        # Mature flow: 10 packets, 0.1s duration
        mature = make_dummy_flow(flow_id=1, packets=10, duration=0.1)
        assert engine.should_evaluate_flow(mature)

        # Submit mature flow
        submitted = engine.submit_flow(mature)
        assert submitted is True

        # Re-submitting before crossing any milestone must be rejected (duplicate prevention)
        assert not engine.should_evaluate_flow(mature)
        assert not engine.submit_flow(mature)
    finally:
        engine.stop()


def test_milestone_100_and_1000_packets_reevaluation():
    """Verify flow is re-evaluated at packet milestone 100 and 1000, but not for intermediate packets."""
    cfg = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="ml/artifacts",
        min_packets_for_inference=5,
        min_duration_for_inference=0.05,
        packet_milestones=[100, 1000],
    )
    engine = MLRuntimeEngine(config=cfg)
    try:
        # 1. Initial maturity submission (20 packets)
        flow = make_dummy_flow(flow_id=2, packets=20, duration=0.5)
        assert engine.submit_flow(flow) is True

        # 2. Intermediate packets (e.g. 50, 99 packets) -> should NOT trigger re-evaluation
        flow.stats.packets_forward = 25
        flow.stats.packets_reverse = 25
        assert not engine.should_evaluate_flow(flow)
        flow.stats.packets_forward = 50
        flow.stats.packets_reverse = 49
        assert not engine.should_evaluate_flow(flow)

        # 3. Cross milestone 100 -> should trigger re-evaluation
        flow.stats.packets_forward = 50
        flow.stats.packets_reverse = 50
        assert engine.should_evaluate_flow(flow)
        assert engine.submit_flow(flow) is True

        # Subsequent packets before 1000 (e.g. 101, 500) -> should NOT trigger re-evaluation
        flow.stats.packets_forward = 51
        flow.stats.packets_reverse = 50
        assert not engine.should_evaluate_flow(flow)
        flow.stats.packets_forward = 250
        flow.stats.packets_reverse = 250
        assert not engine.should_evaluate_flow(flow)

        # 4. Cross milestone 1000 -> should trigger re-evaluation
        flow.stats.packets_forward = 500
        flow.stats.packets_reverse = 500
        assert engine.should_evaluate_flow(flow)
        assert engine.submit_flow(flow) is True

        # Subsequent packets (e.g. 1001, 2000) -> should NOT trigger re-evaluation
        flow.stats.packets_forward = 501
        flow.stats.packets_reverse = 500
        assert not engine.should_evaluate_flow(flow)
    finally:
        engine.stop()


def test_duplicate_prevention_at_same_milestone():
    """Verify that multiple checks or submissions at the exact same milestone are strictly deduplicated."""
    cfg = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="ml/artifacts",
        packet_milestones=[100, 1000],
    )
    engine = MLRuntimeEngine(config=cfg)
    try:
        flow = make_dummy_flow(flow_id=3, packets=100, duration=1.0)
        # Should be eligible
        assert engine.should_evaluate_flow(flow)
        # First submission succeeds
        assert engine.submit_flow(flow) is True
        # Second submission at same state must be rejected immediately
        assert not engine.should_evaluate_flow(flow)
        assert not engine.submit_flow(flow)
    finally:
        engine.stop()


def test_byte_volume_milestone_reevaluation():
    """Verify flow re-evaluation when crossing configurable byte-volume milestones."""
    cfg = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="ml/artifacts",
        packet_milestones=[100, 1000],
        byte_milestones=[500_000, 5_000_000],
    )
    engine = MLRuntimeEngine(config=cfg)
    try:
        # Initial maturity
        flow = make_dummy_flow(flow_id=4, packets=10, bytes_val=50_000, duration=0.5)
        assert engine.submit_flow(flow) is True

        # Intermediate byte volume
        flow.stats.bytes_forward = 200_000
        flow.stats.bytes_reverse = 200_000
        assert not engine.should_evaluate_flow(flow)

        # Cross 500,000 bytes
        flow.stats.bytes_forward = 250_000
        flow.stats.bytes_reverse = 250_000
        assert engine.should_evaluate_flow(flow)
        assert engine.submit_flow(flow) is True

        # Duplicate at same byte milestone
        assert not engine.should_evaluate_flow(flow)

        # Cross 5,000,000 bytes
        flow.stats.bytes_forward = 2_500_001
        flow.stats.bytes_reverse = 2_500_000
        assert engine.should_evaluate_flow(flow)
        assert engine.submit_flow(flow) is True
    finally:
        engine.stop()


def test_non_blocking_queue_under_milestone_bursts():
    """Verify that submitting to a saturated queue drops gracefully without blocking packet capture."""
    cfg = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="ml/artifacts",
        queue_capacity=2,
        num_workers=0,  # No workers running so queue stays full
    )
    engine = MLRuntimeEngine(config=cfg)
    # Stop workers if any started
    engine._is_running = True
    try:
        flow1 = make_dummy_flow(flow_id=10, packets=10)
        flow2 = make_dummy_flow(flow_id=11, packets=10)
        flow3 = make_dummy_flow(flow_id=12, packets=10)

        assert engine.submit_flow(flow1) is True
        assert engine.submit_flow(flow2) is True
        # Queue capacity is 2; 3rd submission must drop without blocking
        t0 = time.perf_counter()
        res = engine.submit_flow(flow3)
        elapsed = time.perf_counter() - t0

        assert res is False
        assert elapsed < 0.05  # Instant non-blocking return
        assert engine.metrics.queue_drops >= 1
    finally:
        engine.stop()


def test_dashboard_ml_telemetry_rendering():
    """Verify that LiveTerminalDashboard renders ML telemetry panel accurately when enabled and disabled."""
    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    ps = MockPacketSource()

    dash = LiveTerminalDashboard(
        worker_pool=wp,
        client_manager=cm,
        packet_source=ps,
        enable_interactive=False,
    )

    try:
        # 1. Render when ML engine is active
        wp.ml_engine.metrics.record_job_submitted()
        wp.ml_engine.metrics.record_job_processed(latency_ms=1.23)
        wp.ml_engine.metrics.record_rf_classification()

        table = dash.build_ml_telemetry_table()
        assert table is not None
        assert table.title is not None
        assert "MACHINE LEARNING RUNTIME TELEMETRY" in str(table.title)

        # Full layout render
        layout = dash.render_dashboard()
        assert layout is not None

        # 2. Render when ML engine is disabled
        wp.ml_engine.config.enabled = False
        table_disabled = dash.build_ml_telemetry_table()
        assert table_disabled is not None
        # Check rows contain DISABLED
        rows_text = str([row for row in table_disabled.columns[1]._cells])
        assert "DISABLED" in rows_text or "UNAVAILABLE" in rows_text
    finally:
        dash.stop()
        wp.stop()


def test_graceful_shutdown_draining_and_timeout():
    """Verify graceful shutdown drains pending queue items and halts workers within timeout."""
    cfg = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="ml/artifacts",
        num_workers=2,
    )
    engine = MLRuntimeEngine(config=cfg)

    # Submit a few flows
    for i in range(5):
        flow = make_dummy_flow(flow_id=100 + i, packets=10)
        engine.submit_flow(flow)

    # Stop with bounded timeout
    t0 = time.perf_counter()
    engine.stop(timeout=1.0)
    elapsed = time.perf_counter() - t0

    assert elapsed < 1.5  # Bounded timeout respected
    assert not engine._is_running
    assert len(engine._workers) == 0

    # New submissions must be rejected when stopped
    new_flow = make_dummy_flow(flow_id=999, packets=10)
    assert not engine.submit_flow(new_flow)


def test_worker_exception_resilience():
    """Verify that exceptions during feature scaling or model prediction do not crash workers."""
    cfg = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="ml/artifacts",
        num_workers=1,
    )
    engine = MLRuntimeEngine(config=cfg)
    try:
        # Create a malformed job with corrupt feature vector that causes a calculation error
        job = MLInferenceJob(
            flow_id=777,
            flow_key_repr="test",
            source_ip="192.168.1.1",
            destination_ip="10.0.0.1",
            source_port=1234,
            destination_port=80,
            protocol="TCP",
            features_vector="invalid_string_vector",  # Will raise AttributeError on .reshape()
            timestamp=time.time(),
        )

        engine._queue.put_nowait(job)
        time.sleep(0.3)

        # Worker should have caught exception, incremented failure count, and remained alive
        assert engine.metrics.inference_failures >= 1
        assert engine._workers[0].is_alive()
    finally:
        engine.stop()
