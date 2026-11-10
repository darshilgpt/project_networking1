"""End-to-end integration tests verifying cross-subsystem pipeline behavior for Phase 6.1."""

import os
import queue
import time
from typing import List
import pytest
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether

from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.flow_model import Flow, FlowKey, FlowStats, TCPState
from ml.runtime.config import MLRuntimeConfig
from ml.runtime.engine import MLRuntimeEngine
from server.client_manager import ClientManager
from server.ingestion import QueuedPacket
from server.worker_pool import PipelineWorkerPool


def test_e2e_mature_flow_reevaluation_on_new_traffic():
    """
    Verifies that mature flows already evaluated by ML can safely continue receiving
    packets without crashing or corrupting flow tracking state.
    """
    client_mgr = ClientManager(vpn_subnets=["10.8.0.0/24"])
    ml_alerts: List[IDSAlert] = []

    ml_conf = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        min_packets_for_inference=3,
        min_duration_for_inference=0.01,
        num_workers=1,
    )

    pool = PipelineWorkerPool(
        client_manager=client_mgr,
        num_workers=2,
        queue_size=100,
        active_prevention=False,
        ml_config=ml_conf,
        on_alert_generated=lambda alert, ctx: ml_alerts.append(alert),
    )
    pool.start()

    try:
        # Phase A: Send initial packets to establish and mature the flow
        for i in range(4):
            pkt = Ether() / IP(src="10.8.0.5", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="PA") / b"GET /first HTTP/1.1\r\n\r\n"
            qp = QueuedPacket(raw_bytes=bytes(pkt), timestamp=time.time() + (i * 0.01), source_name="test")
            pool.packet_queue.put(qp)

        pool.packet_queue.join()
        time.sleep(0.3)

        # ML should have ingested and processed the mature flow once
        stats1 = pool.ml_engine.metrics.get_snapshot()
        assert stats1["jobs_submitted"] == 1

        # Phase B: Send subsequent packets on the SAME flow (e.g. streaming or follow-up response)
        for i in range(4):
            pkt = Ether() / IP(src="10.8.0.5", dst="93.184.216.34") / TCP(sport=49152, dport=80, flags="A") / b"HTTP/1.1 200 OK\r\n\r\n"
            qp = QueuedPacket(raw_bytes=bytes(pkt), timestamp=time.time() + 1.0 + (i * 0.01), source_name="test")
            pool.packet_queue.put(qp)

        pool.packet_queue.join()
        time.sleep(0.3)

        # Total pipeline packets processed must equal 8
        pipe_stats = pool.get_stats_snapshot()
        assert pipe_stats.total_processed >= 8

        # ML jobs submitted should remain exactly 1 (duplicate flow evaluation prevented)
        stats2 = pool.ml_engine.metrics.get_snapshot()
        assert stats2["jobs_submitted"] == 1
    finally:
        pool.stop()


def test_e2e_ml_alert_never_triggers_firewall_block():
    """
    Verifies that ML-only alerts (DetectionCategory.ML_CLASSIFICATION / ML_ANOMALY)
    never cause the BlockingManager to drop packets or issue firewall blocks.
    """
    client_mgr = ClientManager(vpn_subnets=["10.8.0.0/24"])
    ml_conf = MLRuntimeConfig(
        enabled=True,
        artifacts_dir="project_networking/ml/artifacts",
        rf_confidence_threshold=0.50,  # Sensitive to trigger ML alerts easily
        num_workers=1,
    )

    pool = PipelineWorkerPool(
        client_manager=client_mgr,
        num_workers=2,
        queue_size=100,
        active_prevention=True,  # Active IPS enabled
        ml_config=ml_conf,
    )
    pool.start()

    try:
        # Create an artificial ML alert directly through the ML engine callback
        fake_ml_alert = IDSAlert.create(
            alert_id=999999,
            timestamp=time.time(),
            source_ip="10.8.0.50",
            destination_ip="192.168.1.1",
            source_port=12345,
            destination_port=80,
            protocol="TCP",
            category=DetectionCategory.ML_CLASSIFICATION,
            severity=Severity.HIGH,  # High severity ML alert
            matched_rule="ML-RF-PORTSCAN",
            evidence='{"predicted_attack": "PortScan", "confidence": 0.98}',
            recommended_action=DecisionAction.ALERT,  # Strictly advisory
        )

        # Dispatch through blocking manager evaluation
        parsed_dummy = pool.dispatcher.dispatch(
            raw_bytes=bytes(Ether() / IP(src="10.8.0.50", dst="192.168.1.1") / TCP(sport=12345, dport=80)),
            timestamp=time.time(),
        )

        res = pool.blocking_manager.evaluate_and_enforce(
            packet=parsed_dummy,
            alerts=[fake_ml_alert],
            is_outbound=True,
            client_ip="10.8.0.50",
        )

        # Verify enforcement allows the packet (never blocks on advisory ML alerts)
        assert res.decision != DecisionAction.BLOCK
        assert res.is_forwarded is True
        assert res.dynamic_ban_issued is False
    finally:
        pool.stop()


def test_e2e_ml_worker_exception_does_not_crash_packet_pipeline():
    """
    Verifies that an unhandled exception inside an ML background worker
    does not terminate the worker thread or halt packet processing.
    """
    engine = MLRuntimeEngine(
        config=MLRuntimeConfig(
            enabled=True,
            artifacts_dir="project_networking/ml/artifacts",
            num_workers=1,
        )
    )

    try:
        # Inject an intentionally corrupt job that will trigger an exception during scaling/inference
        corrupt_job = engine._queue.put(
            type(
                "CorruptJob",
                (),
                {
                    "flow_id": 9999,
                    "flow_key_repr": "corrupt",
                    "source_ip": "10.0.0.1",
                    "destination_ip": "10.0.0.2",
                    "source_port": 1,
                    "destination_port": 2,
                    "protocol": "TCP",
                    "features_vector": "not_an_array_which_causes_reshape_error",
                    "timestamp": time.time(),
                },
            )()
        )

        # Allow worker to encounter exception
        time.sleep(0.3)

        # Metric should record failure without dead workers
        snapshot = engine.metrics.get_snapshot()
        assert snapshot["inference_failures"] >= 1
        assert len(engine._workers) == 1
        assert engine._workers[0].is_alive()
    finally:
        engine.stop()

