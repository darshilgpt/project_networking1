"""Phase 6.4 — Performance, Resource Profiling and Stress Testing Suite."""

import time
from typing import List
import psutil
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP
from scapy.layers.dns import DNS, DNSQR

from dpi.dpi_engine import DPIEngine
from flow.flow_manager import FlowManager
from flow.flow_tracker import FlowTracker
from ids.ids_engine import IDSEngine
from ml.runtime.config import MLRuntimeConfig
from ml.runtime.engine import MLRuntimeEngine
from models.flow_model import Flow, FlowKey, FlowStats, TCPState
from parser.packet_dispatcher import PacketDispatcher


def test_packet_processing_throughput_10k():
    """Validates that 10,000 synthetic packets process through the full DPI+IDS pipeline at >= 1,000 pkts/sec."""
    dispatcher = PacketDispatcher()
    flow_mgr = FlowManager()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    raw_pkt = bytes(
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src="192.168.1.10", dst="10.0.0.1")
        / TCP(sport=50000, dport=80, flags="PA")
        / b"GET /index.html HTTP/1.1\r\nHost: test.local\r\n\r\n"
    )

    t0 = time.perf_counter()
    N = 10000
    for _ in range(N):
        p = dispatcher.dispatch(raw_pkt)
        assert p is not None
        flow_mgr.process_packet(p)
        dpi_res = dpi_eng.inspect(p)
        ids_eng.evaluate(p, dpi_res)
    elapsed = time.perf_counter() - t0
    throughput = N / elapsed

    assert throughput >= 1000.0, f"Expected >= 1000 pps, got {throughput:.1f} pps"


def test_cpu_and_memory_bounded_under_50k_packets():
    """Validates that memory consumption remains strictly bounded and delta is <= 5MB under 50k packets."""
    proc = psutil.Process()
    mem_before = proc.memory_info().rss / (1024 * 1024)

    dispatcher = PacketDispatcher()
    flow_mgr = FlowManager()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    http_pkt = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.10", dst="10.0.0.1") / TCP(sport=50001, dport=80, flags="PA") / b"GET /data HTTP/1.1\r\nHost: test.local\r\n\r\n")
    dns_pkt = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.11", dst="10.0.0.1") / TCP(sport=50002, dport=53, flags="PA") / bytes(DNS(rd=1, qd=DNSQR(qname="test.org", qtype="A"))))
    syn_pkt = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.12", dst="10.0.0.1") / TCP(sport=50003, dport=443, flags="S"))

    packets = [http_pkt, dns_pkt, syn_pkt]
    N = 50000
    for i in range(N):
        p = dispatcher.dispatch(packets[i % 3])
        assert p is not None
        flow_mgr.process_packet(p)
        dpi_res = dpi_eng.inspect(p)
        ids_eng.evaluate(p, dpi_res)

    mem_after = proc.memory_info().rss / (1024 * 1024)
    mem_delta = mem_after - mem_before
    # Delta should remain under 5.0 MB due to internal state reuse and bounded dicts
    assert mem_delta < 5.0, f"Memory leak suspected: delta was {mem_delta:.2f} MB"


def test_concurrent_flows_bounded_memory_capacity():
    """Validates that FlowTracker strictly enforces max_flows limit without unbounded growth."""
    tracker = FlowTracker(max_flows=500)
    flow_mgr = FlowManager(tracker=tracker)
    dispatcher = PacketDispatcher()

    # Generate 2,500 distinct connection flows
    for i in range(2500):
        src = f"10.{(i >> 8) & 255}.{i & 255}.1"
        pkt_bytes = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src=src, dst="10.0.0.1") / TCP(sport=10000 + (i % 50000), dport=80, flags="S"))
        p = dispatcher.dispatch(pkt_bytes)
        assert p is not None
        flow_mgr.process_packet(p)

    assert tracker.active_flow_count <= tracker.max_flows
    assert tracker.active_flow_count == 500


def test_ml_runtime_nonblocking_queue_and_latency():
    """Validates that ML job submission is non-blocking (sub-millisecond) and processed asynchronously."""
    cfg = MLRuntimeConfig(enabled=True, num_workers=2, queue_capacity=100)
    engine = MLRuntimeEngine(config=cfg)

    try:
        fk = FlowKey(ip_a="10.0.0.10", port_a=50000, ip_b="10.0.0.1", port_b=80, protocol="TCP")
        stats = FlowStats(packets_forward=50, packets_reverse=50, bytes_forward=5000, bytes_reverse=5000, first_seen=1000.0, last_seen=1001.0)
        
        # Rapid burst submission
        t0 = time.perf_counter()
        submitted_count = 0
        for i in range(50):
            flow = Flow(flow_id=100 + i, key=fk, initiator_ip="10.0.0.10", initiator_port=50000, responder_ip="10.0.0.1", responder_port=80, protocol="TCP", tcp_state=TCPState.ESTABLISHED, stats=stats)
            if engine.submit_flow(flow):
                submitted_count += 1
        elapsed = time.perf_counter() - t0
        time_per_submit = (elapsed * 1000) / 50

        # Submitting to queue must be sub-millisecond per flow
        assert time_per_submit < 1.0, f"Submission blocked packet capture: {time_per_submit:.3f} ms/submit"
        assert submitted_count == 50

        # Wait for workers to process jobs
        deadline = time.time() + 10.0
        while not engine._queue.empty() and time.time() < deadline:
            time.sleep(0.05)

        snap = engine.metrics.get_snapshot()
        assert snap["jobs_submitted"] == 50
        assert snap["jobs_processed"] > 0
        assert snap["inference_failures"] == 0
    finally:
        engine.stop(timeout=1.0)


def test_reliability_pipeline_continues_after_malformed_packets():
    """Validates that malformed and corrupted raw packets do not disrupt subsequent processing."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    # Corrupt payloads
    corrupt_packets = [
        b"\x00\x01\x02",
        b"",
        b"\xff" * 20,
        b"MALFORMED_HEADER_DATA_12345",
    ]

    for raw in corrupt_packets:
        p = dispatcher.dispatch(raw)
        # Dispatcher returns ParsedPacket or None; should never raise uncaught exception
        if p:
            dpi_res = dpi_eng.inspect(p)
            ids_eng.evaluate(p, dpi_res)

    # Valid packet arrives immediately after
    valid_raw = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="S"))
    p_valid = dispatcher.dispatch(valid_raw)
    assert p_valid is not None
    assert p_valid.ipv4 is not None
    assert p_valid.ipv4.src_ip == "10.0.0.1"

