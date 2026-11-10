"""Phase 6.3 — Live Traffic, Attack Simulation & Firewall Integration Validation Suite."""

import os
import time
from typing import List
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.dns import DNS, DNSQR

from dpi.dpi_engine import DPIEngine
from ids.ids_engine import IDSEngine
from ips.blocking_manager import BlockingManager
from ips.windows_firewall_enforcer import WindowsFirewallEnforcer
from ml.data.feature_mapping import AttackCategory
from ml.features.feature_schema import FeatureSchema
from ml.runtime.config import MLInferenceJob, MLRuntimeConfig
from ml.runtime.engine import MLRuntimeEngine
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.flow_model import Flow, FlowKey, FlowStats, TCPState
from parser.packet_dispatcher import PacketDispatcher
from server.client_manager import ClientManager
from server.ingestion import QueuedPacket
from server.worker_pool import PipelineWorkerPool


def test_scenario_tcp_port_scan_simulation():
    """Scenario 1: TCP Port Scanning simulation through dispatcher, DPI, and IDS."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    src = "10.10.0.50"
    dst = "10.10.0.1"
    base_time = 1000.0
    alerts_found = []

    for port in range(1, 20):
        pkt_bytes = bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=40000 + port, dport=port, flags="S"))
        pkt = dispatcher.dispatch(pkt_bytes, timestamp=base_time + (port * 0.05))
        dpi_res = dpi_eng.inspect(pkt)
        alerts = ids_eng.evaluate(pkt, dpi_res)
        for a in alerts:
            if a.category in (DetectionCategory.PORT_SCAN, DetectionCategory.SYN_SCAN, DetectionCategory.RECONNAISSANCE):
                alerts_found.append(a)

    assert len(alerts_found) >= 1
    assert alerts_found[0].source_ip == src
    assert alerts_found[0].severity in (Severity.MEDIUM, Severity.HIGH)


def test_scenario_controlled_syn_flood():
    """Scenario 2: Controlled SYN Flood rate burst simulation."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    src = "10.10.0.55"
    dst = "10.10.0.1"
    base_time = 2000.0
    syn_alerts = []

    for i in range(35):
        pkt_bytes = bytes(Ether() / IP(src=src, dst=dst) / TCP(sport=30000 + i, dport=80, flags="S"))
        pkt = dispatcher.dispatch(pkt_bytes, timestamp=base_time + (i * 0.01))
        dpi_res = dpi_eng.inspect(pkt)
        alerts = ids_eng.evaluate(pkt, dpi_res)
        for a in alerts:
            if a.category == DetectionCategory.SYN_FLOOD:
                syn_alerts.append(a)

    assert len(syn_alerts) >= 1
    assert syn_alerts[0].severity in (Severity.HIGH, Severity.CRITICAL)


def test_scenario_http_sql_injection():
    """Scenario 3: HTTP SQL Injection attack simulation."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    payload = b"GET /search?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1\r\nHost: target.local\r\n\r\n"
    pkt_bytes = bytes(Ether() / IP(src="10.10.0.60", dst="10.10.0.1") / TCP(sport=51000, dport=80, flags="PA", seq=1) / payload)
    pkt = dispatcher.dispatch(pkt_bytes)
    dpi_res = dpi_eng.inspect(pkt)
    alerts = ids_eng.evaluate(pkt, dpi_res)

    sqli_alerts = [a for a in alerts if a.category == DetectionCategory.SQL_INJECTION]
    assert len(sqli_alerts) >= 1
    assert sqli_alerts[0].severity == Severity.HIGH
    assert "UNION_SELECT" in sqli_alerts[0].matched_rule


def test_scenario_http_xss():
    """Scenario 4: HTTP Cross-Site Scripting attack simulation."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    payload = b"GET /profile?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1\r\nHost: target.local\r\n\r\n"
    pkt_bytes = bytes(Ether() / IP(src="10.10.0.61", dst="10.10.0.1") / TCP(sport=51001, dport=80, flags="PA", seq=1) / payload)
    pkt = dispatcher.dispatch(pkt_bytes)
    dpi_res = dpi_eng.inspect(pkt)
    alerts = ids_eng.evaluate(pkt, dpi_res)

    xss_alerts = [a for a in alerts if a.category == DetectionCategory.XSS]
    assert len(xss_alerts) >= 1
    assert xss_alerts[0].severity == Severity.HIGH


def test_scenario_directory_traversal():
    """Scenario 5: HTTP Directory / Path Traversal simulation."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    payload = b"GET /download?file=..%2f..%2f..%2fetc%2fpasswd HTTP/1.1\r\nHost: target.local\r\n\r\n"
    pkt_bytes = bytes(Ether() / IP(src="10.10.0.62", dst="10.10.0.1") / TCP(sport=51002, dport=80, flags="PA", seq=1) / payload)
    pkt = dispatcher.dispatch(pkt_bytes)
    dpi_res = dpi_eng.inspect(pkt)
    alerts = ids_eng.evaluate(pkt, dpi_res)

    trav_alerts = [a for a in alerts if a.category == DetectionCategory.PATH_TRAVERSAL]
    assert len(trav_alerts) >= 1
    assert trav_alerts[0].severity == Severity.HIGH


def test_scenario_dns_anomalies_and_tunneling():
    """Scenario 6: High-entropy DNS Tunneling simulation."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    tunneling_query = "a8f9c7e2b1d4f6a9c8b7e6d5c4b3a2.exfil.data.attacker-c2.net"
    scapy_dns = DNS(rd=1, qd=DNSQR(qname=tunneling_query, qtype="A"))
    pkt_bytes = bytes(Ether() / IP(src="10.10.0.63", dst="10.10.0.1") / UDP(sport=53000, dport=53) / scapy_dns)
    pkt = dispatcher.dispatch(pkt_bytes)
    dpi_res = dpi_eng.inspect(pkt)
    alerts = ids_eng.evaluate(pkt, dpi_res)

    tunnel_alerts = [
        a for a in alerts
        if a.category in (DetectionCategory.DNS_TUNNELING, DetectionCategory.SUSPICIOUS_DNS)
    ]
    assert len(tunnel_alerts) >= 1


def test_scenario_threat_intelligence_matching():
    """Scenario 7: Threat Intelligence IP/domain IOC matching."""
    from ids.threat_intel import ThreatIndicator

    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    # IP match with pre-seeded Cobalt Strike C2 IP: 198.51.100.23
    pkt_bytes_ip = bytes(Ether() / IP(src="198.51.100.23", dst="10.10.0.1") / TCP(sport=50000, dport=80, flags="S"))
    pkt_ip = dispatcher.dispatch(pkt_bytes_ip)
    dpi_res_ip = dpi_eng.inspect(pkt_ip)
    alerts_ip = ids_eng.evaluate(pkt_ip, dpi_res_ip)
    cats_ip = [a.category for a in alerts_ip]
    assert (
        DetectionCategory.MALICIOUS_IP in cats_ip
        or DetectionCategory.THREAT_REPUTATION in cats_ip
    )

    # Domain match
    ind_dom = ThreatIndicator(
        indicator="malicious-c2.org",
        ioc_type="DOMAIN",
        category="C2",
        severity=Severity.HIGH,
        confidence=1.0,
        source="test_ioc",
        description="CobaltStrike Domain",
    )
    ids_eng.threat_intel_engine.domain_matcher.load_indicators([ind_dom])

    scapy_dns = DNS(rd=1, qd=DNSQR(qname="malicious-c2.org", qtype="A"))
    pkt_bytes_dom = bytes(Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src="10.10.0.64", dst="10.10.0.1") / UDP(sport=53001, dport=53) / scapy_dns)
    pkt_dom = dispatcher.dispatch(pkt_bytes_dom)
    dpi_res_dom = dpi_eng.inspect(pkt_dom)
    alerts_dom = ids_eng.evaluate(pkt_dom, dpi_res_dom)
    cats_dom = [a.category for a in alerts_dom]
    assert (
        DetectionCategory.MALICIOUS_DOMAIN in cats_dom
        or DetectionCategory.THREAT_REPUTATION in cats_dom
        or DetectionCategory.SUSPICIOUS_DNS in cats_dom
    )


def test_scenario_benign_traffic_no_false_positives():
    """Verify clean benign HTTP traffic does not trigger malicious attack alerts."""
    dispatcher = PacketDispatcher()
    dpi_eng = DPIEngine()
    ids_eng = IDSEngine()

    payload = b"GET /shop?category=select+items+from+catalog&order=relevance HTTP/1.1\r\nHost: target.local\r\n\r\n"
    pkt_bytes = bytes(Ether() / IP(src="10.10.0.70", dst="10.10.0.1") / TCP(sport=49999, dport=80, flags="PA", seq=1) / payload)
    pkt = dispatcher.dispatch(pkt_bytes)
    dpi_res = dpi_eng.inspect(pkt)
    alerts = ids_eng.evaluate(pkt, dpi_res)

    attack_alerts = [
        a for a in alerts if a.category in (
            DetectionCategory.SQL_INJECTION,
            DetectionCategory.XSS,
            DetectionCategory.PATH_TRAVERSAL,
            DetectionCategory.COMMAND_INJECTION,
            DetectionCategory.PORT_SCAN,
            DetectionCategory.SYN_FLOOD,
            DetectionCategory.DNS_TUNNELING,
        )
    ]
    assert len(attack_alerts) == 0


def test_scenario_firewall_active_and_ml_isolation():
    """Scenario 8 & 9 + Firewall Validation: Verify active firewall execution vs ML alert safety."""
    dispatcher = PacketDispatcher()
    calls = []

    def mock_executor(cmd):
        calls.append(cmd)
        return 0, "Ok", ""

    enforcer = WindowsFirewallEnforcer(is_admin=True, command_executor=mock_executor, auto_cleanup_stale=False)
    bm_active = BlockingManager(active_prevention=True, firewall_enforcer=enforcer)

    # Legitimate connection packet (SYN)
    pkt_bytes = bytes(Ether() / IP(src="10.10.0.90", dst="10.10.0.1") / TCP(sport=50000, dport=80, flags="S"))
    pkt = dispatcher.dispatch(pkt_bytes)

    # 1. Classical BLOCK alert -> rules installed
    block_alert = IDSAlert(
        alert_id=5001,
        timestamp=time.time(),
        datetime_str="12:00:00",
        source_ip="10.10.0.90",
        destination_ip="10.10.0.1",
        source_port=50000,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.SQL_INJECTION,
        severity=Severity.HIGH,
        matched_rule="SQLi Block Rule",
        evidence="admin' OR '1'='1",
        recommended_action=DecisionAction.BLOCK,
        packet_id=1,
    )
    res_block = bm_active.evaluate_and_enforce(packet=pkt, alerts=[block_alert], client_ip="10.10.0.90")
    assert res_block.effective_action == "ACTUAL_BLOCK"
    assert not res_block.is_forwarded
    assert len(calls) == 2  # Inbound and Outbound rule commands

    # 2. ML Alert on clean IP -> NO firewall commands invoked
    calls.clear()
    clean_pkt_bytes = bytes(Ether() / IP(src="10.10.0.91", dst="10.10.0.1") / TCP(sport=50001, dport=80, flags="S"))
    clean_pkt = dispatcher.dispatch(clean_pkt_bytes)
    ml_alert = IDSAlert(
        alert_id=5002,
        timestamp=time.time(),
        datetime_str="12:00:00",
        source_ip="10.10.0.91",
        destination_ip="10.10.0.1",
        source_port=50001,
        destination_port=80,
        protocol="TCP",
        category=DetectionCategory.ML_CLASSIFICATION,
        severity=Severity.HIGH,
        matched_rule="ML Random Forest Attack: PortScan",
        evidence="Confidence: 0.94",
        recommended_action=DecisionAction.ALERT,
        packet_id=2,
    )
    res_ml = bm_active.evaluate_and_enforce(packet=clean_pkt, alerts=[ml_alert], client_ip="10.10.0.91")
    assert res_ml.effective_action == "ALERT"
    assert res_ml.decision == DecisionAction.ALERT
    assert res_ml.is_forwarded is True
    assert len(calls) == 0  # Zero firewall rules created by ML alert
