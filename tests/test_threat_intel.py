"""Unit tests for Phase 4.3 Threat Intelligence and Reputation Detection.

Covers:
1. IPv4 exact match.
2. IPv6 exact match.
3. IPv4 CIDR match.
4. IPv6 CIDR match.
5. Non-matching IP.
6. Exact malicious domain.
7. Malicious subdomain matching (bounded).
8. Unrelated domain with similar suffix (negative control).
9. HTTP Host metadata matching.
10. TLS SNI metadata matching.
11. DNS query name matching.
12. Invalid feed entries handling without crashing.
13. Atomic feed reload.
14. Expired indicators handling.
15. Allowlist precedence.
16. Duplicate alert cooldown.
17. Cache limits and expiry.
18. Detection-only zero-BLOCK / no-CRITICAL invariant.
"""

from __future__ import annotations

import json
import os
import tempfile
import time
import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether

from dpi.dns_inspector import DNSInspector
from dpi.http_inspector import HTTPMetadata
from dpi.tls_inspector import TLSMetadata
from ids.ids_engine import IDSEngine
from ids.threat_intel import (
    DomainReputationMatcher,
    FeedManager,
    IPReputationMatcher,
    ThreatIndicator,
    ThreatIntelEngine,
    normalize_domain,
    normalize_ip,
)
from ips.decision_engine import DecisionEngine
from models.alert_model import DecisionAction, DetectionCategory, DPIResult, IDSAlert, Severity
from models.packet_models import ParsedPacket
from parser.packet_dispatcher import PacketDispatcher


def create_mock_packet(
    src_ip: str = "192.168.1.100",
    dst_ip: str = "8.8.8.8",
    src_port: int = 54321,
    dst_port: int = 80,
    is_ipv6: bool = False,
) -> ParsedPacket:
    """Helper to synthesize a ParsedPacket."""
    dispatcher = PacketDispatcher()
    if is_ipv6:
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IPv6(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
    else:
        pkt = Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb") / IP(src=src_ip, dst=dst_ip) / TCP(sport=src_port, dport=dst_port)
    parsed = dispatcher.dispatch(bytes(pkt))
    assert parsed is not None
    return parsed


# --- 1. IP Matching Tests (IPv4, IPv6, CIDR, Non-matching) ---
def test_threat_intel_ip_matches():
    engine = ThreatIntelEngine()

    # 1. IPv4 Exact match
    ind_v4 = engine.check_ip("198.51.100.23")
    assert ind_v4 is not None
    assert ind_v4.ioc_type == "IPv4"
    assert ind_v4.category == "C2"

    # 2. IPv6 Exact match
    ind_v6 = engine.check_ip("2001:db8:dead:beef::1")
    assert ind_v6 is not None
    assert ind_v6.ioc_type == "IPv6"
    assert ind_v6.category == "C2"

    # 3. IPv4 CIDR match (198.51.100.0/24)
    ind_v4_cidr = engine.check_ip("198.51.100.45")
    assert ind_v4_cidr is not None
    assert ind_v4_cidr.ioc_type == "IPv4_CIDR"
    assert ind_v4_cidr.category == "BOTNET"

    # 4. IPv6 CIDR match (2001:db8:bad::/48)
    ind_v6_cidr = engine.check_ip("2001:db8:bad:ffff::99")
    assert ind_v6_cidr is not None
    assert ind_v6_cidr.ioc_type == "IPv6_CIDR"

    # 5. Non-matching IP
    assert engine.check_ip("8.8.4.4") is None
    assert engine.check_ip("2001:4860:4860::8888") is None


# --- 2. Domain Matching Tests ---
def test_threat_intel_domain_matches():
    engine = ThreatIntelEngine()

    # 6. Exact malicious domain
    ind_exact = engine.check_domain("evil-c2-server.com")
    assert ind_exact is not None
    assert ind_exact.indicator == "evil-c2-server.com"
    assert ind_exact.category == "C2"

    # 7. Malicious subdomain matching (bounded)
    ind_sub = engine.check_domain("beacon.stage1.evil-c2-server.com")
    assert ind_sub is not None
    assert ind_sub.indicator == "evil-c2-server.com"

    # 8. Unrelated domain with similar suffix (negative control)
    # 'notevil-c2-server.com' or 'evil-c2-server.com.legit.org' MUST NOT match
    assert engine.check_domain("notevil-c2-server.com") is None
    assert engine.check_domain("fake-evil-c2-server.com") is None
    assert engine.check_domain("evil-c2-server.com.legitimate.com") is None


# --- 3. Protocol Metadata Matching (HTTP Host, TLS SNI, DNS Query) ---
def test_threat_intel_protocol_metadata_matching():
    engine = ThreatIntelEngine()
    pkt = create_mock_packet(src_ip="192.168.1.50", dst_ip="1.1.1.1")

    # 9. HTTP Host matching
    http_meta = HTTPMetadata(is_request=True, method="GET", uri="/login", host="phishing-bank-login.xyz:8080")
    dpi_http = DPIResult(flow_id=1, protocol="HTTP", metadata={"http": http_meta})
    alerts_http = engine.evaluate_packet(pkt, dpi_http, lambda: 1, time.time())
    assert len(alerts_http) == 1
    assert alerts_http[0].category == DetectionCategory.MALICIOUS_DOMAIN
    assert "HTTP Host" in alerts_http[0].evidence
    assert alerts_http[0].recommended_action == DecisionAction.ALERT

    # 10. TLS SNI matching
    tls_meta = TLSMetadata(
        content_type_code=22,
        content_type_name="Handshake",
        record_version_code=0x0303,
        record_version_name="TLS 1.2",
        record_length=120,
        is_handshake=True,
        handshake_type="ClientHello",
        sni="evil-c2-server.com",
    )
    dpi_tls = DPIResult(flow_id=2, protocol="TLS", metadata={"tls": tls_meta})
    alerts_tls = engine.evaluate_packet(pkt, dpi_tls, lambda: 2, time.time() + 1.0)
    assert len(alerts_tls) == 1
    assert alerts_tls[0].category == DetectionCategory.MALICIOUS_DOMAIN
    assert "TLS SNI" in alerts_tls[0].evidence

    # 11. DNS Query matching
    scapy_dns = DNS(id=0x1111, qd=DNSQR(qname="malicious-payload-drop.buzz", qtype="A"))
    dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)
    dpi_dns = DPIResult(flow_id=3, protocol="DNS", metadata={"dns": dns_meta})
    alerts_dns = engine.evaluate_packet(pkt, dpi_dns, lambda: 3, time.time() + 2.0)
    assert len(alerts_dns) == 1
    assert alerts_dns[0].category == DetectionCategory.MALICIOUS_DOMAIN
    assert "DNS Query" in alerts_dns[0].evidence


# --- 4. Invalid Feed Entries & Safe Atomic Reload ---
def test_feed_manager_invalid_entries_and_safe_reload():
    mgr = FeedManager()
    engine = ThreatIntelEngine()

    with tempfile.TemporaryDirectory() as tmpdir:
        # 12. Invalid Feed file with mixed malformed entries
        csv_path = os.path.join(tmpdir, "mixed_feed.csv")
        with open(csv_path, "w", encoding="utf-8") as f:
            f.write("indicator,category,severity,description\n")
            f.write("203.0.113.99,SCANNER,HIGH,Valid IP\n")
            f.write("not-an-ip-or-domain,MALWARE,HIGH,Invalid indicator\n")
            f.write("999.999.999.999,SCANNER,HIGH,Malformed IPv4\n")
            f.write("valid-feed-threat.org,PHISHING,HIGH,Valid domain\n")
            f.write("192.168.250.0/35,BOTNET,HIGH,Invalid CIDR\n")
            f.write("192.168.250.0/24,BOTNET,MEDIUM,Valid CIDR\n")

        # Must parse valid without crashing
        inds = mgr.parse_csv(csv_path)
        assert len(inds) == 3
        assert any(i.indicator == "203.0.113.99" for i in inds)
        assert any(i.indicator == "valid-feed-threat.org" for i in inds)
        assert any(i.indicator == "192.168.250.0/24" for i in inds)

        # 13. Safe Atomic Reload: loading malformed file does not break existing database
        success = engine.load_feed_file(csv_path)
        assert success is True
        assert engine.check_ip("203.0.113.99") is not None
        assert engine.check_domain("valid-feed-threat.org") is not None

        # Non-existent file fails gracefully
        assert engine.load_feed_file(os.path.join(tmpdir, "missing.json")) is False


# --- 5. Expired Indicators Handling ---
def test_threat_intel_expired_indicators():
    now = time.time()
    ind_expired = ThreatIndicator(
        indicator="203.0.113.150",
        ioc_type="IPv4",
        category="MALWARE",
        expires_at=now - 10.0,  # Expired 10s ago
    )
    ind_active = ThreatIndicator(
        indicator="203.0.113.151",
        ioc_type="IPv4",
        category="MALWARE",
        expires_at=now + 3600.0,  # Active for 1 hour
    )

    ip_matcher = IPReputationMatcher()
    ip_matcher.load_indicators([ind_expired, ind_active])

    assert ip_matcher.match("203.0.113.150", now=now) is None
    assert ip_matcher.match("203.0.113.151", now=now) is not None


# --- 6. Allowlist Precedence ---
def test_threat_intel_allowlist_precedence():
    engine = ThreatIntelEngine()

    # Seed malicious IP exists
    assert engine.check_ip("198.51.100.23") is not None

    # Add to allowlist
    engine.add_to_allowlist("198.51.100.23")
    # Must immediately return None
    assert engine.check_ip("198.51.100.23") is None

    # Allowlist domain
    assert engine.check_domain("evil-c2-server.com") is not None
    engine.add_to_allowlist("evil-c2-server.com")
    assert engine.check_domain("evil-c2-server.com") is None
    assert engine.check_domain("sub.evil-c2-server.com") is None


# --- 7. Duplicate Alert Cooldown ---
def test_threat_intel_alert_cooldown():
    engine = ThreatIntelEngine()
    now = time.time()
    pkt = create_mock_packet(src_ip="198.51.100.23", dst_ip="8.8.8.8")

    # First packet: generates alert
    alerts1 = engine.evaluate_packet(pkt, None, lambda: 1, now=now)
    assert len(alerts1) == 1
    assert alerts1[0].category == DetectionCategory.MALICIOUS_IP

    # Second packet immediately after: suppressed by cooldown
    alerts2 = engine.evaluate_packet(pkt, None, lambda: 2, now=now + 1.0)
    assert len(alerts2) == 0

    # Advance past 60s cooldown: generates alert again
    alerts3 = engine.evaluate_packet(pkt, None, lambda: 3, now=now + 65.0)
    assert len(alerts3) == 1


# --- 8. Cache Limits and Expiry ---
def test_bounded_ttl_cache_limits():
    from ids.threat_intel.common import BoundedTTLCache
    cache = BoundedTTLCache(max_size=50, ttl_seconds=2.0)
    now = 1000.0

    for i in range(60):
        cache.set(f"k_{i}", f"v_{i}", now=now)

    assert len(cache) <= 50
    assert cache.get("k_0", now=now) is None  # Evicted
    assert cache.get("k_59", now=now) == "v_59"

    # Expire
    assert cache.get("k_59", now=now + 3.0) is None


# --- 9. Detection-Only Zero-BLOCK Invariant ---
def test_threat_intel_detection_only_never_triggers_block():
    ids_engine = IDSEngine()
    decision_engine = DecisionEngine()

    pkt = create_mock_packet(src_ip="45.154.255.99", dst_ip="8.8.8.8")  # Known malware delivery host
    alerts = ids_engine.evaluate(pkt, None)

    assert len(alerts) >= 1
    ti_alerts = [a for a in alerts if a.category in (DetectionCategory.MALICIOUS_IP, DetectionCategory.MALICIOUS_DOMAIN)]
    assert len(ti_alerts) >= 1

    for a in ti_alerts:
        assert a.recommended_action == DecisionAction.ALERT
        assert a.severity != Severity.CRITICAL
        action = decision_engine.decide(packet=pkt, dpi_result=None, alerts=[a])
        assert action == DecisionAction.ALERT
        assert action != DecisionAction.BLOCK


# --- 10. Startup Feed Configuration Tests ---
def test_ids_engine_configured_feeds_startup():
    """Verifies that configured feeds load during normal IDSEngine initialization,
    supporting multiple feeds, no-feed startup, and malformed feeds without crashing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Feed 1: CSV
        f1_path = os.path.join(tmpdir, "feed1.csv")
        with open(f1_path, "w", encoding="utf-8") as f:
            f.write("indicator,category,severity,description\n")
            f.write("198.51.100.222,C2,HIGH,Configured Feed 1 C2\n")

        # Feed 2: JSON
        f2_path = os.path.join(tmpdir, "feed2.json")
        with open(f2_path, "w", encoding="utf-8") as f:
            json.dump([{"indicator": "configured-feed-domain.org", "category": "PHISHING", "severity": "HIGH"}], f)

        # Feed 3: Malformed file
        f3_path = os.path.join(tmpdir, "malformed.json")
        with open(f3_path, "w", encoding="utf-8") as f:
            f.write("{ invalid json")

        # Missing file
        missing_path = os.path.join(tmpdir, "does_not_exist.txt")

        # 1. Multiple configured feeds load correctly and malformed feeds do not prevent startup
        engine = IDSEngine(threat_intel_feeds=[f1_path, f2_path, f3_path, missing_path])

        # Feed 1 IP loaded
        assert engine.threat_intel_engine.check_ip("198.51.100.222") is not None
        # Feed 2 Domain loaded
        assert engine.threat_intel_engine.check_domain("configured-feed-domain.org") is not None
        # Existing seed intelligence remains available
        assert engine.threat_intel_engine.check_ip("198.51.100.23") is not None
        assert engine.threat_intel_engine.check_domain("evil-c2-server.com") is not None

        # 2. No-feed startup works normally
        engine_nofeed = IDSEngine(threat_intel_feeds=None)
        assert engine_nofeed.threat_intel_engine.check_ip("198.51.100.23") is not None

        # 3. Environment variable configuration
        os.environ["DPI_THREAT_INTEL_FEEDS"] = f"{f1_path},{f2_path}"
        try:
            engine_env = IDSEngine()
            assert engine_env.threat_intel_engine.check_ip("198.51.100.222") is not None
            assert engine_env.threat_intel_engine.check_domain("configured-feed-domain.org") is not None
        finally:
            del os.environ["DPI_THREAT_INTEL_FEEDS"]

