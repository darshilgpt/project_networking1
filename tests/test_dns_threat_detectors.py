"""Unit tests for Phase 4.2 Advanced DNS Threat Detectors.

Covers:
1. eSLD multi-part public suffix extraction.
2. DGA heuristic multi-factor detection, CDN attenuation, and short-string rejection.
3. Composite DNS tunneling with threshold >= 3.5.
4. Dedicated high-churn detection (>= 25 unique subdomains, CDN >= 100).
5. Repeated queries do not inflate unique churn count.
6. SPF/DKIM/DMARC TXT record exemption.
7. DNS transaction 7-tuple correlation and unsolicited response anomaly detection.
8. IPv4, IPv6 (/48 prefix), and mixed A/AAAA Fast Flux detection with negative controls.
9. SERVFAIL and REFUSED error burst detection, thresholds, and cooldown behavior.
10. Unmatched tracker periodic cleanup of empty keys.
11. Bounded state and eviction.
12. Strict detection-only zero-BLOCK / no-CRITICAL invariant across all new alerts.
"""

from __future__ import annotations

import time
import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, UDP

from dpi.dns_inspector import DNSInspector, DNSMetadata
from ids.dns import (
    DNSAnomalyDetector,
    DNSDGADetector,
    DNSThreatEngine,
    DNSTunnelingDetector,
)
from ids.dns.common import (
    BoundedLRUCache,
    calculate_entropy,
    calculate_normalized_entropy,
    extract_apex_and_subdomain,
    is_cdn_or_cloud_domain,
    is_legitimate_txt_record,
)
from ids.ids_engine import IDSEngine
from ips.decision_engine import DecisionEngine
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket
from parser.packet_dispatcher import PacketDispatcher


def create_dns_packet(
    scapy_dns: DNS,
    src_ip: str = "192.168.1.100",
    dst_ip: str = "8.8.8.8",
    src_port: int = 54321,
    dst_port: int = 53,
) -> ParsedPacket:
    """Helper to synthesize a ParsedPacket containing DNS payload."""
    from scapy.layers.l2 import Ether
    pkt_bytes = bytes(
        Ether(src="00:11:22:33:44:55", dst="66:77:88:99:aa:bb")
        / IP(src=src_ip, dst=dst_ip)
        / UDP(sport=src_port, dport=dst_port)
        / scapy_dns
    )
    dispatcher = PacketDispatcher()
    parsed = dispatcher.dispatch(pkt_bytes)
    assert parsed is not None
    return parsed


# --- Test 1: eSLD Extraction ---
def test_esld_multi_part_public_suffix_extraction():
    """Verifies that multi-part suffixes like .co.uk and .com.au correctly extract apex and subdomain."""
    apex, sub = extract_apex_and_subdomain("deep.malicious.tunnel.co.uk")
    assert apex == "tunnel.co.uk"
    assert sub == "deep.malicious"

    apex, sub = extract_apex_and_subdomain("data123.exfil.org.au")
    assert apex == "exfil.org.au"
    assert sub == "data123"

    apex, sub = extract_apex_and_subdomain("randomlabel123.sub.example.com")
    assert apex == "example.com"
    assert sub == "randomlabel123.sub"

    apex, sub = extract_apex_and_subdomain("localhost")
    assert apex == "localhost"
    assert sub == ""


# --- Test 2: Heuristic DGA Detection ---
def test_dga_detection_positive_multi_feature():
    """Verifies that a synthetic algorithmic domain triggering multiple linguistic/entropy features alerts."""
    detector = DNSDGADetector()
    dga_domain = "xrt7pk9qzbcdw1234.attacker.com"
    scapy_dns = DNS(id=0x1111, qd=DNSQR(qname=dga_domain, qtype="A"))
    packet = create_dns_packet(scapy_dns)

    alerts = detector.evaluate(
        domain_name=dga_domain,
        packet=packet,
        next_alert_id_fn=lambda: 1,
        now=time.time(),
    )

    assert len(alerts) == 1
    a = alerts[0]
    assert a.category == DetectionCategory.SUSPICIOUS_DNS
    assert a.severity == Severity.MEDIUM
    assert a.recommended_action == DecisionAction.ALERT
    assert "Heuristic DGA indicator (non-ML" in a.evidence
    assert "Heuristic observation, not confirmed malware" in a.evidence


def test_dga_negative_short_domains():
    """Verifies that labels shorter than 12 characters are never classified as DGA even if random-looking."""
    detector = DNSDGADetector()
    short_domain = "x7z9q.attacker.com"
    scapy_dns = DNS(id=0x2222, qd=DNSQR(qname=short_domain, qtype="A"))
    packet = create_dns_packet(scapy_dns)

    alerts = detector.evaluate(
        domain_name=short_domain,
        packet=packet,
        next_alert_id_fn=lambda: 1,
        now=time.time(),
    )
    assert len(alerts) == 0


def test_dga_cdn_attenuation():
    """Verifies that legitimate randomized CDN subdomains do not produce false DGA alerts."""
    detector = DNSDGADetector()
    cdn_domain = "d12345abcdefgh.cloudfront.net"
    scapy_dns = DNS(id=0x3333, qd=DNSQR(qname=cdn_domain, qtype="A"))
    packet = create_dns_packet(scapy_dns)

    alerts = detector.evaluate(
        domain_name=cdn_domain,
        packet=packet,
        next_alert_id_fn=lambda: 1,
        now=time.time(),
    )
    assert len(alerts) == 0


# --- Test 3: Composite Tunneling Threshold (>= 3.5) ---
def test_composite_tunneling_threshold_3_5():
    """Verifies that composite score < 3.5 yields 0 alerts, while >= 3.5 yields a HIGH tunneling alert."""
    detector = DNSTunnelingDetector()
    now = time.time()

    # Query with Base32 (1.5) + Length (1.5) + Entropy (1.0) = 4.0 >= 3.5 -> ALERT
    b32_sub = "mnwgk2lonfzs45dvmv3gs3theb2g64tfor2xgltd"
    tunnel_domain = f"{b32_sub}.exfil-c2.net"
    scapy_dns = DNS(id=0x4444, qd=DNSQR(qname=tunnel_domain, qtype="TXT"))
    packet = create_dns_packet(scapy_dns)

    alerts = detector.evaluate(
        domain_name=tunnel_domain,
        qtype_name="TXT",
        packet=packet,
        next_alert_id_fn=lambda: 1,
        now=now,
    )
    assert len(alerts) == 1
    assert alerts[0].category == DetectionCategory.DNS_TUNNELING
    assert alerts[0].severity == Severity.HIGH
    assert "Composite Score:" in alerts[0].evidence
    assert "/3.5" in alerts[0].evidence

    # Query with ONLY length (1.5) and unusual type (0.5) = 2.0 < 3.5 -> NO ALERT
    # Use natural English words without matching Base32/Hex regex
    long_plain = "my-sample-application-testing-long-domain-name-with-standard-hyphens-and-natural-words-in-query.normal-words.com"
    plain_dns = DNS(id=0x4445, qd=DNSQR(qname=long_plain, qtype="TXT"))
    pkt_plain = create_dns_packet(plain_dns)
    alerts_plain = detector.evaluate(
        domain_name=long_plain,
        qtype_name="TXT",
        packet=pkt_plain,
        next_alert_id_fn=lambda: 2,
        now=now + 0.1,
    )
    assert len(alerts_plain) == 0


# --- Test 4: Dedicated High-Churn Detection & CDN Threshold ---
def test_dedicated_subdomain_churn_detection():
    """Verifies that 25 unique short subdomains under one apex triggers dedicated churn rule with MEDIUM severity."""
    detector = DNSTunnelingDetector(window_seconds=60.0)
    apex = "tunnel-exfil.com"
    alerts = []
    now = time.time()

    for i in range(26):
        qname = f"chunk{i}.{apex}"
        scapy_dns = DNS(id=0x7000 + i, qd=DNSQR(qname=qname, qtype="A"))
        pkt = create_dns_packet(scapy_dns)
        det_alerts = detector.evaluate(
            domain_name=qname,
            qtype_name="A",
            packet=pkt,
            next_alert_id_fn=lambda: i + 1,
            now=now + (i * 0.1),
        )
        alerts.extend(det_alerts)

    assert len(alerts) >= 1
    churn_alerts = [a for a in alerts if a.matched_rule == "Excessive Unique Subdomain Generation (DNS Anomaly)"]
    assert len(churn_alerts) >= 1
    ca = churn_alerts[0]
    assert ca.category == DetectionCategory.SUSPICIOUS_DNS
    assert ca.severity == Severity.MEDIUM
    assert ca.recommended_action == DecisionAction.ALERT
    assert "Dedicated Subdomain Churn:" in ca.evidence


def test_repeated_queries_do_not_inflate_churn():
    """Verifies that repeated identical queries for the same subdomain do not inflate unique count."""
    detector = DNSTunnelingDetector(window_seconds=60.0)
    apex = "company.com"
    now = time.time()
    alerts = []

    # 40 queries for the exact same domain
    for i in range(40):
        qname = f"mail.{apex}"
        scapy_dns = DNS(id=0x7500 + i, qd=DNSQR(qname=qname, qtype="A"))
        pkt = create_dns_packet(scapy_dns)
        det_alerts = detector.evaluate(
            domain_name=qname,
            qtype_name="A",
            packet=pkt,
            next_alert_id_fn=lambda: i + 1,
            now=now + (i * 0.1),
        )
        alerts.extend(det_alerts)

    # Unique count is 1; must produce 0 alerts
    assert len(alerts) == 0


def test_cdn_churn_threshold_100():
    """Verifies that CDN domains with 50 unique subdomains do not alert, requiring >= 100."""
    detector = DNSTunnelingDetector(window_seconds=60.0)
    apex = "cloudfront.net"
    now = time.time()
    alerts_50 = []

    for i in range(50):
        qname = f"edge{i}.{apex}"
        scapy_dns = DNS(id=0x7800 + i, qd=DNSQR(qname=qname, qtype="A"))
        pkt = create_dns_packet(scapy_dns)
        det_alerts = detector.evaluate(
            domain_name=qname,
            qtype_name="A",
            packet=pkt,
            next_alert_id_fn=lambda: i + 1,
            now=now + (i * 0.1),
        )
        alerts_50.extend(det_alerts)

    assert len(alerts_50) == 0


# --- Test 5: SPF/DKIM Verification Exemption ---
def test_dns_tunneling_spf_dkim_verification_exemption():
    """Verifies that legitimate email SPF/DKIM TXT records are exempted from TXT unusual type vector."""
    detector = DNSTunnelingDetector()
    domain = "company.com"
    scapy_dns = DNS(id=0x6666, qd=DNSQR(qname=domain, qtype="TXT"))
    packet = create_dns_packet(scapy_dns)

    spf_txt = "v=spf1 include:_spf.google.com ~all"
    alerts = detector.evaluate(
        domain_name=domain,
        qtype_name="TXT",
        packet=packet,
        next_alert_id_fn=lambda: 1,
        now=time.time(),
        txt_records=[spf_txt],
    )
    assert len(alerts) == 0


# --- Test 6: Transaction Correlation & Unsolicited Response Burst ---
def test_dns_transaction_correlation_strict_and_unsolicited_burst():
    """Verifies normal 7-tuple correlation and unsolicited burst detection."""
    anomaly_detector = DNSAnomalyDetector()
    now = time.time()

    # Query
    query_dns = DNS(id=0x1234, qr=0, qd=DNSQR(qname="test.org", qtype="A"))
    q_pkt = create_dns_packet(query_dns, src_ip="192.168.1.50", dst_ip="8.8.8.8", src_port=50000, dst_port=53)
    q_meta = DNSInspector.inspect(bytes(query_dns), is_udp=True)
    anomaly_detector.process_query(q_meta, q_pkt, now)

    # Matching Response
    resp_dns = DNS(
        id=0x1234,
        qr=1,
        qd=DNSQR(qname="test.org", qtype="A"),
        an=DNSRR(rrname="test.org", type="A", rdata="93.184.216.34", ttl=300),
    )
    r_pkt = create_dns_packet(resp_dns, src_ip="8.8.8.8", dst_ip="192.168.1.50", src_port=53, dst_port=50000)
    r_meta = DNSInspector.inspect(bytes(resp_dns), is_udp=True)
    normal_alerts = anomaly_detector.evaluate_response(r_meta, r_pkt, lambda: 10, now + 0.05)
    assert len(normal_alerts) == 0
    assert r_meta.rtt_ms is not None

    # Unsolicited response burst (6 packets without prior queries)
    unsolicited_alerts = []
    for i in range(6):
        unsol_dns = DNS(
            id=0x9000 + i,
            qr=1,
            qd=DNSQR(qname=f"fake{i}.com", qtype="A"),
            an=DNSRR(rrname=f"fake{i}.com", type="A", rdata="1.2.3.4", ttl=60),
        )
        u_pkt = create_dns_packet(unsol_dns, src_ip="8.8.8.8", dst_ip="192.168.1.50", src_port=53, dst_port=50000)
        u_meta = DNSInspector.inspect(bytes(unsol_dns), is_udp=True)
        u_alerts = anomaly_detector.evaluate_response(u_meta, u_pkt, lambda: 100 + i, now + 1.0 + (i * 0.1))
        unsolicited_alerts.extend(u_alerts)

    assert len(unsolicited_alerts) >= 1
    assert any(a.matched_rule == "Unsolicited DNS Response Burst (Low Confidence)" for a in unsolicited_alerts)
    assert unsolicited_alerts[0].severity == Severity.LOW


# --- Test 7: Fast Flux (IPv4, IPv6 /48, Mixed, and Negative Controls) ---
def test_fast_flux_ipv4_and_ipv6_diversity():
    """Verifies Fast Flux detection across pure IPv4, pure IPv6 (/48 prefix), and mixed responses."""
    anomaly_detector = DNSAnomalyDetector()
    now = time.time()

    # Pure IPv4: 5 distinct /24 subnets with TTL=5s
    an_v4 = (
        DNSRR(rrname="v4.fastflux.net", type="A", rdata="10.1.1.1", ttl=5)
        / DNSRR(rrname="v4.fastflux.net", type="A", rdata="20.2.2.2", ttl=5)
        / DNSRR(rrname="v4.fastflux.net", type="A", rdata="30.3.3.3", ttl=5)
        / DNSRR(rrname="v4.fastflux.net", type="A", rdata="40.4.4.4", ttl=5)
        / DNSRR(rrname="v4.fastflux.net", type="A", rdata="50.5.5.5", ttl=5)
    )
    d_v4 = DNS(id=0x8801, qr=1, ancount=5, qd=DNSQR(qname="v4.fastflux.net", qtype="A"), an=an_v4)
    meta_v4 = DNSInspector.inspect(bytes(d_v4), is_udp=True)
    alerts_v4 = anomaly_detector.evaluate_response(meta_v4, create_dns_packet(d_v4), lambda: 1, now)
    assert len(alerts_v4) >= 1
    assert alerts_v4[0].severity == Severity.MEDIUM

    # Pure IPv6: 5 AAAA records across 3 distinct /48 allocations with TTL=10s
    an_v6 = (
        DNSRR(rrname="v6.fastflux.net", type="AAAA", rdata="2001:db8:1::1", ttl=10)
        / DNSRR(rrname="v6.fastflux.net", type="AAAA", rdata="2001:db8:1::2", ttl=10)
        / DNSRR(rrname="v6.fastflux.net", type="AAAA", rdata="2001:db8:2::1", ttl=10)
        / DNSRR(rrname="v6.fastflux.net", type="AAAA", rdata="2001:db8:3::1", ttl=10)
        / DNSRR(rrname="v6.fastflux.net", type="AAAA", rdata="2001:db8:3::2", ttl=10)
    )
    d_v6 = DNS(id=0x8802, qr=1, ancount=5, qd=DNSQR(qname="v6.fastflux.net", qtype="AAAA"), an=an_v6)
    meta_v6 = DNSInspector.inspect(bytes(d_v6), is_udp=True)
    alerts_v6 = anomaly_detector.evaluate_response(meta_v6, create_dns_packet(d_v6), lambda: 2, now + 0.1)
    assert len(alerts_v6) >= 1
    assert "Fast Flux" in alerts_v6[0].evidence

    # Mixed A and AAAA: 3 IPv4 in 2 /24s + 2 IPv6 in 2 /48s = 4 distinct prefixes
    an_mixed = (
        DNSRR(rrname="mixed.fastflux.net", type="A", rdata="192.168.1.1", ttl=5)
        / DNSRR(rrname="mixed.fastflux.net", type="A", rdata="192.168.2.1", ttl=5)
        / DNSRR(rrname="mixed.fastflux.net", type="A", rdata="192.168.2.2", ttl=5)
        / DNSRR(rrname="mixed.fastflux.net", type="AAAA", rdata="2001:db8:a::1", ttl=5)
        / DNSRR(rrname="mixed.fastflux.net", type="AAAA", rdata="2001:db8:b::1", ttl=5)
    )
    d_mixed = DNS(id=0x8803, qr=1, ancount=5, qd=DNSQR(qname="mixed.fastflux.net", qtype="A"), an=an_mixed)
    meta_mixed = DNSInspector.inspect(bytes(d_mixed), is_udp=True)
    alerts_mixed = anomaly_detector.evaluate_response(meta_mixed, create_dns_packet(d_mixed), lambda: 3, now + 0.2)
    assert len(alerts_mixed) >= 1


def test_fast_flux_negative_controls():
    """Verifies that responses with high TTL or insufficient prefixes do not trigger Fast Flux alerts."""
    anomaly_detector = DNSAnomalyDetector()
    now = time.time()

    # Negative 1: 5 distinct subnets but normal TTL (300s) -> NO ALERT
    an_high_ttl = (
        DNSRR(rrname="normal.net", type="A", rdata="10.1.1.1", ttl=300)
        / DNSRR(rrname="normal.net", type="A", rdata="20.2.2.2", ttl=300)
        / DNSRR(rrname="normal.net", type="A", rdata="30.3.3.3", ttl=300)
        / DNSRR(rrname="normal.net", type="A", rdata="40.4.4.4", ttl=300)
        / DNSRR(rrname="normal.net", type="A", rdata="50.5.5.5", ttl=300)
    )
    d1 = DNS(id=0x8810, qr=1, ancount=5, qd=DNSQR(qname="normal.net", qtype="A"), an=an_high_ttl)
    meta1 = DNSInspector.inspect(bytes(d1), is_udp=True)
    assert len(anomaly_detector.evaluate_response(meta1, create_dns_packet(d1), lambda: 1, now)) == 0

    # Negative 2: Low TTL (5s) but only 1 subnet (/24) -> NO ALERT
    an_same_subnet = (
        DNSRR(rrname="same.net", type="A", rdata="10.1.1.1", ttl=5)
        / DNSRR(rrname="same.net", type="A", rdata="10.1.1.2", ttl=5)
        / DNSRR(rrname="same.net", type="A", rdata="10.1.1.3", ttl=5)
        / DNSRR(rrname="same.net", type="A", rdata="10.1.1.4", ttl=5)
        / DNSRR(rrname="same.net", type="A", rdata="10.1.1.5", ttl=5)
    )
    d2 = DNS(id=0x8811, qr=1, ancount=5, qd=DNSQR(qname="same.net", qtype="A"), an=an_same_subnet)
    meta2 = DNSInspector.inspect(bytes(d2), is_udp=True)
    assert len(anomaly_detector.evaluate_response(meta2, create_dns_packet(d2), lambda: 2, now + 0.1)) == 0


# --- Test 8: SERVFAIL and REFUSED Error Burst & Cooldown ---
def test_servfail_and_refused_error_bursts_and_cooldown():
    """Verifies that 15 SERVFAIL or REFUSED in 10s alerts and cooldown prevents re-alerting."""
    anomaly_detector = DNSAnomalyDetector()
    now = time.time()
    dest_ip = "192.168.1.100"

    # 1. SERVFAIL Burst (RCODE=2, threshold 15)
    # Register corresponding queries first so responses are correlated and don't trigger unsolicited response bursts
    for i in range(16):
        q_sf = DNS(id=0x6000 + i, qr=0, qd=DNSQR(qname="broken.org", qtype="A"))
        pkt_q = create_dns_packet(q_sf, src_ip=dest_ip, dst_ip="8.8.8.8")
        meta_q = DNSInspector.inspect(bytes(q_sf), is_udp=True)
        anomaly_detector.process_query(meta_q, pkt_q, now + (i * 0.1))

    servfail_alerts = []
    for i in range(16):
        d_sf = DNS(id=0x6000 + i, qr=1, rcode=2, qd=DNSQR(qname="broken.org", qtype="A"))
        pkt = create_dns_packet(d_sf, src_ip="8.8.8.8", dst_ip=dest_ip)
        meta_sf = DNSInspector.inspect(bytes(d_sf), is_udp=True)
        a = anomaly_detector.evaluate_response(meta_sf, pkt, lambda: 200 + i, now + 0.05 + (i * 0.1))
        servfail_alerts.extend(a)

    # Exactly 1 alert on packet 15; packet 16 suppressed by cooldown
    assert len(servfail_alerts) == 1
    assert servfail_alerts[0].matched_rule == "DNS Response Error Burst (SERVFAIL)"
    assert servfail_alerts[0].severity == Severity.LOW

    # 2. REFUSED Burst (RCODE=5, threshold 15)
    for i in range(16):
        q_ref = DNS(id=0x7000 + i, qr=0, qd=DNSQR(qname="denied.org", qtype="A"))
        pkt_qr = create_dns_packet(q_ref, src_ip=dest_ip, dst_ip="8.8.8.8")
        meta_qr = DNSInspector.inspect(bytes(q_ref), is_udp=True)
        anomaly_detector.process_query(meta_qr, pkt_qr, now + 2.0 + (i * 0.1))

    refused_alerts = []
    for i in range(16):
        d_ref = DNS(id=0x7000 + i, qr=1, rcode=5, qd=DNSQR(qname="denied.org", qtype="A"))
        pkt = create_dns_packet(d_ref, src_ip="8.8.8.8", dst_ip=dest_ip)
        meta_ref = DNSInspector.inspect(bytes(d_ref), is_udp=True)
        a = anomaly_detector.evaluate_response(meta_ref, pkt, lambda: 300 + i, now + 2.05 + (i * 0.1))
        refused_alerts.extend(a)

    assert len(refused_alerts) == 1
    assert refused_alerts[0].matched_rule == "DNS Response Error Burst (REFUSED)"
    assert refused_alerts[0].severity == Severity.MEDIUM


def test_error_burst_below_threshold_no_alert():
    """Verifies that 10 SERVFAIL responses (below 15 threshold) generates 0 alerts."""
    anomaly_detector = DNSAnomalyDetector()
    now = time.time()
    alerts = []

    # Register queries first
    for i in range(10):
        q_sf = DNS(id=0x6500 + i, qr=0, qd=DNSQR(qname="broken.org", qtype="A"))
        pkt_q = create_dns_packet(q_sf, src_ip="192.168.1.100", dst_ip="8.8.8.8")
        meta_q = DNSInspector.inspect(bytes(q_sf), is_udp=True)
        anomaly_detector.process_query(meta_q, pkt_q, now + (i * 0.2))

    for i in range(10):
        d_sf = DNS(id=0x6500 + i, qr=1, rcode=2, qd=DNSQR(qname="broken.org", qtype="A"))
        pkt = create_dns_packet(d_sf, src_ip="8.8.8.8", dst_ip="192.168.1.100")
        meta = DNSInspector.inspect(bytes(d_sf), is_udp=True)
        alerts.extend(anomaly_detector.evaluate_response(meta, pkt, lambda: i, now + (i * 0.2)))

    assert len(alerts) == 0


# --- Test 9: Unmatched Tracker Periodic Cleanup ---
def test_unmatched_tracker_periodic_cleanup():
    """Verifies that empty/stale destination IP keys are deleted from _unmatched_tracker."""
    anomaly_detector = DNSAnomalyDetector()
    now = 1000.0

    # Add unmatched entries for host A and host B
    for ip in ("10.0.0.1", "10.0.0.2"):
        for i in range(2):
            d = DNS(id=0x9900 + i, qr=1, qd=DNSQR(qname="test.org", qtype="A"))
            meta = DNSInspector.inspect(bytes(d), is_udp=True)
            pkt = create_dns_packet(d, dst_ip=ip)
            anomaly_detector.evaluate_response(meta, pkt, lambda: 1, now)

    assert "10.0.0.1" in anomaly_detector._unmatched_tracker
    assert "10.0.0.2" in anomaly_detector._unmatched_tracker

    # Advance time by 6.0s (> 5.0s TTL) and trigger evaluation
    d_late = DNS(id=0x9999, qr=1, qd=DNSQR(qname="test.org", qtype="A"))
    meta_late = DNSInspector.inspect(bytes(d_late), is_udp=True)
    pkt_late = create_dns_packet(d_late, dst_ip="10.0.0.3")
    anomaly_detector.evaluate_response(meta_late, pkt_late, lambda: 2, now + 6.0)

    # Stale hosts 10.0.0.1 and 10.0.0.2 must have been deleted
    assert "10.0.0.1" not in anomaly_detector._unmatched_tracker
    assert "10.0.0.2" not in anomaly_detector._unmatched_tracker
    assert "10.0.0.3" in anomaly_detector._unmatched_tracker


# --- Test 10: Bounded LRU Cache & Eviction ---
def test_bounded_lru_cache_and_eviction():
    """Verifies that BoundedLRUCache strictly enforces max capacity and expires entries properly."""
    cache = BoundedLRUCache(max_size=50, ttl_seconds=2.0)
    now = 1000.0

    for i in range(60):
        cache.set(f"key_{i}", f"val_{i}", now=now)

    assert len(cache) <= 50
    assert cache.get("key_0", now=now) is None
    assert cache.get("key_59", now=now) == "val_59"
    assert cache.get("key_59", now=now + 3.0) is None


# --- Test 11: Zero-BLOCK Invariant across all DNS Alerts ---
def test_dns_detection_only_never_triggers_block():
    """Verifies that all DNS alerts generated are strictly ALERT and never cause DecisionEngine to BLOCK."""
    engine = IDSEngine()
    decision_engine = DecisionEngine()

    # DGA packet
    dga_domain = "xrt7pk9qzbcdw1234.attacker.com"
    scapy_dns = DNS(id=0x9999, qd=DNSQR(qname=dga_domain, qtype="A"))
    packet = create_dns_packet(scapy_dns)
    dns_meta = DNSInspector.inspect(bytes(scapy_dns), is_udp=True)

    from models.alert_model import DPIResult
    dpi_res = DPIResult(flow_id=1, protocol="DNS", metadata={"dns": dns_meta})

    alerts = engine.evaluate(packet, dpi_res)
    assert len(alerts) >= 1

    for a in alerts:
        assert a.recommended_action == DecisionAction.ALERT
        assert a.severity != Severity.CRITICAL
        action = decision_engine.decide(packet=packet, dpi_result=dpi_res, alerts=[a])
        assert action == DecisionAction.ALERT
        assert action != DecisionAction.BLOCK
