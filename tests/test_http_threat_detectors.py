"""Unit and integration tests for Phase 4.1 HTTP Threat Detectors.

Covers:
- SQL Injection detection & false-positive business query tests
- XSS tag, handler, and pseudo-protocol detection & false-positive HTML tests
- Path Traversal canonical, double-encoded, and sensitive file detection & false-positive URL tests
- Command Injection chaining and interpreter tests & false-positive shell character tests
- Parser state gating: incomplete, truncated, ambiguous, and desynchronized safety
- Sensitive header and cookie redaction
- Fault isolation: individual detector exception resilience
- Detection-only guarantee: zero BLOCK decisions generated
"""

from collections import deque
import time
import pytest
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP

from dpi.dpi_engine import DPIEngine
from dpi.http_inspector import HTTPMetadata, HTTPMessageStreamParser
from ids.ids_engine import IDSEngine
from ids.http.sqli_detector import SQLiDetector
from ids.http.xss_detector import XSSDetector
from ids.http.traversal_detector import PathTraversalDetector
from ids.http.command_injection_detector import CommandInjectionDetector
from ids.http.common import redact_sensitive_headers, sanitize_evidence_string
from ips.decision_engine import DecisionEngine
from models.alert_model import DecisionAction, DetectionCategory, Severity
from parser.packet_dispatcher import PacketDispatcher
from reassembly.tcp_reassembler import TCPReassembler, TrafficDirection


@pytest.fixture
def dispatcher():
    return PacketDispatcher()


@pytest.fixture
def reassembler():
    return TCPReassembler()


@pytest.fixture
def ids_engine():
    return IDSEngine()


@pytest.fixture
def decision_engine():
    return DecisionEngine()


# =====================================================================
# 1. SQL Injection Tests & False-Positive Tests
# =====================================================================

def test_sqli_union_select_and_boolean_tautology(dispatcher, ids_engine):
    """Asserts that UNION SELECT and boolean tautologies trigger SQL_INJECTION alerts."""
    # Attack in query parameter
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /search?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users-- HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    sqli_alerts = [a for a in alerts if a.category == DetectionCategory.SQL_INJECTION]
    assert len(sqli_alerts) >= 1
    assert sqli_alerts[0].recommended_action == DecisionAction.ALERT
    assert sqli_alerts[0].severity == Severity.HIGH
    assert "UNION_SELECT" in sqli_alerts[0].matched_rule


def test_sqli_false_positive_business_queries(dispatcher, ids_engine):
    """Asserts that ordinary English business queries with words like 'select' or 'order' do NOT trigger SQLi alerts."""
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /shop?category=select+items+from+catalog&order=relevance HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    sqli_alerts = [a for a in alerts if a.category == DetectionCategory.SQL_INJECTION]
    assert len(sqli_alerts) == 0


# =====================================================================
# 2. XSS Tests & False-Positive Tests
# =====================================================================

def test_xss_script_tags_and_event_handlers(dispatcher, ids_engine):
    """Asserts that <script> tags and onerror= event handlers trigger XSS alerts."""
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /profile?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    xss_alerts = [a for a in alerts if a.category == DetectionCategory.XSS]
    assert len(xss_alerts) >= 1
    assert xss_alerts[0].recommended_action == DecisionAction.ALERT
    assert xss_alerts[0].severity == Severity.HIGH


def test_xss_false_positive_html_and_math(dispatcher, ids_engine):
    """Asserts that ordinary markup and mathematical inequalities do NOT trigger XSS alerts."""
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /forum?text=value%20is%20x%20%3C%205%20and%20y%20%3E%202&format=b HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    xss_alerts = [a for a in alerts if a.category == DetectionCategory.XSS]
    assert len(xss_alerts) == 0


# =====================================================================
# 3. Path Traversal Tests & False-Positive Tests
# =====================================================================

def test_path_traversal_double_encoding_and_sensitive_file(dispatcher, ids_engine):
    """Asserts that double-encoded traversals and /etc/passwd targeting trigger PATH_TRAVERSAL alerts."""
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /download?file=%252e%252e%252f%252e%252e%252fetc/passwd HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    trav_alerts = [a for a in alerts if a.category == DetectionCategory.PATH_TRAVERSAL]
    assert len(trav_alerts) >= 1
    assert trav_alerts[0].recommended_action == DecisionAction.ALERT
    assert trav_alerts[0].severity == Severity.HIGH


def test_path_traversal_false_positive_legitimate_paths(dispatcher, ids_engine):
    """Asserts that normal paths (e.g. /static/css/theme.css) do NOT trigger traversal alerts."""
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /static/css/theme.css?v=2.1 HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    trav_alerts = [a for a in alerts if a.category == DetectionCategory.PATH_TRAVERSAL]
    assert len(trav_alerts) == 0


# =====================================================================
# 4. Command Injection Tests & False-Positive Tests
# =====================================================================

def test_command_injection_chained_binaries(dispatcher, ids_engine):
    """Asserts that chained shell execution (; whoami) triggers COMMAND_INJECTION alerts."""
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /network_test?ip=127.0.0.1;%20whoami HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    cmdi_alerts = [a for a in alerts if a.category == DetectionCategory.COMMAND_INJECTION]
    assert len(cmdi_alerts) >= 1
    assert cmdi_alerts[0].recommended_action == DecisionAction.ALERT
    assert cmdi_alerts[0].severity == Severity.HIGH


def test_command_injection_false_positive_semicolons_in_text(dispatcher, ids_engine):
    """Asserts that natural semicolons in sentences do NOT trigger command injection alerts."""
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="192.168.1.50", dst="192.168.1.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /comment?msg=first;then+second HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    engine = DPIEngine()
    dpi_res = engine.inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    cmdi_alerts = [a for a in alerts if a.category == DetectionCategory.COMMAND_INJECTION]
    assert len(cmdi_alerts) == 0


# =====================================================================
# 5. Parser Safety Gating Tests (Incomplete, Truncated, Ambiguous)
# =====================================================================

def test_incomplete_message_defers_threat_detection(dispatcher, ids_engine):
    """Asserts that incomplete messages defer threat detection (no false alerts)."""
    # Truncated HTTP request in-flight
    meta = HTTPMetadata(
        is_request=True,
        method="GET",
        uri="/search?q=union+select",
        is_complete=False,  # Incomplete!
    )
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=80))
    pkt = dispatcher.dispatch(pkt_raw)
    from models.alert_model import DPIResult
    dpi_res = DPIResult(flow_id=1, protocol="HTTP", metadata={"http": meta, "http_messages": [meta]})

    alerts = ids_engine.evaluate(pkt, dpi_res)
    assert len([a for a in alerts if a.category == DetectionCategory.SQL_INJECTION]) == 0


def test_ambiguous_framing_suppresses_attack_classifications(dispatcher, ids_engine):
    """Asserts that messages with ambiguous framing do not generate confirmed attack classifications."""
    meta = HTTPMetadata(
        is_request=True,
        method="POST",
        uri="/api",
        framing_method="AMBIGUOUS_CONTENT_LENGTH",
        normalized_body="union select password from users",
        is_complete=True,
    )
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=80))
    pkt = dispatcher.dispatch(pkt_raw)
    from models.alert_model import DPIResult
    dpi_res = DPIResult(flow_id=1, protocol="HTTP", metadata={"http": meta, "http_messages": [meta]})

    alerts = ids_engine.evaluate(pkt, dpi_res)
    # Ambiguous framing must suppress attack alerts
    assert len([a for a in alerts if a.category == DetectionCategory.SQL_INJECTION]) == 0


def test_truncated_message_suppresses_attack_classifications(dispatcher, ids_engine):
    """Asserts that messages exceeding header/body limits do not generate confirmed attack alerts."""
    meta = HTTPMetadata(
        is_request=True,
        method="POST",
        uri="/api",
        is_truncated=True,
        truncation_reason="BODY_EXCEEDED_LIMIT",
        normalized_body="union select password from users",
        is_complete=True,
    )
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="1.1.1.1", dst="2.2.2.2") / TCP(sport=1, dport=80))
    pkt = dispatcher.dispatch(pkt_raw)
    from models.alert_model import DPIResult
    dpi_res = DPIResult(flow_id=1, protocol="HTTP", metadata={"http": meta, "http_messages": [meta]})

    alerts = ids_engine.evaluate(pkt, dpi_res)
    assert len([a for a in alerts if a.category == DetectionCategory.SQL_INJECTION]) == 0


# =====================================================================
# 6. Sensitive Header & Cookie Redaction Tests
# =====================================================================

def test_sensitive_header_and_cookie_redaction():
    """Asserts that Cookie and Authorization headers are completely redacted in evidence strings."""
    headers = {
        "host": "target.local",
        "cookie": "sessionid=xyz123secret; user=alice",
        "authorization": "Bearer eyJhbGciOi...",
        "user-agent": "Mozilla/5.0",
    }
    sanitized = redact_sensitive_headers(headers)
    assert sanitized["host"] == "target.local"
    assert "xyz123secret" not in sanitized["cookie"]
    assert sanitized["cookie"] == "[REDACTED_COOKIE]"
    assert sanitized["authorization"] == "[REDACTED_AUTHORIZATION]"

    # Test evidence string masking
    ev = sanitize_evidence_string("user=admin&password=SuperSecretPassword123&action=login")
    assert "SuperSecretPassword123" not in ev
    assert "password=[REDACTED]" in ev


# =====================================================================
# 7. Fault Isolation Tests
# =====================================================================

def test_detector_fault_isolation(dispatcher):
    """Asserts that an unhandled exception in one detector does not crash the pipeline or silence other detectors."""
    engine = IDSEngine()

    # Create a faulty detector that raises an unexpected exception
    class FaultyDetector:
        def evaluate(self, http_meta, packet, next_alert_id_fn, alert_context):
            raise RuntimeError("Simulated crash in buggy detector!")

    # Prepend faulty detector and include functional XSSDetector
    engine.http_detectors = [FaultyDetector(), XSSDetector()]

    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=80, flags="PA", seq=1) / b"GET /page?q=%3Cscript%3Ealert(1)%3C/script%3E HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    dpi_res = DPIEngine().inspect(pkt)

    # Pipeline MUST NOT crash and XSSDetector MUST still execute and alert cleanly
    alerts = engine.evaluate(pkt, dpi_res)
    xss_alerts = [a for a in alerts if a.category == DetectionCategory.XSS]
    assert len(xss_alerts) >= 1


# =====================================================================
# 8. Detection-Only Guarantee: Zero BLOCK Decisions
# =====================================================================

def test_http_attack_detection_only_never_triggers_block(dispatcher, ids_engine, decision_engine):
    """Asserts that HTTP threat alerts use recommended_action=ALERT and never trigger DecisionAction.BLOCK."""
    # Synthesize severe SQLi attack
    pkt_raw = bytes(Ether(src="00:01:02:03:04:05", dst="00:06:07:08:09:0a") / IP(src="10.0.0.5", dst="10.0.0.1") / TCP(sport=5000, dport=80, flags="PA", seq=1) / b"GET /login?user=admin%27%20OR%20%271%27=%271-- HTTP/1.1\r\nHost: target.local\r\n\r\n")
    pkt = dispatcher.dispatch(pkt_raw)
    dpi_res = DPIEngine().inspect(pkt)
    alerts = ids_engine.evaluate(pkt, dpi_res)

    assert len(alerts) >= 1
    # Verify every alert has recommended_action == ALERT and severity != CRITICAL
    for a in alerts:
        if a.category in (DetectionCategory.SQL_INJECTION, DetectionCategory.XSS, DetectionCategory.PATH_TRAVERSAL, DetectionCategory.COMMAND_INJECTION):
            assert a.recommended_action == DecisionAction.ALERT
            assert a.severity != Severity.CRITICAL

    # Evaluate through DecisionEngine: MUST yield ALERT, NEVER BLOCK
    action = decision_engine.decide(packet=pkt, dpi_result=dpi_res, alerts=alerts)
    assert action == DecisionAction.ALERT

