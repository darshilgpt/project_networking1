"""SQL Injection (SQLi) Detector with syntactic clustering and false-positive guards."""

from __future__ import annotations

import logging
import re
from typing import Callable, Dict, List, Optional, Tuple

from ids.http.common import normalize_http_text, sanitize_evidence_string
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ids.http.sqli")

# Weighted SQL Injection indicator patterns (precompiled)
SQLI_PATTERNS: List[Tuple[str, re.Pattern, float]] = [
    # 1. UNION SELECT queries
    (
        "SQLI_UNION_SELECT",
        re.compile(r"\bunion\s+(?:all\s+)?select\b", re.IGNORECASE),
        4.0,
    ),
    # 2. Boolean tautology (e.g. OR 1=1, AND 'a'='a', OR 'x'='x')
    (
        "SQLI_BOOLEAN_TAUTOLOGY",
        re.compile(r"(?:\bor\b|\band\b)\s+['\"]?([0-9a-zA-Z_]+)['\"]?\s*=\s*['\"]?\1['\"]?", re.IGNORECASE),
        4.0,
    ),
    # 3. Inline and block comments coupled with quotes/terminators
    (
        "SQLI_COMMENT_INJECTION",
        re.compile(r"(?:--\s+|#|/\*.*?\*/|;\s*--)", re.IGNORECASE),
        3.0,
    ),
    # 4. Batched / stacked SQL statements
    (
        "SQLI_STACKED_QUERY",
        re.compile(r";\s*(?:drop\s+table|delete\s+from|insert\s+into|update\s+\w+\s+set)\b", re.IGNORECASE),
        4.5,
    ),
    # 5. Database fingerprinting and time-delay functions
    (
        "SQLI_DATABASE_FUNCTIONS",
        re.compile(r"\b(?:sleep|benchmark|extractvalue|load_file|xp_cmdshell|pg_sleep)\s*\(", re.IGNORECASE),
        3.5,
    ),
    # 6. ORDER BY / GROUP BY enumeration probes
    (
        "SQLI_ORDER_BY_PROBE",
        re.compile(r"\border\s+by\s+\d{1,4}\s*(?:--|#|/\*)", re.IGNORECASE),
        3.5,
    ),
]


class SQLiDetector:
    """Detects SQL Injection attempts across HTTP URIs, parameters, and bodies."""

    def __init__(self, score_threshold: float = 3.0) -> None:
        self.score_threshold = score_threshold

    def evaluate(
        self,
        http_meta: Any,
        packet: ParsedPacket,
        next_alert_id_fn: Callable[[], int],
        alert_context: Dict[str, Any],
    ) -> List[IDSAlert]:
        """
        Evaluates a complete, trustworthy HTTP message for SQL injection indicators.
        Strictly detection-only: recommends ALERT, never BLOCK.
        """
        alerts: List[IDSAlert] = []

        # Target inspection strings
        targets: List[Tuple[str, str, str]] = []  # (field_name, normalized_val, raw_val)

        if http_meta.normalized_uri:
            targets.append(("uri", normalize_http_text(http_meta.normalized_uri), http_meta.raw_uri or ""))

        for qk, qvals in getattr(http_meta, "normalized_query_params", {}).items():
            norm_k = normalize_http_text(qk)
            raw_k = qk
            for qv in qvals:
                norm_v = normalize_http_text(qv)
                raw_v = qv
                targets.append((f"query_param[{norm_k}]", norm_v, f"{raw_k}={raw_v}"))

        if getattr(http_meta, "normalized_body", ""):
            targets.append(("body", normalize_http_text(http_meta.normalized_body), http_meta.body_preview or ""))

        src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "")
        dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "")
        src_port = packet.tcp.src_port if packet.tcp else 0
        dst_port = packet.tcp.dst_port if packet.tcp else 0
        ts = packet.timestamp or 0.0

        for field_name, norm_text, raw_text in targets:
            # Quick token pre-check to eliminate unnecessary regex runs on ordinary text
            if not any(token in norm_text.lower() for token in ("'", '"', "--", "#", "/*", "select", "union", "or ", "and ", "sleep", "benchmark", "drop")):
                continue

            matched_rules = []
            accumulated_score = 0.0

            for rule_name, pattern, weight in SQLI_PATTERNS:
                m = pattern.search(norm_text)
                if m:
                    matched_rules.append((rule_name, m.group(0)))
                    accumulated_score += weight

            if accumulated_score >= self.score_threshold:
                primary_rule = matched_rules[0][0]
                matched_token = matched_rules[0][1]

                # Deduplication key check against already alerted rules on this HTTP message
                dedup_key = (alert_context.get("message_id", ""), primary_rule)
                seen_set = alert_context.setdefault("alerted_rules", set())
                if dedup_key in seen_set:
                    continue
                seen_set.add(dedup_key)

                sanitized_raw = sanitize_evidence_string(raw_text)
                sanitized_norm = sanitize_evidence_string(norm_text)
                evidence = (
                    f"[CONFIDENCE: HIGH] Matched SQLi in {field_name}: token='{matched_token}' "
                    f"(Score: {accumulated_score:.1f}, Rules: {[r[0] for r in matched_rules]}). "
                    f"Evidence: '{sanitized_norm}' (Raw: '{sanitized_raw}')"
                )

                alert = IDSAlert.create(
                    alert_id=next_alert_id_fn(),
                    timestamp=ts,
                    source_ip=src_ip,
                    destination_ip=dst_ip,
                    source_port=src_port,
                    destination_port=dst_port,
                    protocol="HTTP",
                    category=DetectionCategory.SQL_INJECTION,
                    severity=Severity.HIGH,
                    matched_rule=f"SQL_INJECTION_{primary_rule}",
                    evidence=evidence,
                    recommended_action=DecisionAction.ALERT,  # Detection-only
                    packet_id=packet.packet_id,
                )
                alerts.append(alert)

        return alerts

