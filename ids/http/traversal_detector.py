"""Path Traversal and Directory Traversal Detector with encoding normalization."""

from __future__ import annotations

import logging
import re
from typing import Callable, Dict, List, Optional, Tuple

from ids.http.common import normalize_http_text, sanitize_evidence_string
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ids.http.traversal")

# Path traversal indicator patterns
TRAVERSAL_PATTERNS: List[Tuple[str, re.Pattern, Severity]] = [
    # 1. Canonical dot-dot slash sequence (../ or ..\)
    (
        "PATH_TRAVERSAL_DOT_DOT_SLASH",
        re.compile(r"(?:\.\./|\.\.\\)", re.IGNORECASE),
        Severity.HIGH,
    ),
    # 2. Overlong or encoded traversal representations (%2e%2e, %c0%ae%c0%ae)
    (
        "PATH_TRAVERSAL_ENCODED_DOTS",
        re.compile(r"(?:%2e|%252e|%c0%ae){2}(?:/|\\|%2f|%5c)", re.IGNORECASE),
        Severity.HIGH,
    ),
    # 3. Null byte path truncation injection (%00 or \x00)
    (
        "PATH_TRAVERSAL_NULL_BYTE",
        re.compile(r"(?:%00|\x00)", re.IGNORECASE),
        Severity.HIGH,
    ),
    # 4. Sensitive OS file/path targets
    (
        "PATH_TRAVERSAL_SENSITIVE_FILE_ACCESS",
        re.compile(
            r"(?:etc/(?:passwd|shadow|hosts)|windows/(?:win\.ini|system\.ini)|system32/drivers/etc/hosts|\.env\b|web\.config\b|boot\.ini\b)",
            re.IGNORECASE,
        ),
        Severity.HIGH,
    ),
]


class PathTraversalDetector:
    """Detects Path Traversal probes and unauthorized local file inclusion attempts."""

    def __init__(self) -> None:
        pass

    def evaluate(
        self,
        http_meta: Any,
        packet: ParsedPacket,
        next_alert_id_fn: Callable[[], int],
        alert_context: Dict[str, Any],
    ) -> List[IDSAlert]:
        alerts: List[IDSAlert] = []

        targets: List[Tuple[str, str, str]] = []

        if http_meta.normalized_uri:
            # Include both normalized and raw URI to catch encoding evasions
            targets.append(("uri", normalize_http_text(http_meta.normalized_uri), http_meta.raw_uri or ""))
            if http_meta.raw_uri and http_meta.raw_uri != http_meta.normalized_uri:
                targets.append(("raw_uri", http_meta.raw_uri, http_meta.raw_uri))

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
            # Pre-filter
            if not any(token in norm_text.lower() for token in ("..", "%2e", "%00", "etc/", "win.ini", "system.ini", ".env", "web.config", "passwd")):
                continue

            for rule_name, pattern, severity in TRAVERSAL_PATTERNS:
                m = pattern.search(norm_text)
                if m:
                    dedup_key = (alert_context.get("message_id", ""), rule_name)
                    seen_set = alert_context.setdefault("alerted_rules", set())
                    if dedup_key in seen_set:
                        continue
                    seen_set.add(dedup_key)

                    matched_str = m.group(0)
                    sanitized_raw = sanitize_evidence_string(raw_text)
                    sanitized_norm = sanitize_evidence_string(norm_text)
                    evidence = (
                        f"[CONFIDENCE: HIGH] Matched Path Traversal indicator '{matched_str}' in {field_name}. "
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
                        category=DetectionCategory.PATH_TRAVERSAL,
                        severity=severity,
                        matched_rule=rule_name,
                        evidence=evidence,
                        recommended_action=DecisionAction.ALERT,  # Detection-only
                        packet_id=packet.packet_id,
                    )
                    alerts.append(alert)

        return alerts

