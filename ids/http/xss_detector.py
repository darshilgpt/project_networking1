"""Cross-Site Scripting (XSS) Detector with tag, handler, and pseudo-protocol inspection."""

from __future__ import annotations

import logging
import re
from typing import Callable, Dict, List, Optional, Tuple

from ids.http.common import normalize_http_text, sanitize_evidence_string
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ids.http.xss")

# Precompiled XSS indicator patterns
XSS_PATTERNS: List[Tuple[str, re.Pattern, Severity]] = [
    # 1. Script tag injection
    (
        "XSS_SCRIPT_TAG",
        re.compile(r"<\s*script\b[^>]*>", re.IGNORECASE),
        Severity.HIGH,
    ),
    # 2. Dangerous HTML event handlers (e.g. onload, onerror, onclick)
    (
        "XSS_EVENT_HANDLER",
        re.compile(r"\b(onload|onerror|onclick|onmouseover|onfocus|onblur|onkeydown|onkeyup)\s*=\s*['\"]?[^'\" >]+", re.IGNORECASE),
        Severity.HIGH,
    ),
    # 3. JavaScript / VBScript / Data URI pseudo-protocols
    (
        "XSS_JAVASCRIPT_URI",
        re.compile(r"(?:href|src|action)\s*=\s*['\"]?\s*(?:javascript|vbscript|data):", re.IGNORECASE),
        Severity.HIGH,
    ),
    # 4. Embedded SVG / IFRAME execution sinks
    (
        "XSS_EMBEDDED_FRAME_OR_SVG",
        re.compile(r"<\s*(?:iframe|object|embed|svg)\b[^>]*?(?:onload|onerror|src\s*=\s*['\"]?javascript:)", re.IGNORECASE),
        Severity.HIGH,
    ),
    # 5. DOM sinks (eval, document.cookie access)
    (
        "XSS_DOM_EXECUTION_SINK",
        re.compile(r"\b(?:eval|document\.cookie|window\.location|String\.fromCharCode)\s*\(", re.IGNORECASE),
        Severity.MEDIUM,
    ),
]


class XSSDetector:
    """Detects Cross-Site Scripting (XSS) in HTTP parameters, URIs, and bodies."""

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
            # Pre-filter: must contain characters common in markup or script calls
            if not any(token in norm_text.lower() for token in ("<", "script", "javascript:", "onload", "onerror", "onclick", "eval(", "document.cookie")):
                continue

            for rule_name, pattern, severity in XSS_PATTERNS:
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
                        f"[CONFIDENCE: HIGH] Matched XSS indicator '{matched_str}' in {field_name}. "
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
                        category=DetectionCategory.XSS,
                        severity=severity,
                        matched_rule=rule_name,
                        evidence=evidence,
                        recommended_action=DecisionAction.ALERT,  # Detection-only
                        packet_id=packet.packet_id,
                    )
                    alerts.append(alert)

        return alerts

