"""Central Intrusion Detection System Engine coordinating signature and behavioural detectors."""

from __future__ import annotations

import logging
import os
from typing import Dict, List, Optional

from ids.behaviour_detector import BehaviourDetector
from ids.signature_detector import SignatureDetector
from ids.http.sqli_detector import SQLiDetector
from ids.http.xss_detector import XSSDetector
from ids.http.traversal_detector import PathTraversalDetector
from ids.http.command_injection_detector import CommandInjectionDetector
from ids.dns import DNSThreatEngine
from ids.threat_intel import ThreatIntelEngine
from models.alert_model import DecisionAction, DetectionCategory, DPIResult, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ids.ids_engine")


class IDSEngine:
    """Evaluates packet streams against signature rules, specialized HTTP threat detectors, and behavioural baselines."""

    def __init__(
        self,
        signature_detector: Optional[SignatureDetector] = None,
        behaviour_detector: Optional[BehaviourDetector] = None,
        threat_intel_feeds: Optional[List[str]] = None,
    ) -> None:
        self.signature_detector = signature_detector or SignatureDetector()
        self.behaviour_detector = behaviour_detector or BehaviourDetector()

        # Phase 4.1 Specialized HTTP threat detectors
        self.http_detectors = [
            SQLiDetector(),
            XSSDetector(),
            PathTraversalDetector(),
            CommandInjectionDetector(),
        ]

        # Phase 4.2 Specialized DNS threat engine
        self.dns_threat_engine = DNSThreatEngine()

        # Phase 4.3 Modular Threat Intelligence Engine with configurable feeds
        # Resolves feeds from explicit argument, environment variable, or defaults to empty list
        resolved_feeds: List[str] = []
        if threat_intel_feeds:
            resolved_feeds.extend(threat_intel_feeds)
        else:
            # Check environment variable (comma or semicolon separated)
            env_feeds = os.environ.get("DPI_THREAT_INTEL_FEEDS", "").strip()
            if env_feeds:
                for p in env_feeds.replace(";", ",").split(","):
                    p_clean = p.strip()
                    if p_clean:
                        resolved_feeds.append(p_clean)

        self.threat_intel_engine = ThreatIntelEngine(feed_dir_or_paths=resolved_feeds if resolved_feeds else None)

        self._alert_id_counter = 0
        self.alerts_history: List[IDSAlert] = []

        # Metrics
        self.total_alerts = 0
        self.severity_counts: Dict[str, int] = {
            Severity.LOW.value: 0,
            Severity.MEDIUM.value: 0,
            Severity.HIGH.value: 0,
            Severity.CRITICAL.value: 0,
        }
        self.category_counts: Dict[str, int] = {}

    def _next_alert_id(self) -> int:
        self._alert_id_counter += 1
        return self._alert_id_counter

    def evaluate(self, packet: ParsedPacket, dpi_result: Optional[DPIResult]) -> List[IDSAlert]:
        """
        Runs signature, specialized HTTP threat, and behavioural analysis on the packet.

        Args:
            packet: ParsedPacket from Phase 1.
            dpi_result: DPIResult from DPIEngine.

        Returns:
            List of generated IDSAlert objects.
        """
        alerts: List[IDSAlert] = []

        # 1. Signature-based inspection
        if dpi_result:
            sig_alerts = self.signature_detector.evaluate(packet, dpi_result, self._next_alert_id)
            alerts.extend(sig_alerts)

        # 2. Specialized HTTP Threat Detectors (Detection-Only)
        if dpi_result and dpi_result.metadata:
            http_msgs = dpi_result.metadata.get("http_messages", [])
            # Fallback to single http metadata if http_messages not present
            if not http_msgs and "http" in dpi_result.metadata:
                http_msgs = [dpi_result.metadata["http"]]

            for http_meta in http_msgs:
                # Parser state safety gating:
                # 1. Incomplete messages: defer inspection
                if not getattr(http_meta, "is_complete", True):
                    continue

                # 2. Ambiguous framing: do not produce attack classifications
                framing = getattr(http_meta, "framing_method", "")
                if "AMBIGUOUS" in framing:
                    continue

                # 3. Truncated messages: do not produce confirmed attack alerts; emit informational warning if needed
                if getattr(http_meta, "is_truncated", False):
                    continue

                alert_ctx = {
                    "message_id": getattr(http_meta, "message_id", ""),
                    "alerted_rules": set(),
                }

                # Evaluate each HTTP threat detector with fault isolation
                for detector in self.http_detectors:
                    try:
                        det_alerts = detector.evaluate(
                            http_meta=http_meta,
                            packet=packet,
                            next_alert_id_fn=self._next_alert_id,
                            alert_context=alert_ctx,
                        )
                        # Guarantee detection-only safety: never allow BLOCK or CRITICAL
                        for a in det_alerts:
                            if a.recommended_action == DecisionAction.BLOCK:
                                a.recommended_action = DecisionAction.ALERT
                            if a.severity == Severity.CRITICAL:
                                a.severity = Severity.HIGH
                        alerts.extend(det_alerts)
                    except Exception as det_err:
                        logger.error(
                            f"Detector {detector.__class__.__name__} failed safely on packet {packet.packet_id}: {det_err}",
                            exc_info=True,
                        )

            # Phase 4.2 Specialized DNS Threat Evaluation
            dns_meta = dpi_result.metadata.get("dns")
            if dns_meta:
                try:
                    dns_alerts = self.dns_threat_engine.evaluate(
                        dns_meta=dns_meta,
                        packet=packet,
                        next_alert_id_fn=self._next_alert_id,
                        now=packet.timestamp,
                    )
                    # Enforce detection-only invariants: ALERT only, never BLOCK or CRITICAL
                    for da in dns_alerts:
                        if da.recommended_action == DecisionAction.BLOCK:
                            da.recommended_action = DecisionAction.ALERT
                        if da.severity == Severity.CRITICAL:
                            da.severity = Severity.HIGH
                    alerts.extend(dns_alerts)
                except Exception as dns_err:
                    logger.error(
                        f"DNSThreatEngine failed safely on packet {packet.packet_id}: {dns_err}",
                        exc_info=True,
                    )

        # Phase 4.3 Modular Threat Intelligence and Reputation Evaluation
        try:
            ti_alerts = self.threat_intel_engine.evaluate_packet(
                packet=packet,
                dpi_result=dpi_result,
                next_alert_id_fn=self._next_alert_id,
                now=packet.timestamp,
            )
            alerts.extend(ti_alerts)
        except Exception as ti_err:
            logger.error(
                f"ThreatIntelEngine failed safely on packet {packet.packet_id}: {ti_err}",
                exc_info=True,
            )

        # 3. Behavioural analysis (Rate thresholds, scans, floods, errors)
        beh_alerts = self.behaviour_detector.evaluate(packet, dpi_result, self._next_alert_id)
        alerts.extend(beh_alerts)

        # Record statistics
        for alert in alerts:
            self.total_alerts += 1
            self.alerts_history.append(alert)
            sev = alert.severity.value
            self.severity_counts[sev] = self.severity_counts.get(sev, 0) + 1
            cat = alert.category.value
            self.category_counts[cat] = self.category_counts.get(cat, 0) + 1

        return alerts

