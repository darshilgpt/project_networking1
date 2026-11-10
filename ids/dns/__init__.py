"""DNS Threat Engine coordinator and package exports."""

from __future__ import annotations

import logging
from typing import List, Optional

from dpi.dns_inspector import DNSMetadata
from ids.dns.anomaly_detector import DNSAnomalyDetector
from ids.dns.common import BoundedLRUCache, extract_apex_and_subdomain, get_packet_endpoints
from ids.dns.dga_detector import DNSDGADetector
from ids.dns.tunneling_detector import DNSTunnelingDetector
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger(__name__)


class DNSThreatEngine:
    """
    Coordinates DNS threat detection modules with duplicate suppression,
    cooldown management, and strictly detection-only safety guarantees.
    """

    def __init__(self) -> None:
        self.dga_detector = DNSDGADetector()
        self.tunneling_detector = DNSTunnelingDetector()
        self.anomaly_detector = DNSAnomalyDetector()

        # Cooldown caches to prevent alert spam: key -> last_alert_time
        # Max 2000 active entries with 60-second TTL
        self._cooldown_cache = BoundedLRUCache(max_size=2000, ttl_seconds=60.0)

    def evaluate(
        self,
        dns_meta: DNSMetadata,
        packet: ParsedPacket,
        next_alert_id_fn: callable,
        now: Optional[float] = None,
    ) -> List[IDSAlert]:
        """
        Evaluates a parsed DNS packet across all DNS threat detectors.
        """
        current_time = now if now is not None else (packet.timestamp or 0.0)
        alerts: List[IDSAlert] = []

        qname = dns_meta.query_name
        qtype_name = dns_meta.questions[0].qtype_name if dns_meta.questions else "A"
        src_ip, _, _, _ = get_packet_endpoints(packet)

        apex, _ = extract_apex_and_subdomain(qname)

        # 1. Process Transaction Tracking
        if not dns_meta.is_response:
            self.anomaly_detector.process_query(dns_meta, packet, current_time)
        else:
            resp_alerts = self.anomaly_detector.evaluate_response(dns_meta, packet, next_alert_id_fn, current_time)
            alerts.extend(resp_alerts)

        # 2. Heuristic DGA Detection (evaluated on query name)
        if qname:
            dga_key = f"DNS_DGA:{apex or qname}"
            if not self._cooldown_cache.get(dga_key, current_time):
                dga_alerts = self.dga_detector.evaluate(qname, packet, next_alert_id_fn, current_time)
                if dga_alerts:
                    self._cooldown_cache.set(dga_key, current_time, current_time)
                    alerts.extend(dga_alerts)

        # 3. DNS Tunneling Detection
        if qname:
            tunnel_key = f"DNS_TUNNEL:{src_ip}:{apex or qname}"
            if not self._cooldown_cache.get(tunnel_key, current_time):
                # Collect any TXT record strings for SPF/DKIM verification exemption
                txt_records = [ans.rdata for ans in dns_meta.answers if ans.rtype_code == 16]
                tunnel_alerts = self.tunneling_detector.evaluate(
                    domain_name=qname,
                    qtype_name=qtype_name,
                    packet=packet,
                    next_alert_id_fn=next_alert_id_fn,
                    now=current_time,
                    txt_records=txt_records,
                )
                if tunnel_alerts:
                    self._cooldown_cache.set(tunnel_key, current_time, current_time)
                    alerts.extend(tunnel_alerts)

        # Enforce Detection-Only Safety Invariant:
        # Never allow BLOCK action or CRITICAL severity from DNS threat detectors
        for alert in alerts:
            if alert.recommended_action == DecisionAction.BLOCK:
                alert.recommended_action = DecisionAction.ALERT
            if alert.severity == Severity.CRITICAL:
                alert.severity = Severity.HIGH

        return alerts


__all__ = [
    "DNSThreatEngine",
    "DNSDGADetector",
    "DNSTunnelingDetector",
    "DNSAnomalyDetector",
]
