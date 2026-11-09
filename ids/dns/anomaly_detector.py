"""DNS Transaction Correlation and Response Anomaly Detector.

Tracks in-flight transactions using strict 7-tuple matching with timestamp validation,
handles asymmetric captures without false cache poisoning alarms, detects Fast Flux
low-TTL response pools across IPv4 /24 and IPv6 /48 prefixes, and detects SERVFAIL/REFUSED
error bursts with bounded cooldown tracking and periodic memory cleanup.
"""

from __future__ import annotations

import ipaddress
import logging
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from dpi.dns_inspector import DNSMetadata
from ids.dns.common import get_packet_endpoints
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger(__name__)


@dataclass
class PendingQuery:
    """Represents a recorded in-flight DNS query."""
    tx_id: int
    client_ip: str
    server_ip: str
    client_port: int
    server_port: int
    query_name: str
    qtype_code: int
    transport: str
    timestamp: float


class DNSTransactionCorrelationTracker:
    """
    Correlates DNS queries and responses using robust multi-tuple keying with bounded memory.
    Supports strict 7-tuple matching and validated relaxed matching.
    """

    def __init__(self, max_in_flight: int = 5000, query_timeout: float = 10.0) -> None:
        self.max_in_flight = max_in_flight
        self.query_timeout = query_timeout

        # Strict 7-tuple table:
        # (tx_id, client_ip, server_ip, client_port, qname_lower, qtype_code, transport) -> PendingQuery
        self._strict_table: Dict[Tuple[int, str, str, int, str, int, str], PendingQuery] = {}

        # Relaxed secondary lookup index: (tx_id, qname_lower, qtype_code) -> List[PendingQuery]
        self._relaxed_index: Dict[Tuple[int, str, int], List[PendingQuery]] = defaultdict(list)

    def record_query(
        self,
        tx_id: int,
        client_ip: str,
        server_ip: str,
        client_port: int,
        server_port: int,
        query_name: str,
        qtype_code: int,
        transport: str,
        now: float,
    ) -> None:
        """Records an in-flight DNS query."""
        self._expire(now)

        qname_lower = query_name.strip().lower().rstrip(".")
        strict_key = (tx_id, client_ip, server_ip, client_port, qname_lower, qtype_code, transport)

        # Evict oldest entry if capacity reached
        if strict_key not in self._strict_table and len(self._strict_table) >= self.max_in_flight:
            oldest_key = min(self._strict_table.keys(), key=lambda k: self._strict_table[k].timestamp)
            old_pq = self._strict_table.pop(oldest_key)
            rel_k = (old_pq.tx_id, old_pq.query_name, old_pq.qtype_code)
            if rel_k in self._relaxed_index:
                self._relaxed_index[rel_k] = [q for q in self._relaxed_index[rel_k] if q != old_pq]

        pq = PendingQuery(
            tx_id=tx_id,
            client_ip=client_ip,
            server_ip=server_ip,
            client_port=client_port,
            server_port=server_port,
            query_name=qname_lower,
            qtype_code=qtype_code,
            transport=transport,
            timestamp=now,
        )
        self._strict_table[strict_key] = pq
        self._relaxed_index[(tx_id, qname_lower, qtype_code)].append(pq)

    def match_response(
        self,
        tx_id: int,
        server_ip: str,
        client_ip: str,
        server_port: int,
        client_port: int,
        query_name: str,
        qtype_code: int,
        transport: str,
        now: float,
    ) -> Tuple[Optional[float], bool]:
        """
        Attempts to match an incoming DNS response against recorded in-flight queries.
        
        Returns:
            Tuple of (rtt_ms, is_unmatched).
            If matched: (float, False).
            If unmatched: (None, True).
        """
        self._expire(now)
        qname_lower = query_name.strip().lower().rstrip(".")

        # 1. Attempt strict 7-tuple match (inverting server/client IPs and ports)
        strict_key = (tx_id, client_ip, server_ip, client_port, qname_lower, qtype_code, transport)
        if strict_key in self._strict_table:
            pq = self._strict_table.pop(strict_key)
            rel_k = (tx_id, qname_lower, qtype_code)
            if rel_k in self._relaxed_index:
                self._relaxed_index[rel_k] = [q for q in self._relaxed_index[rel_k] if q != pq]
            rtt = max(0.0, (now - pq.timestamp) * 1000.0)
            return round(rtt, 2), False

        # 2. Attempt validated relaxed match for asymmetric capture
        # Must match (tx_id, qname_lower, qtype_code), validate timestamp window (< 10s),
        # use server address where available, and reject ambiguous matches.
        rel_k = (tx_id, qname_lower, qtype_code)
        candidates = self._relaxed_index.get(rel_k, [])
        valid_candidates = [
            q for q in candidates
            if now - q.timestamp <= self.query_timeout
            and (q.client_ip == client_ip or q.server_ip == server_ip)
        ]

        # Reject ambiguous matches: if more than 1 candidate matches, never guess
        if len(valid_candidates) == 1:
            matched_pq = valid_candidates[0]
            # Remove from index and strict table
            self._relaxed_index[rel_k].remove(matched_pq)
            st_k = (
                matched_pq.tx_id,
                matched_pq.client_ip,
                matched_pq.server_ip,
                matched_pq.client_port,
                matched_pq.query_name,
                matched_pq.qtype_code,
                matched_pq.transport,
            )
            self._strict_table.pop(st_k, None)
            rtt = max(0.0, (now - matched_pq.timestamp) * 1000.0)
            return round(rtt, 2), False

        return None, True

    def _expire(self, now: float) -> None:
        """Expires stale in-flight transactions."""
        expired_keys = [k for k, pq in self._strict_table.items() if now - pq.timestamp > self.query_timeout]
        for k in expired_keys:
            pq = self._strict_table.pop(k)
            rel_k = (pq.tx_id, pq.query_name, pq.qtype_code)
            if rel_k in self._relaxed_index:
                self._relaxed_index[rel_k] = [q for q in self._relaxed_index[rel_k] if q != pq]
                if not self._relaxed_index[rel_k]:
                    del self._relaxed_index[rel_k]


class DNSAnomalyDetector:
    """
    Detects DNS response anomalies including Fast Flux low TTLs across IPv4/IPv6,
    unsolicited response bursts, and SERVFAIL/REFUSED error bursts.
    """

    def __init__(self) -> None:
        self.tracker = DNSTransactionCorrelationTracker()

        # Track unmatched responses per destination host: dst_ip -> deque of timestamps
        self._unmatched_tracker: Dict[str, deque] = defaultdict(deque)

        # Track DNS response error bursts: (dst_ip, rcode_name) -> deque of timestamps
        self._error_burst_tracker: Dict[Tuple[str, str], deque] = defaultdict(deque)

        # Bounded cooldown tracker for error bursts: (dst_ip, rcode_name) -> last_alert_time
        self._error_cooldown_tracker: Dict[Tuple[str, str], float] = {}

        self._last_cleanup_time = 0.0

    def process_query(self, dns_meta: DNSMetadata, packet: ParsedPacket, now: float) -> None:
        """Records an outgoing DNS query."""
        if not dns_meta.questions or dns_meta.is_response:
            return

        src_ip, dst_ip, src_port, dst_port = get_packet_endpoints(packet)
        transport = "UDP" if (hasattr(packet, "udp") and packet.udp) else "TCP"

        q = dns_meta.questions[0]
        self.tracker.record_query(
            tx_id=dns_meta.tx_id,
            client_ip=src_ip,
            server_ip=dst_ip,
            client_port=src_port,
            server_port=dst_port,
            query_name=q.name,
            qtype_code=q.qtype_code,
            transport=transport,
            now=now,
        )

    def evaluate_response(
        self,
        dns_meta: DNSMetadata,
        packet: ParsedPacket,
        next_alert_id_fn: callable,
        now: float,
    ) -> List[IDSAlert]:
        """
        Evaluates an incoming DNS response for Fast Flux pools, low TTL, unsolicited bursts,
        and SERVFAIL/REFUSED error bursts.
        """
        if not dns_meta.is_response:
            return []

        src_ip, dst_ip, src_port, dst_port = get_packet_endpoints(packet)
        # Note: in responses, src_ip is the DNS server, dst_ip is the client receiving it
        transport = "UDP" if (hasattr(packet, "udp") and packet.udp) else "TCP"

        alerts: List[IDSAlert] = []
        qname = dns_meta.query_name
        qtype_code = dns_meta.questions[0].qtype_code if dns_meta.questions else 1

        self._periodic_cleanup(now)

        # 1. Transaction Correlation Check
        rtt_ms, is_unmatched = self.tracker.match_response(
            tx_id=dns_meta.tx_id,
            server_ip=src_ip,
            client_ip=dst_ip,
            server_port=src_port,
            client_port=dst_port,
            query_name=qname,
            qtype_code=qtype_code,
            transport=transport,
            now=now,
        )
        dns_meta.rtt_ms = rtt_ms

        if is_unmatched:
            # Low-confidence anomaly handling: account for asymmetric capture.
            # Require a burst of unmatched responses (>= 5 within 5 seconds to same host)
            uq = self._unmatched_tracker[dst_ip]
            uq.append(now)
            while uq and now - uq[0] > 5.0:
                uq.popleft()

            if len(uq) >= 5:
                evidence = (
                    f"Observed {len(uq)} unmatched DNS responses in 5s (TxID=0x{dns_meta.tx_id:04x}, Domain='{qname[:32]}'). "
                    f"Low confidence: potential unsolicited spoofing or asymmetric network capture."
                )
                alerts.append(
                    IDSAlert.create(
                        alert_id=next_alert_id_fn(),
                        timestamp=now,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        protocol="DNS",
                        category=DetectionCategory.SUSPICIOUS_DNS,
                        severity=Severity.LOW,
                        matched_rule="Unsolicited DNS Response Burst (Low Confidence)",
                        evidence=evidence[:256],
                        recommended_action=DecisionAction.ALERT,
                        packet_id=packet.packet_id,
                    )
                )

        # 2. Fast Flux / Ultra-Low TTL Multi-IP Pool Detection (IPv4 /24 and IPv6 /48)
        a_records = [ans for ans in dns_meta.answers if ans.rtype_code in (1, 28)]
        if len(a_records) >= 5:
            min_ttl = min(ans.ttl for ans in a_records)
            if min_ttl <= 15:
                network_prefixes: Set[str] = set()
                for ans in a_records:
                    if ans.rtype_code == 1:  # IPv4 (A)
                        try:
                            v4_net = ipaddress.IPv4Network(f"{ans.rdata}/24", strict=False)
                            network_prefixes.add(str(v4_net))
                        except (ipaddress.AddressValueError, ValueError):
                            continue
                    elif ans.rtype_code == 28:  # IPv6 (AAAA)
                        try:
                            # Standard IPv6 /48 prefix extraction using ipaddress
                            clean_ipv6 = ans.rdata.split("%")[0].strip()
                            v6_addr = ipaddress.IPv6Address(clean_ipv6)
                            v6_net = ipaddress.IPv6Network(f"{v6_addr}/48", strict=False)
                            network_prefixes.add(str(v6_net))
                        except (ipaddress.AddressValueError, ValueError):
                            continue

                if len(network_prefixes) >= 3:
                    evidence = (
                        f"Fast Flux Suspicion: Domain '{qname[:48]}' resolved {len(a_records)} IP addresses "
                        f"across {len(network_prefixes)} distinct prefixes (IPv4 /24 or IPv6 /48) with ultra-low TTL ({min_ttl}s)."
                    )
                    alerts.append(
                        IDSAlert.create(
                            alert_id=next_alert_id_fn(),
                            timestamp=now,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            source_port=src_port,
                            destination_port=dst_port,
                            protocol="DNS",
                            category=DetectionCategory.SUSPICIOUS_DNS,
                            severity=Severity.MEDIUM,
                            matched_rule="Fast Flux Low-TTL Multi-Subnet DNS Response",
                            evidence=evidence[:256],
                            recommended_action=DecisionAction.ALERT,
                            packet_id=packet.packet_id,
                        )
                    )

        # 3. DNS Response Error Bursts (SERVFAIL & REFUSED)
        rcode_code = dns_meta.rcode_code
        if rcode_code in (2, 5):  # 2: SERVFAIL, 5: REFUSED
            rcode_name = "SERVFAIL" if rcode_code == 2 else "REFUSED"
            error_key = (dst_ip, rcode_name)

            eq = self._error_burst_tracker[error_key]
            eq.append(now)
            while eq and now - eq[0] > 10.0:
                eq.popleft()

            # Threshold: at least 15 responses within 10 seconds
            if len(eq) >= 15:
                last_alert_time = self._error_cooldown_tracker.get(error_key, 0.0)
                # Bounded cooldown of 30 seconds per host per RCODE
                if now - last_alert_time >= 30.0:
                    self._error_cooldown_tracker[error_key] = now
                    severity = Severity.LOW if rcode_code == 2 else Severity.MEDIUM
                    rule_desc = (
                        "Resolver Failure / Misconfiguration Burst"
                        if rcode_code == 2
                        else "Policy Refusal / Zone Transfer Attempt Burst"
                    )
                    evidence = (
                        f"Observed {len(eq)} DNS {rcode_name} error responses in 10.0s for host {dst_ip}. "
                        f"{rule_desc}."
                    )
                    alerts.append(
                        IDSAlert.create(
                            alert_id=next_alert_id_fn(),
                            timestamp=now,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            source_port=src_port,
                            destination_port=dst_port,
                            protocol="DNS",
                            category=DetectionCategory.SUSPICIOUS_DNS,
                            severity=severity,
                            matched_rule=f"DNS Response Error Burst ({rcode_name})",
                            evidence=evidence[:256],
                            recommended_action=DecisionAction.ALERT,
                            packet_id=packet.packet_id,
                        )
                    )

        return alerts

    def _periodic_cleanup(self, now: float) -> None:
        """
        Periodically prunes empty/stale destination keys across trackers without scanning on every packet.
        Throttled to run at most once every 5.0 seconds.
        """
        if now - self._last_cleanup_time < 5.0:
            return
        self._last_cleanup_time = now

        # Prune inactive unmatched destination IP keys
        stale_unmatched = [ip for ip, q in self._unmatched_tracker.items() if not q or now - q[-1] > 5.0]
        for ip in stale_unmatched:
            del self._unmatched_tracker[ip]

        # Enforce hard capacity limit on unmatched tracker
        if len(self._unmatched_tracker) > 2000:
            excess = len(self._unmatched_tracker) - 2000
            for ip in list(self._unmatched_tracker.keys())[:excess]:
                del self._unmatched_tracker[ip]

        # Prune inactive error burst keys
        stale_errors = [k for k, q in self._error_burst_tracker.items() if not q or now - q[-1] > 10.0]
        for k in stale_errors:
            del self._error_burst_tracker[k]

        if len(self._error_burst_tracker) > 2000:
            excess = len(self._error_burst_tracker) - 2000
            for k in list(self._error_burst_tracker.keys())[:excess]:
                del self._error_burst_tracker[k]

        # Prune expired cooldown entries (older than 60s)
        stale_cooldowns = [k for k, ts in self._error_cooldown_tracker.items() if now - ts > 60.0]
        for k in stale_cooldowns:
            del self._error_cooldown_tracker[k]
