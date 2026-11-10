"""Threat Intelligence and Reputation Engine coordinator."""

from __future__ import annotations

import logging
import os
import threading
import time
from typing import Dict, List, Optional, Set, Tuple

from ids.threat_intel.common import (
    BoundedTTLCache,
    ThreatIndicator,
    normalize_domain,
    normalize_ip,
)
from ids.threat_intel.domain_reputation import DomainReputationMatcher
from ids.threat_intel.feed_manager import FeedManager
from ids.threat_intel.ip_reputation import IPReputationMatcher
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger("dpi_ids_ips.ids.threat_intel.engine")


class ThreatIntelEngine:
    """
    Coordinates IP and Domain reputation lookups with allowlist precedence,
    bounded TTL caching, safe feed reloading, and strictly detection-only safety guarantees.
    """

    def __init__(self, feed_dir_or_paths: Optional[List[str]] = None) -> None:
        self.feed_manager = FeedManager()
        self.ip_matcher = IPReputationMatcher()
        self.domain_matcher = DomainReputationMatcher()

        # Bounded lookup caches: key -> (ThreatIndicator or False)
        # Prevents repeated CIDR traverses or string splits for frequent packets
        self._ip_cache = BoundedTTLCache(max_size=5000, ttl_seconds=60.0)
        self._domain_cache = BoundedTTLCache(max_size=5000, ttl_seconds=60.0)

        # Cooldown cache to prevent alert flooding: key -> last_alert_time
        self._alert_cooldown = BoundedTTLCache(max_size=3000, ttl_seconds=60.0)

        # Allowlist: IPs, CIDRs, and domains that must never generate threat intel alerts
        self._allowlist_ips: Set[str] = {"127.0.0.1", "::1", "0.0.0.0"}
        self._allowlist_domains: Set[str] = {"localhost", "local", "internal"}

        self._lock = threading.RLock()

        # Statistics
        self.total_ip_lookups = 0
        self.total_domain_lookups = 0
        self.total_reputation_matches = 0

        # Load built-in seed intelligence
        self._load_seed_intel()

        # Load feeds if provided
        if feed_dir_or_paths:
            for p in feed_dir_or_paths:
                self.load_feed_file(p)

    def _load_seed_intel(self) -> None:
        """Seeds known malicious baseline indicators."""
        seed_indicators = [
            # IP indicators
            ThreatIndicator(indicator="198.51.100.23", ioc_type="IPv4", category="C2", severity=Severity.HIGH, description="Known Cobalt Strike C2 server", source="seed_intel"),
            ThreatIndicator(indicator="203.0.113.88", ioc_type="IPv4", category="SCANNER", severity=Severity.HIGH, description="Mirai botnet scanning node", source="seed_intel"),
            ThreatIndicator(indicator="185.220.101.5", ioc_type="IPv4", category="TOR_EXIT", severity=Severity.MEDIUM, description="Tor exit node used in brute force", source="seed_intel"),
            ThreatIndicator(indicator="45.154.255.99", ioc_type="IPv4", category="MALWARE", severity=Severity.HIGH, description="Emotet malware delivery host", source="seed_intel"),
            ThreatIndicator(indicator="192.0.2.66", ioc_type="IPv4", category="RECON", severity=Severity.HIGH, description="Masscan / Shodan reconnaissance scanner", source="seed_intel"),
            ThreatIndicator(indicator="2001:db8:dead:beef::1", ioc_type="IPv6", category="C2", severity=Severity.HIGH, description="Known IPv6 ransomware C2 server", source="seed_intel"),
            ThreatIndicator(indicator="198.51.100.0/24", ioc_type="IPv4_CIDR", category="BOTNET", severity=Severity.HIGH, description="Bulletproof hosting botnet subnet", source="seed_intel"),
            ThreatIndicator(indicator="2001:db8:bad::/48", ioc_type="IPv6_CIDR", category="MALWARE", severity=Severity.HIGH, description="Malicious IPv6 hosting allocation", source="seed_intel"),
            # Domain indicators
            ThreatIndicator(indicator="evil-c2-server.com", ioc_type="DOMAIN", category="C2", severity=Severity.HIGH, description="Known ransomware C2 domain", source="seed_intel"),
            ThreatIndicator(indicator="phishing-bank-login.xyz", ioc_type="DOMAIN", category="PHISHING", severity=Severity.HIGH, description="Credential harvesting portal", source="seed_intel"),
            ThreatIndicator(indicator="crypto-miner-pool.top", ioc_type="DOMAIN", category="MALWARE", severity=Severity.MEDIUM, description="Cryptojacking mining pool", source="seed_intel"),
            ThreatIndicator(indicator="malicious-payload-drop.buzz", ioc_type="DOMAIN", category="MALWARE", severity=Severity.HIGH, description="Trojan dropper URL domain", source="seed_intel"),
        ]
        self.ip_matcher.load_indicators(seed_indicators)
        self.domain_matcher.load_indicators(seed_indicators)

    def add_to_allowlist(self, ip_or_domain: str) -> None:
        """Adds an IP or domain to the engine allowlist to prevent alert generation."""
        val = ip_or_domain.strip().lower().rstrip(".")
        if ":" in val or (val.replace(".", "").isdigit() and val.count(".") == 3):
            self._allowlist_ips.add(val)
        else:
            self._allowlist_domains.add(val)

    def load_feed_file(self, filepath: str) -> bool:
        """
        Loads indicators from a single local file (Plaintext, CSV, or JSON).
        Validates entries atomically: does not replace working indices if reading fails.
        """
        if not os.path.exists(filepath):
            logger.warning(f"Threat feed file not found: {filepath}")
            return False

        ext = os.path.splitext(filepath)[1].lower()
        new_indicators: List[ThreatIndicator] = []

        try:
            if ext in (".txt", ".list"):
                new_indicators = self.feed_manager.parse_plain_text(filepath)
            elif ext == ".csv":
                new_indicators = self.feed_manager.parse_csv(filepath)
            elif ext == ".json":
                new_indicators = self.feed_manager.parse_json(filepath)
            else:
                # Default to plaintext
                new_indicators = self.feed_manager.parse_plain_text(filepath)

            with self._lock:
                self.ip_matcher.load_indicators(new_indicators)
                self.domain_matcher.load_indicators(new_indicators)
                self._ip_cache.clear()
                self._domain_cache.clear()
            logger.info(f"Loaded {len(new_indicators)} threat indicators from '{filepath}'")
            return True
        except Exception as e:
            logger.error(f"Failed loading threat feed '{filepath}': {e}", exc_info=True)
            return False

    def check_ip(self, ip_str: str, now: Optional[float] = None) -> Optional[ThreatIndicator]:
        """Checks an IP address against the threat intelligence database with allowlist and cache."""
        self.total_ip_lookups += 1
        norm_ip = normalize_ip(ip_str)
        if not norm_ip or norm_ip in self._allowlist_ips:
            return None

        current_time = now if now is not None else time.time()

        # Check cache
        cached = self._ip_cache.get(norm_ip, current_time)
        if cached is not None:
            return cached if isinstance(cached, ThreatIndicator) else None

        with self._lock:
            match = self.ip_matcher.match(norm_ip, current_time)

        if match:
            self.total_reputation_matches += 1
            self._ip_cache.set(norm_ip, match, current_time)
            return match
        else:
            self._ip_cache.set(norm_ip, False, current_time)
            return None

    def check_domain(self, domain_name: str, now: Optional[float] = None) -> Optional[ThreatIndicator]:
        """Checks a domain name against the threat intelligence database with allowlist and cache."""
        self.total_domain_lookups += 1
        clean = normalize_domain(domain_name)
        if not clean or clean in self._allowlist_domains:
            return None

        # Check allowlist parent hierarchy
        parts = clean.split(".")
        for i in range(len(parts)):
            if ".".join(parts[i:]) in self._allowlist_domains:
                return None

        current_time = now if now is not None else time.time()

        # Check cache
        cached = self._domain_cache.get(clean, current_time)
        if cached is not None:
            return cached if isinstance(cached, ThreatIndicator) else None

        with self._lock:
            match = self.domain_matcher.match(clean, current_time)

        if match:
            self.total_reputation_matches += 1
            self._domain_cache.set(clean, match, current_time)
            return match
        else:
            self._domain_cache.set(clean, False, current_time)
            return None

    def evaluate_packet(
        self,
        packet: ParsedPacket,
        dpi_result: Optional[Any],
        next_alert_id_fn: callable,
        now: Optional[float] = None,
    ) -> List[IDSAlert]:
        """
        Evaluates source IP, destination IP, DNS query, HTTP host, and TLS SNI
        against threat intelligence. Enforces strictly detection-only ALERT invariant.
        """
        current_time = now if now is not None else (packet.timestamp or time.time())
        alerts: List[IDSAlert] = []

        # Extract IPs and ports
        if hasattr(packet, "ipv4") and packet.ipv4:
            src_ip = packet.ipv4.src_ip
            dst_ip = packet.ipv4.dst_ip
            proto = packet.ipv4.protocol_name
        elif hasattr(packet, "ipv6") and packet.ipv6:
            src_ip = packet.ipv6.src_ip
            dst_ip = packet.ipv6.dst_ip
            proto = packet.ipv6.protocol_name
        else:
            return alerts

        src_port = packet.udp.src_port if packet.udp else (packet.tcp.src_port if packet.tcp else 0)
        dst_port = packet.udp.dst_port if packet.udp else (packet.tcp.dst_port if packet.tcp else 0)

        # 1. Source IP Reputation Check
        rep_src = self.check_ip(src_ip, current_time)
        if rep_src:
            cooldown_key = f"TI_IP_SRC:{src_ip}:{rep_src.category}"
            if not self._alert_cooldown.get(cooldown_key, current_time):
                self._alert_cooldown.set(cooldown_key, current_time, current_time)
                evidence = (
                    f"Threat Intelligence Match: Source IP {src_ip} matches {rep_src.ioc_type} IOC '{rep_src.indicator}' "
                    f"[Feed: {rep_src.source}, Category: {rep_src.category}, Confidence: {rep_src.confidence:.2f}]. "
                    f"Description: {rep_src.description}."
                )
                alerts.append(
                    IDSAlert.create(
                        alert_id=next_alert_id_fn(),
                        timestamp=current_time,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        protocol=proto,
                        category=DetectionCategory.MALICIOUS_IP,
                        severity=Severity.HIGH if rep_src.severity == Severity.CRITICAL else rep_src.severity,
                        matched_rule=f"Threat Intelligence IP: {rep_src.category}",
                        evidence=evidence[:256],
                        recommended_action=DecisionAction.ALERT,
                        packet_id=packet.packet_id,
                    )
                )

        # 2. Destination IP Reputation Check
        rep_dst = self.check_ip(dst_ip, current_time)
        if rep_dst:
            cooldown_key = f"TI_IP_DST:{dst_ip}:{rep_dst.category}"
            if not self._alert_cooldown.get(cooldown_key, current_time):
                self._alert_cooldown.set(cooldown_key, current_time, current_time)
                evidence = (
                    f"Threat Intelligence Match: Destination IP {dst_ip} matches {rep_dst.ioc_type} IOC '{rep_dst.indicator}' "
                    f"[Feed: {rep_dst.source}, Category: {rep_dst.category}, Confidence: {rep_dst.confidence:.2f}]. "
                    f"Description: {rep_dst.description}."
                )
                alerts.append(
                    IDSAlert.create(
                        alert_id=next_alert_id_fn(),
                        timestamp=current_time,
                        source_ip=src_ip,
                        destination_ip=dst_ip,
                        source_port=src_port,
                        destination_port=dst_port,
                        protocol=proto,
                        category=DetectionCategory.MALICIOUS_IP,
                        severity=Severity.HIGH if rep_dst.severity == Severity.CRITICAL else rep_dst.severity,
                        matched_rule=f"Threat Intelligence IP: {rep_dst.category}",
                        evidence=evidence[:256],
                        recommended_action=DecisionAction.ALERT,
                        packet_id=packet.packet_id,
                    )
                )

        # 3. Domain Reputation Check across DNS, HTTP Host, and TLS SNI
        candidate_domains: List[Tuple[str, str]] = []  # (domain, context_source)

        if dpi_result and dpi_result.metadata:
            # DNS Query
            dns_meta = dpi_result.metadata.get("dns")
            if dns_meta and getattr(dns_meta, "query_name", None):
                candidate_domains.append((dns_meta.query_name, "DNS Query"))

            # HTTP Host Header
            http_meta = dpi_result.metadata.get("http")
            if http_meta and getattr(http_meta, "host", None):
                # Strip optional port suffix from HTTP host (e.g. evil.com:8080)
                clean_host = http_meta.host.split(":")[0].strip()
                if clean_host:
                    candidate_domains.append((clean_host, "HTTP Host"))

            # TLS SNI
            tls_meta = dpi_result.metadata.get("tls")
            if tls_meta and getattr(tls_meta, "sni", None):
                candidate_domains.append((tls_meta.sni, "TLS SNI"))

        for dom, ctx in candidate_domains:
            rep_dom = self.check_domain(dom, current_time)
            if rep_dom:
                cooldown_key = f"TI_DOM:{dom}:{rep_dom.category}"
                if not self._alert_cooldown.get(cooldown_key, current_time):
                    self._alert_cooldown.set(cooldown_key, current_time, current_time)
                    evidence = (
                        f"Threat Intelligence Match: Observed {ctx} '{dom}' matches Domain IOC '{rep_dom.indicator}' "
                        f"[Feed: {rep_dom.source}, Category: {rep_dom.category}, Confidence: {rep_dom.confidence:.2f}]. "
                        f"Description: {rep_dom.description}."
                    )
                    alerts.append(
                        IDSAlert.create(
                            alert_id=next_alert_id_fn(),
                            timestamp=current_time,
                            source_ip=src_ip,
                            destination_ip=dst_ip,
                            source_port=src_port,
                            destination_port=dst_port,
                            protocol=proto,
                            category=DetectionCategory.MALICIOUS_DOMAIN,
                            severity=Severity.HIGH if rep_dom.severity == Severity.CRITICAL else rep_dom.severity,
                            matched_rule=f"Threat Intelligence Domain: {rep_dom.category}",
                            evidence=evidence[:256],
                            recommended_action=DecisionAction.ALERT,
                            packet_id=packet.packet_id,
                        )
                    )

        # Enforce Detection-Only Invariants:
        # Never allow recommended_action = DecisionAction.BLOCK
        # Never allow severity = Severity.CRITICAL
        for a in alerts:
            if a.recommended_action == DecisionAction.BLOCK:
                a.recommended_action = DecisionAction.ALERT
            if a.severity == Severity.CRITICAL:
                a.severity = Severity.HIGH

        return alerts

