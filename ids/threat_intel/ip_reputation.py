"""IP Reputation matcher supporting IPv4, IPv6, and CIDR subnet containment."""

from __future__ import annotations

import ipaddress
import logging
from typing import Dict, List, Optional, Tuple

from ids.threat_intel.common import ThreatIndicator, normalize_ip

logger = logging.getLogger("dpi_ids_ips.ids.threat_intel.ip")


class IPReputationMatcher:
    """
    Performs fast, normalized IP reputation lookups using exact match hash tables O(1)
    and sorted subnet containment searches.
    """

    def __init__(self) -> None:
        # Exact IP lookups: normalized_ip_str -> ThreatIndicator
        self._exact_ips: Dict[str, ThreatIndicator] = {}

        # Subnet lookups: List of (IPv4Network/IPv6Network, ThreatIndicator)
        self._ipv4_subnets: List[Tuple[ipaddress.IPv4Network, ThreatIndicator]] = []
        self._ipv6_subnets: List[Tuple[ipaddress.IPv6Network, ThreatIndicator]] = []

    def load_indicators(self, indicators: List[ThreatIndicator]) -> None:
        """Loads IP and CIDR indicators into the lookup indices."""
        for ind in indicators:
            if ind.ioc_type in ("IPv4", "IPv6"):
                self._exact_ips[ind.indicator] = ind
            elif ind.ioc_type in ("IPv4_CIDR", "IPv6_CIDR"):
                try:
                    net = ipaddress.ip_network(ind.indicator, strict=False)
                    if net.version == 4:
                        self._ipv4_subnets.append((net, ind))
                    else:
                        self._ipv6_subnets.append((net, ind))
                except ValueError:
                    logger.warning(f"Invalid network in IP reputation indicator: {ind.indicator}")

        # Sort subnets by prefix length descending (longest prefix match first)
        self._ipv4_subnets.sort(key=lambda item: item[0].prefixlen, reverse=True)
        self._ipv6_subnets.sort(key=lambda item: item[0].prefixlen, reverse=True)

    def match(self, ip_str: str, now: Optional[float] = None) -> Optional[ThreatIndicator]:
        """
        Matches an IP address string against exact and CIDR reputation indices.
        Returns matching non-expired ThreatIndicator or None.
        """
        if not ip_str or ip_str in ("0.0.0.0", "127.0.0.1", "::1"):
            return None

        norm_ip = normalize_ip(ip_str)
        if not norm_ip:
            return None

        # 1. Exact match O(1)
        if norm_ip in self._exact_ips:
            ind = self._exact_ips[norm_ip]
            if not ind.is_expired(now):
                return ind

        # 2. CIDR subnet match
        try:
            addr = ipaddress.ip_address(norm_ip)
            subnet_list = self._ipv4_subnets if addr.version == 4 else self._ipv6_subnets
            for net, ind in subnet_list:
                if addr in net:
                    if not ind.is_expired(now):
                        return ind
        except ValueError:
            pass

        return None

    def clear(self) -> None:
        self._exact_ips.clear()
        self._ipv4_subnets.clear()
        self._ipv6_subnets.clear()

    def __len__(self) -> int:
        return len(self._exact_ips) + len(self._ipv4_subnets) + len(self._ipv6_subnets)

