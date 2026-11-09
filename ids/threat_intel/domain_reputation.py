"""Domain Reputation matcher supporting exact and properly bounded subdomain matching."""

from __future__ import annotations

import logging
from typing import Dict, List, Optional, Set

from ids.threat_intel.common import ThreatIndicator, normalize_domain

logger = logging.getLogger("dpi_ids_ips.ids.threat_intel.domain")


class DomainReputationMatcher:
    """
    Performs normalized domain reputation lookups.
    Supports exact domain matching and bounded parent subdomain containment
    (e.g., query 'sub.c2.evil.com' matches indicator 'evil.com', but
    'notevil.com' or 'evil.com.other.org' does NOT match).
    """

    def __init__(self) -> None:
        # Exact domain index: normalized_domain -> ThreatIndicator
        self._exact_domains: Dict[str, ThreatIndicator] = {}

    def load_indicators(self, indicators: List[ThreatIndicator]) -> None:
        """Loads domain indicators into the lookup index."""
        for ind in indicators:
            if ind.ioc_type == "DOMAIN":
                norm_d = normalize_domain(ind.indicator)
                self._exact_domains[norm_d] = ind

    def match(self, domain_name: str, now: Optional[float] = None) -> Optional[ThreatIndicator]:
        """
        Matches a domain name against known indicators.
        Checks exact match, then traverses parent labels (sub.evil.com -> evil.com).
        Never matches arbitrary substring suffixes (e.g. 'fake-evil.com' does not match 'evil.com').
        """
        if not domain_name:
            return None

        clean = normalize_domain(domain_name)
        if not clean:
            return None

        # 1. Exact match O(1)
        if clean in self._exact_domains:
            ind = self._exact_domains[clean]
            if not ind.is_expired(now):
                return ind

        # 2. Bounded parent subdomain match
        # Split on '.' and check each parent level: sub.target.evil.com -> target.evil.com -> evil.com
        parts = clean.split(".")
        for i in range(1, len(parts)):
            parent_candidate = ".".join(parts[i:])
            if parent_candidate in self._exact_domains:
                ind = self._exact_domains[parent_candidate]
                if not ind.is_expired(now):
                    return ind

        return None

    def clear(self) -> None:
        self._exact_domains.clear()

    def __len__(self) -> int:
        return len(self._exact_domains)

