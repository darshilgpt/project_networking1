"""Threat Intelligence and Reputation Detection package."""

from __future__ import annotations

from ids.threat_intel.common import ThreatIndicator, normalize_domain, normalize_ip, normalize_network
from ids.threat_intel.domain_reputation import DomainReputationMatcher
from ids.threat_intel.feed_manager import FeedManager
from ids.threat_intel.ip_reputation import IPReputationMatcher
from ids.threat_intel.reputation_engine import ThreatIntelEngine

__all__ = [
    "ThreatIndicator",
    "ThreatIntelEngine",
    "FeedManager",
    "IPReputationMatcher",
    "DomainReputationMatcher",
    "normalize_domain",
    "normalize_ip",
    "normalize_network",
]

