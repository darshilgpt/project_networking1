"""Common utilities, data classes, validation, and bounded caching for threat intelligence."""

from __future__ import annotations

import ipaddress
import logging
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from models.alert_model import Severity

logger = logging.getLogger("dpi_ids_ips.ids.threat_intel")


@dataclass
class ThreatIndicator:
    """Represents a validated threat intelligence indicator."""
    indicator: str
    ioc_type: str  # "IPv4", "IPv6", "IPv4_CIDR", "IPv6_CIDR", "DOMAIN"
    category: str  # e.g., C2, SCANNER, PHISHING, MALWARE, TOR_EXIT, RECON
    severity: Severity = Severity.HIGH
    confidence: float = 1.0  # 0.0 to 1.0
    source: str = "local_feed"
    description: str = ""
    first_seen: float = field(default_factory=time.time)
    expires_at: Optional[float] = None

    def is_expired(self, now: Optional[float] = None) -> bool:
        """Checks if the indicator has passed its expiration timestamp."""
        if self.expires_at is None:
            return False
        current = now if now is not None else time.time()
        return current >= self.expires_at


def normalize_domain(domain: str) -> str:
    """Normalizes domain strings: lowercase, strip whitespace, remove trailing dots."""
    return domain.strip().lower().rstrip(".")


def normalize_ip(ip_str: str) -> Optional[str]:
    """Validates and canonicalizes IPv4 or IPv6 address strings."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return str(addr)
    except ValueError:
        return None


def normalize_network(cidr_str: str) -> Optional[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Validates and parses IPv4 or IPv6 CIDR network strings."""
    try:
        net = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return net
    except ValueError:
        return None


class BoundedTTLCache:
    """A thread-safe, bounded LRU/FIFO cache with TTL support."""

    def __init__(self, max_size: int = 5000, ttl_seconds: float = 60.0) -> None:
        self.max_size = max_size
        self.ttl_seconds = ttl_seconds
        self._data: OrderedDict = OrderedDict()

    def get(self, key: str, now: Optional[float] = None) -> Optional[Any]:
        current_time = now if now is not None else time.time()
        if key not in self._data:
            return None
        val, ts = self._data[key]
        if current_time - ts > self.ttl_seconds:
            del self._data[key]
            return None
        self._data.move_to_end(key)
        return val

    def set(self, key: str, value: Any, now: Optional[float] = None) -> None:
        current_time = now if now is not None else time.time()
        if key in self._data:
            del self._data[key]
        elif len(self._data) >= self.max_size:
            evict_count = max(1, self.max_size // 10)
            for _ in range(evict_count):
                if self._data:
                    self._data.popitem(last=False)
        self._data[key] = (value, current_time)

    def prune_expired(self, now: Optional[float] = None) -> int:
        current_time = now if now is not None else time.time()
        expired_keys = [k for k, (_, ts) in self._data.items() if current_time - ts > self.ttl_seconds]
        for k in expired_keys:
            del self._data[k]
        return len(expired_keys)

    def clear(self) -> None:
        self._data.clear()

    def __len__(self) -> int:
        return len(self._data)

