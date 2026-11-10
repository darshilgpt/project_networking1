"""Firewall service providing policy, dynamic blocks, and enforcement operations."""

from __future__ import annotations

from typing import Any, Dict
from backend.integrations.firewall_adapter import FirewallAdapter


class FirewallService:
    """Encapsulates firewall rule inspection and administrative block/unblock actions."""

    def __init__(self, firewall_adapter: FirewallAdapter) -> None:
        self.firewall_adapter = firewall_adapter

    def get_status(self) -> Dict[str, Any]:
        """Provides firewall blocking manager status."""
        return self.firewall_adapter.get_firewall_status()

    def list_active_rules(self) -> Dict[str, Any]:
        """Lists active firewall block rules."""
        return self.firewall_adapter.list_active_rules()

    def block_ip(
        self,
        ip_address: str,
        duration_seconds: float = 300.0,
        reason: str = "Manual Administrator Block",
    ) -> Dict[str, Any]:
        """Creates an expirable block rule for the given IP."""
        return self.firewall_adapter.block_ip(
            ip_address=ip_address,
            duration_seconds=duration_seconds,
            reason=reason,
        )

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """Clears an active block rule for the given IP."""
        return self.firewall_adapter.unblock_ip(ip_address)
