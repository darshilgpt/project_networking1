"""Firewall and IPS enforcement adapter."""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, List, Optional
from server.worker_pool import PipelineWorkerPool

logger = logging.getLogger("dpi_ids_ips.backend.firewall_adapter")


class FirewallAdapter:
    """Adapter querying stateful firewall, active blocks, and safe administrative block operations."""

    def __init__(self, worker_pool: Optional[PipelineWorkerPool] = None) -> None:
        self.worker_pool = worker_pool

    @property
    def is_initialized(self) -> bool:
        return self.worker_pool is not None and getattr(self.worker_pool, "blocking_manager", None) is not None

    def get_firewall_status(self) -> Dict[str, Any]:
        """Queries blocking manager status and active temporary rules."""
        if not self.is_initialized:
            return {"status": "uninitialized", "active_prevention": False}

        bm = self.worker_pool.blocking_manager
        enforcement_mech = "Unknown"
        if hasattr(bm, "wfp_status") and bm.wfp_status:
            enforcement_mech = getattr(bm.wfp_status, "selected_enforcement_mechanism", "Software Hook")

        return {
            "status": "operational",
            "active_prevention": bm.active_prevention,
            "security_block_decisions": bm.security_block_decisions,
            "actual_dropped_packets": bm.actual_dropped_packets,
            "forwarded_or_reinjected_packets": bm.forwarded_or_reinjected_packets,
            "simulated_blocks": bm.simulated_blocks,
            "active_temporary_blocks": len(bm.dynamic_blocks.get_all_active_blocks()),
            "enforcement_mechanism": enforcement_mech,
        }

    def list_active_rules(self) -> Dict[str, Any]:
        """
        Lists all active blocking rules from dynamic blocks and windows firewall enforcer.
        """
        if not self.is_initialized:
            return {
                "active_prevention_enabled": False,
                "enforcement_mechanism": "None",
                "total_active_rules": 0,
                "rules": [],
            }

        bm = self.worker_pool.blocking_manager
        rules_list: List[Dict[str, Any]] = []

        # 1. Query dynamic blocks from BlockingManager
        dynamic_blocks = bm.dynamic_blocks.get_all_active_blocks()
        for b in dynamic_blocks:
            rules_list.append({
                "rule_id": f"DYN_{b.ip_address}",
                "rule_name": f"DynamicBlock_{b.ip_address}",
                "ip_address": b.ip_address,
                "direction": "INBOUND",
                "action": "BLOCK",
                "created_at": b.blocked_at,
                "duration_seconds": b.duration_seconds,
                "expires_at": b.expires_at,
                "reason": b.reason,
                "is_simulated": not bm.active_prevention,
                "is_active": not b.is_expired(),
            })

        # 2. Query Windows Defender Firewall Enforcer active rules if distinct
        if hasattr(bm, "firewall_enforcer") and bm.firewall_enforcer:
            enforcer_blocks = bm.firewall_enforcer.get_active_blocks()
            seen_ips = {r["ip_address"] for r in rules_list}
            for eb in enforcer_blocks:
                if eb.ip_address not in seen_ips:
                    rules_list.append({
                        "rule_id": f"WFW_{eb.ip_address}",
                        "rule_name": eb.rule_name,
                        "ip_address": eb.ip_address,
                        "direction": "BOTH",
                        "action": "BLOCK",
                        "created_at": eb.created_at,
                        "duration_seconds": eb.duration_seconds,
                        "expires_at": eb.expires_at,
                        "reason": eb.reason,
                        "is_simulated": eb.is_simulated,
                        "is_active": eb.is_active and not eb.is_expired(),
                    })

        enforcement_mech = "Software Hook"
        if hasattr(bm, "wfp_status") and bm.wfp_status:
            enforcement_mech = getattr(bm.wfp_status, "selected_enforcement_mechanism", "Software Hook")

        return {
            "active_prevention_enabled": bm.active_prevention,
            "enforcement_mechanism": enforcement_mech,
            "total_active_rules": len(rules_list),
            "rules": rules_list,
        }

    def block_ip(
        self,
        ip_address: str,
        duration_seconds: float = 300.0,
        reason: str = "Manual Administrator Block",
    ) -> Dict[str, Any]:
        """
        Executes an administrative IP block through the BlockingManager.
        Respects ENABLE_FIREWALL_MANAGEMENT environment variable to safeguard live network adapters.
        """
        if not self.is_initialized:
            return {
                "success": False,
                "operation": "BLOCK",
                "ip_address": ip_address,
                "effective_mode": "SIMULATION",
                "message": "Pipeline and BlockingManager are not initialized.",
                "rule_id": None,
            }

        bm = self.worker_pool.blocking_manager

        # Check safety allowlist
        if ip_address in getattr(bm.allowlist_denylist, "allowlisted_ips", set()) or ip_address in {"127.0.0.1", "::1", "10.10.0.1"}:
            return {
                "success": False,
                "operation": "BLOCK",
                "ip_address": ip_address,
                "effective_mode": "ALLOWLIST_PROTECTED",
                "message": f"IP {ip_address} is protected by system safety allowlist and cannot be blocked.",
                "rule_id": None,
            }

        # Check whether actual firewall management is permitted
        allow_live_fw = os.getenv("ENABLE_FIREWALL_MANAGEMENT", "false").lower() in ("true", "1", "yes")

        # Add temporary block to dynamic block manager
        block = bm.add_temporary_block(ip_address, duration_seconds=duration_seconds, reason=reason)

        effective_mode = "SIMULATION"
        if allow_live_fw and bm.active_prevention and hasattr(bm, "firewall_enforcer") and bm.firewall_enforcer:
            # Attempt OS firewall rule creation
            os_success = bm.firewall_enforcer.block_ip(
                ip=ip_address,
                reason=reason,
                duration_seconds=duration_seconds,
            )
            effective_mode = "ACTUAL_ENFORCEMENT" if os_success else "SIMULATION"

        rule_id = f"DYN_{ip_address}"
        return {
            "success": True,
            "operation": "BLOCK",
            "ip_address": ip_address,
            "effective_mode": effective_mode,
            "message": f"Successfully created temporary block for {ip_address} ({duration_seconds:.0f}s).",
            "rule_id": rule_id,
        }

    def unblock_ip(self, ip_address: str) -> Dict[str, Any]:
        """
        Removes an active block for the specified IP address.
        """
        if not self.is_initialized:
            return {
                "success": False,
                "operation": "UNBLOCK",
                "ip_address": ip_address,
                "effective_mode": "SIMULATION",
                "message": "Pipeline and BlockingManager are not initialized.",
                "rule_id": None,
            }

        bm = self.worker_pool.blocking_manager
        clean_ip = ip_address.replace("DYN_", "").replace("WFW_", "").strip()

        unblocked_dyn = bm.unblock_ip(clean_ip)
        unblocked_os = False
        if hasattr(bm, "firewall_enforcer") and bm.firewall_enforcer:
            unblocked_os = bm.firewall_enforcer.unblock_ip(clean_ip)

        found = unblocked_dyn or unblocked_os
        effective_mode = "ACTUAL_ENFORCEMENT" if unblocked_os else "SIMULATION"

        return {
            "success": found,
            "operation": "UNBLOCK",
            "ip_address": clean_ip,
            "effective_mode": effective_mode,
            "message": f"Unblocked IP {clean_ip}" if found else f"No active block rule found for IP {clean_ip}",
            "rule_id": f"DYN_{clean_ip}",
        }
