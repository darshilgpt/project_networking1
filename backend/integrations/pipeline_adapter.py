"""Pipeline Adapter connecting the FastAPI backend to the existing DPI/IDS pipeline."""

from __future__ import annotations

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Tuple
from models.alert_model import IDSAlert
from server.client_manager import ClientManager
from server.ingestion import PacketSource
from server.worker_pool import PipelineWorkerPool, ServerPipelineStats

logger = logging.getLogger("dpi_ids_ips.backend.pipeline_adapter")


def _clean_str(val: Any) -> Optional[str]:
    """Helper to cleanly extract string from query params or None."""
    if val is None or not isinstance(val, str):
        return None
    cleaned = val.strip()
    return cleaned if cleaned else None


class PipelineAdapter:
    """
    Thread-safe adapter exposing read-only queries and telemetry from the active
    PipelineWorkerPool, ClientManager, and PacketSource to FastAPI routes and services.
    """

    def __init__(
        self,
        worker_pool: Optional[PipelineWorkerPool] = None,
        client_manager: Optional[ClientManager] = None,
        packet_source: Optional[PacketSource] = None,
    ) -> None:
        self.worker_pool = worker_pool
        self.client_manager = client_manager
        self.packet_source = packet_source

    @property
    def is_initialized(self) -> bool:
        """Returns True if the underlying worker pool is initialized and available."""
        return self.worker_pool is not None

    def get_pipeline_stats(self) -> Dict[str, Any]:
        """Queries current snapshot stats from the worker pool."""
        if not self.worker_pool:
            return {"status": "uninitialized"}
        stats = self.worker_pool.get_stats_snapshot()
        return {
            "status": "active",
            "total_processed": stats.total_processed,
            "total_bytes": stats.total_bytes,
            "total_alerts": stats.total_alerts,
            "total_blocks": stats.total_blocks,
            "packets_per_sec": stats.packets_per_sec,
            "bytes_per_sec": stats.bytes_per_sec,
            "active_workers": stats.active_workers,
            "active_prevention": stats.active_prevention_enabled,
        }

    # =========================================================================
    # Alert Query Methods
    # =========================================================================

    def _format_alert(self, alert: IDSAlert, client_tag: Optional[str] = None) -> Dict[str, Any]:
        """Formats an IDSAlert object into a consistent dictionary for the REST schema."""
        action_val = "ALERT"
        if getattr(alert, "recommended_action", None):
            action_val = getattr(alert.recommended_action, "value", str(alert.recommended_action))

        dt_str = getattr(alert, "datetime_str", "")
        if not dt_str and getattr(alert, "timestamp", 0.0):
            dt_str = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).isoformat()

        return {
            "alert_id": alert.alert_id,
            "timestamp": alert.timestamp,
            "datetime_str": dt_str,
            "source_ip": alert.source_ip,
            "destination_ip": alert.destination_ip,
            "source_port": alert.source_port,
            "destination_port": alert.destination_port,
            "protocol": alert.protocol,
            "category": getattr(alert.category, "value", str(alert.category)),
            "severity": getattr(alert.severity, "value", str(alert.severity)),
            "matched_rule": alert.matched_rule,
            "action": action_val,
            "client_tag": client_tag,
            "evidence": getattr(alert, "evidence", None),
        }

    def get_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        category: Optional[str] = None,
        source_ip: Optional[str] = None,
        date_from: Optional[float] = None,
        date_to: Optional[float] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Queries and filters recent alerts from the worker pool ring buffer.
        Returns a tuple of (matching_slice, total_matching_count).
        """
        if not self.worker_pool:
            return [], 0

        alerts_list = list(self.worker_pool.recent_alerts)
        filtered: List[Dict[str, Any]] = []

        sev_norm = _clean_str(severity)
        cat_norm = _clean_str(category)
        src_norm = _clean_str(source_ip)
        if sev_norm:
            sev_norm = sev_norm.upper()
        if cat_norm:
            cat_norm = cat_norm.upper()

        for alert, client_tag in alerts_list:
            a_dict = self._format_alert(alert, client_tag)

            if sev_norm and a_dict["severity"].upper() != sev_norm:
                continue
            if cat_norm and a_dict["category"].upper() != cat_norm:
                continue
            if src_norm and a_dict["source_ip"] != src_norm:
                continue
            if date_from is not None and isinstance(date_from, (int, float)) and a_dict["timestamp"] < date_from:
                continue
            if date_to is not None and isinstance(date_to, (int, float)) and a_dict["timestamp"] > date_to:
                continue

            filtered.append(a_dict)

        total_count = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total_count

    def get_alert_by_id(self, alert_id: int) -> Optional[Dict[str, Any]]:
        """Finds a single alert by its ID in the recent alerts ring buffer."""
        if not self.worker_pool:
            return None
        for alert, client_tag in list(self.worker_pool.recent_alerts):
            if alert.alert_id == alert_id:
                return self._format_alert(alert, client_tag)
        return None

    def get_recent_alerts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Legacy helper querying up to limit alerts."""
        alerts, _ = self.get_alerts(limit=limit, offset=0)
        return alerts

    # =========================================================================
    # Flow Query Methods
    # =========================================================================

    def _format_flow(self, flow: Any) -> Dict[str, Any]:
        """Formats a Flow model into a dictionary matching FlowItem schema."""
        tcp_state_val = getattr(flow, "tcp_state", "UNKNOWN")
        if hasattr(tcp_state_val, "value"):
            tcp_state_val = tcp_state_val.value
        elif not isinstance(tcp_state_val, str):
            tcp_state_val = str(tcp_state_val)

        stats = getattr(flow, "stats", None)
        total_packets = stats.total_packets if stats else 0
        total_bytes = stats.total_bytes if stats else 0
        duration_sec = stats.duration if stats else 0.0

        return {
            "flow_id": flow.flow_id,
            "source_ip": getattr(flow, "initiator_ip", ""),
            "destination_ip": getattr(flow, "responder_ip", ""),
            "source_port": getattr(flow, "initiator_port", 0),
            "destination_port": getattr(flow, "responder_port", 0),
            "protocol": getattr(flow, "protocol", "OTHER"),
            "application_protocol": getattr(flow, "application_protocol", "Unknown"),
            "tcp_state": tcp_state_val,
            "total_packets": total_packets,
            "total_bytes": total_bytes,
            "duration_seconds": round(duration_sec, 2),
            "is_active": getattr(flow, "is_active", True),
        }

    def get_flows(
        self,
        limit: int = 50,
        offset: int = 0,
        protocol: Optional[str] = None,
        source_ip: Optional[str] = None,
        destination_ip: Optional[str] = None,
        is_active: Optional[bool] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Aggregates active flows across all registered client contexts.
        Returns a tuple of (paginated_flows, total_matching_count).
        """
        all_flows: List[Any] = []
        cm = self.client_manager or (self.worker_pool.client_manager if self.worker_pool else None)
        if cm:
            for client_ctx in cm.get_all_clients():
                if hasattr(client_ctx, "flow_manager") and client_ctx.flow_manager:
                    all_flows.extend(client_ctx.flow_manager.get_active_flows())

        proto_norm = _clean_str(protocol)
        src_norm = _clean_str(source_ip)
        dst_norm = _clean_str(destination_ip)
        if proto_norm:
            proto_norm = proto_norm.upper()

        filtered: List[Dict[str, Any]] = []
        for flow in all_flows:
            f_dict = self._format_flow(flow)

            if proto_norm and f_dict["protocol"].upper() != proto_norm:
                continue
            if src_norm and f_dict["source_ip"] != src_norm:
                continue
            if dst_norm and f_dict["destination_ip"] != dst_norm:
                continue
            if is_active is not None and isinstance(is_active, bool) and f_dict["is_active"] != is_active:
                continue

            filtered.append(f_dict)

        total_count = len(filtered)
        paginated = filtered[offset : offset + limit]
        return paginated, total_count

    def get_flow_by_id(self, flow_id: int) -> Optional[Dict[str, Any]]:
        """Finds a flow by its unique numeric ID across all clients."""
        cm = self.client_manager or (self.worker_pool.client_manager if self.worker_pool else None)
        if not cm:
            return None

        for client_ctx in cm.get_all_clients():
            if hasattr(client_ctx, "flow_manager") and client_ctx.flow_manager:
                for flow in client_ctx.flow_manager.get_active_flows():
                    if flow.flow_id == flow_id:
                        return self._format_flow(flow)
        return None

    # =========================================================================
    # Packet Metadata Methods (Zero Raw Payload Exposure)
    # =========================================================================

    def get_recent_packets(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """
        Extracts bounded, safe packet metadata from the recent packets ring buffer.
        Strictly excludes raw packet payload bytes.
        """
        if not self.worker_pool:
            return [], 0

        raw_list = list(self.worker_pool.recent_packets)
        result: List[Dict[str, Any]] = []

        for item in raw_list:
            packet = item.packet
            src_ip = packet.ipv4.src_ip if packet.ipv4 else (packet.ipv6.src_ip if packet.ipv6 else "Unknown")
            dst_ip = packet.ipv4.dst_ip if packet.ipv4 else (packet.ipv6.dst_ip if packet.ipv6 else "Unknown")
            src_port = packet.tcp.src_port if packet.tcp else (packet.udp.src_port if packet.udp else None)
            dst_port = packet.tcp.dst_port if packet.tcp else (packet.udp.dst_port if packet.udp else None)

            dt_str = getattr(packet, "datetime_str", "")
            if not dt_str and getattr(packet, "timestamp", 0.0):
                dt_str = datetime.fromtimestamp(packet.timestamp, tz=timezone.utc).isoformat()

            flags_repr = None
            if packet.tcp and packet.tcp.flags:
                if hasattr(packet.tcp.flags, "summary"):
                    flags_repr = packet.tcp.flags.summary()
                else:
                    flags_repr = str(packet.tcp.flags)

            decision_str = "ALLOW"
            if item.decision:
                decision_str = getattr(item.decision, "value", str(item.decision))

            result.append({
                "packet_id": packet.packet_id,
                "timestamp": packet.timestamp,
                "datetime_str": dt_str,
                "network_type": packet.network_type,
                "transport_type": packet.transport_type,
                "source_ip": src_ip,
                "destination_ip": dst_ip,
                "source_port": src_port,
                "destination_port": dst_port,
                "packet_length_bytes": packet.raw_length or len(getattr(packet, "payload", b"")),
                "application_protocol": getattr(item.flow, "application_protocol", None) if item.flow else None,
                "flags": flags_repr,
                "decision": decision_str,
                "alerts_count": len(item.alerts),
            })

        total_count = len(result)
        paginated = result[offset : offset + limit]
        return paginated, total_count

    # =========================================================================
    # Aggregated Subsystem Statistics
    # =========================================================================

    def get_aggregate_stats(self) -> Dict[str, Any]:
        """Gathers aggregate real-time metrics across DPI, IDS, and Flow subsystems."""
        if not self.worker_pool:
            return {
                "pipeline_status": "uninitialized",
                "active_prevention": False,
                "total_packets_processed": 0,
                "total_bytes_processed": 0,
                "packets_per_sec": 0.0,
                "bytes_per_sec": 0.0,
                "active_workers": 0,
                "total_flows": 0,
                "active_flows": 0,
                "protocol_distribution": {},
                "alerts_by_severity": {},
                "alerts_by_category": {},
                "total_alerts": 0,
                "total_blocks": 0,
            }

        stats = self.worker_pool.get_stats_snapshot()

        # Flows count
        total_flows = 0
        active_flows = 0
        cm = self.client_manager or self.worker_pool.client_manager
        if cm:
            for client_ctx in cm.get_all_clients():
                if hasattr(client_ctx, "flow_manager") and client_ctx.flow_manager:
                    sm = client_ctx.flow_manager.get_summary_metrics()
                    active_flows += sm.get("active_flows", 0)
                    total_flows += sm.get("total_flows_seen", 0)

        # Protocol distribution
        proto_dist: Dict[str, int] = {}
        if getattr(self.worker_pool, "dpi_engine", None):
            proto_dist = dict(self.worker_pool.dpi_engine.protocol_counts)

        # Alert distributions
        by_sev: Dict[str, int] = {}
        by_cat: Dict[str, int] = {}
        for alert, _ in list(self.worker_pool.recent_alerts):
            sev = getattr(alert.severity, "value", str(alert.severity))
            cat = getattr(alert.category, "value", str(alert.category))
            by_sev[sev] = by_sev.get(sev, 0) + 1
            by_cat[cat] = by_cat.get(cat, 0) + 1

        return {
            "pipeline_status": "active",
            "active_prevention": stats.active_prevention_enabled,
            "total_packets_processed": stats.total_processed,
            "total_bytes_processed": stats.total_bytes,
            "packets_per_sec": stats.packets_per_sec,
            "bytes_per_sec": stats.bytes_per_sec,
            "active_workers": stats.active_workers,
            "total_flows": total_flows,
            "active_flows": active_flows,
            "protocol_distribution": proto_dist,
            "alerts_by_severity": by_sev,
            "alerts_by_category": by_cat,
            "total_alerts": stats.total_alerts,
            "total_blocks": stats.total_blocks,
        }

    # =========================================================================
    # ML Subsystem Status & Metrics
    # =========================================================================

    def get_ml_status(self) -> Dict[str, Any]:
        """Queries status and telemetry metrics of the runtime ML engine."""
        if not self.worker_pool or not getattr(self.worker_pool, "ml_engine", None):
            return {"status": "uninitialized", "enabled": False}

        ml = self.worker_pool.ml_engine
        if not getattr(ml.config, "enabled", False):
            return {
                "status": "disabled",
                "enabled": False,
                "rf_loaded": False,
                "if_loaded": False,
                "queue_depth": 0,
                "queue_capacity": getattr(ml.config, "queue_capacity", 0),
                "metrics": {
                    "jobs_submitted": 0,
                    "jobs_processed": 0,
                    "queue_drops": 0,
                    "inference_failures": 0,
                    "rf_classifications": 0,
                    "if_anomalies": 0,
                    "avg_inference_latency_ms": 0.0,
                },
            }

        metrics = ml.metrics.get_snapshot()
        return {
            "status": "operational",
            "enabled": True,
            "rf_loaded": ml.rf_model is not None,
            "if_loaded": ml.if_model is not None,
            "queue_depth": ml._queue.qsize(),
            "queue_capacity": ml.config.queue_capacity,
            "metrics": {
                "jobs_submitted": metrics.get("jobs_submitted", 0),
                "jobs_processed": metrics.get("jobs_processed", 0),
                "queue_drops": metrics.get("queue_drops", 0),
                "inference_failures": metrics.get("inference_failures", 0),
                "rf_classifications": metrics.get("rf_classifications", 0),
                "if_anomalies": metrics.get("if_anomalies", 0),
                "avg_inference_latency_ms": round(metrics.get("avg_inference_latency_ms", 0.0), 3),
            },
        }

    def get_registered_clients(self) -> List[Dict[str, Any]]:
        """Queries active clients and per-client traffic summaries."""
        if not self.client_manager:
            return []
        snapshots = self.client_manager.get_client_snapshots()
        return [
            {
                "client_ip": s.client_ip,
                "client_name": s.client_name,
                "total_packets": s.total_packets,
                "total_bytes": s.total_bytes,
                "active_flows": s.active_flows,
                "alerts_count": s.alerts_count,
                "top_protocol": s.top_protocol,
                "status": s.status,
            }
            for s in snapshots
        ]
