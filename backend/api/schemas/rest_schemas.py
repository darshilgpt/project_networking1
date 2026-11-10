"""Pydantic request and response schemas for all Phase 7.2 REST API endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, field_validator
import ipaddress


# ==============================================================================
# Common & Pagination Schemas
# ==============================================================================

class PaginationMeta(BaseModel):
    """Metadata regarding paginated resource collections."""
    total: int = Field(description="Total number of items matching query filters")
    limit: int = Field(description="Maximum items per page")
    offset: int = Field(description="Starting offset index")
    returned: int = Field(description="Number of items returned in this page")


class ErrorResponse(BaseModel):
    """Standardized API error contract."""
    error: str = Field(description="Error code or categorization")
    message: str = Field(description="Descriptive explanation of the error")
    path: Optional[str] = Field(default=None, description="Requested API resource path")
    details: Optional[Dict[str, Any]] = Field(default=None, description="Structured validation errors")


# ==============================================================================
# Alert Schemas
# ==============================================================================

class AlertItem(BaseModel):
    """Individual security alert contract."""
    alert_id: int
    timestamp: float
    datetime_str: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: str
    category: str
    severity: str
    matched_rule: str
    action: str
    client_tag: Optional[str] = None
    evidence: Optional[str] = None


class AlertListResponse(BaseModel):
    """Paginated collection of security alerts."""
    alerts: List[AlertItem]
    pagination: PaginationMeta


# ==============================================================================
# Flow Schemas
# ==============================================================================

class FlowItem(BaseModel):
    """Safe read-only network flow snapshot."""
    flow_id: int
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    application_protocol: str
    tcp_state: str
    total_packets: int
    total_bytes: int
    duration_seconds: float
    is_active: bool


class FlowListResponse(BaseModel):
    """Paginated collection of network connection flows."""
    flows: List[FlowItem]
    pagination: PaginationMeta


# ==============================================================================
# Packet Schemas
# ==============================================================================

class PacketItem(BaseModel):
    """Bounded packet metadata summary without exposing raw payload bytes."""
    packet_id: int
    timestamp: float
    datetime_str: str
    network_type: str
    transport_type: str
    source_ip: str
    destination_ip: str
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    packet_length_bytes: int
    application_protocol: Optional[str] = None
    flags: Optional[str] = None
    decision: str = "ALLOW"
    alerts_count: int = 0


class PacketListResponse(BaseModel):
    """Paginated collection of packet metadata."""
    packets: List[PacketItem]
    pagination: PaginationMeta


# ==============================================================================
# Statistics & Telemetry Schemas
# ==============================================================================

class StatisticsResponse(BaseModel):
    """Aggregate real-time metrics across DPI, IDS, and flow subsystems."""
    pipeline_status: str
    active_prevention: bool
    total_packets_processed: int
    total_bytes_processed: int
    packets_per_sec: float
    bytes_per_sec: float
    active_workers: int
    total_flows: int
    active_flows: int
    protocol_distribution: Dict[str, int]
    alerts_by_severity: Dict[str, int]
    alerts_by_category: Dict[str, int]
    total_alerts: int
    total_blocks: int


# ==============================================================================
# Machine Learning Schemas
# ==============================================================================

class MLMetricsResponse(BaseModel):
    """ML telemetry metrics snapshot."""
    jobs_submitted: int
    jobs_processed: int
    queue_drops: int
    inference_failures: int
    rf_classifications: int
    if_anomalies: int
    avg_inference_latency_ms: float


class MLStatusResponse(BaseModel):
    """ML runtime status and availability."""
    status: str
    enabled: bool
    random_forest_loaded: bool
    isolation_forest_loaded: bool
    queue_depth: int
    queue_capacity: int
    metrics: MLMetricsResponse


# ==============================================================================
# Firewall Schemas
# ==============================================================================

class FirewallRuleItem(BaseModel):
    """Information regarding a static or dynamic firewall block rule."""
    rule_id: str
    rule_name: str
    ip_address: str
    direction: str = "INBOUND"
    action: str = "BLOCK"
    created_at: float
    duration_seconds: float
    expires_at: Optional[float] = None
    reason: str
    is_simulated: bool = False
    is_active: bool = True


class FirewallRulesListResponse(BaseModel):
    """List of active firewall block rules."""
    active_prevention_enabled: bool
    enforcement_mechanism: str
    total_active_rules: int
    rules: List[FirewallRuleItem]


class FirewallBlockRequest(BaseModel):
    """Request contract for blocking a specific IP."""
    ip_address: str
    duration_seconds: Optional[float] = Field(default=300.0, ge=10.0, le=86400.0)
    reason: Optional[str] = Field(default="Manual Administrator Block")

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        clean = v.strip()
        try:
            ipaddress.ip_address(clean)
        except ValueError:
            raise ValueError(f"'{clean}' is not a valid IPv4 or IPv6 address.")
        return clean


class FirewallOperationResponse(BaseModel):
    """Result of an administrative firewall block or unblock operation."""
    success: bool
    operation: str  # "BLOCK" or "UNBLOCK"
    ip_address: str
    effective_mode: str  # "ACTUAL_ENFORCEMENT" or "SIMULATION"
    message: str
    rule_id: Optional[str] = None


# ==============================================================================
# Notification Status Schema
# ==============================================================================

class NotificationStatusResponse(BaseModel):
    """Security email notification status (secrets strictly excluded)."""
    enabled: bool
    smtp_status: str  # "configured" or "not_configured"
    recipients_count: int
    cooldown_seconds: float
    queue_depth: int
    queue_capacity: int
    emails_submitted: int
    emails_delivered: int
    emails_failed: int
    emails_suppressed: int
    queue_full_drops: int

