"""Feature schema, canonical feature ordering, and metadata definitions for Network Flow ML."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


class FeatureCategory(str, Enum):
    """Categorization of network flow features."""
    FLOW_BASIC = "FLOW_BASIC"
    PACKET_SIZE = "PACKET_SIZE"
    TRAFFIC_RATE = "TRAFFIC_RATE"
    INTER_ARRIVAL_TIME = "INTER_ARRIVAL_TIME"
    TCP_FLAGS = "TCP_FLAGS"
    SUBFLOW = "SUBFLOW"


@dataclass(frozen=True)
class FeatureDefinition:
    """Represents a feature in the canonical schema."""
    name: str
    category: FeatureCategory
    dtype: str  # "float32", "int64"
    description: str
    cicids2017_column: Optional[str] = None
    available_in_live: bool = False
    is_common_selected: bool = True  # Selected for common ML training & inference


# Canonical Ordered Feature Schema (Ordered List of Features)
# This order is strictly maintained across dataset loading, preprocessing, offline training, and live inference.
CANONICAL_FEATURES: List[FeatureDefinition] = [
    # 1. Basic Flow Features
    FeatureDefinition(
        name="flow_duration",
        category=FeatureCategory.FLOW_BASIC,
        dtype="float32",
        description="Duration of the flow in microseconds",
        cicids2017_column="flow_duration",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="protocol",
        category=FeatureCategory.FLOW_BASIC,
        dtype="int64",
        description="Transport protocol number (e.g. 6=TCP, 17=UDP, 1=ICMP)",
        cicids2017_column=None,  # CIC-IDS2017 files omit protocol number column in some exports
        available_in_live=True,
        is_common_selected=False,  # Excluded from common set if missing in CIC-IDS2017
    ),
    FeatureDefinition(
        name="src_port",
        category=FeatureCategory.FLOW_BASIC,
        dtype="int64",
        description="Source transport port",
        cicids2017_column=None,  # Excluded from model input to prevent overfitting to ephemeral ports
        available_in_live=True,
        is_common_selected=False,
    ),
    FeatureDefinition(
        name="dst_port",
        category=FeatureCategory.FLOW_BASIC,
        dtype="int64",
        description="Destination transport port (service port)",
        cicids2017_column="destination_port",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="tot_fwd_pkts",
        category=FeatureCategory.FLOW_BASIC,
        dtype="float32",
        description="Total packets in the forward direction",
        cicids2017_column="total_fwd_packets",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="tot_bwd_pkts",
        category=FeatureCategory.FLOW_BASIC,
        dtype="float32",
        description="Total packets in the backward direction",
        cicids2017_column="total_backward_packets",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="tot_fwd_bytes",
        category=FeatureCategory.FLOW_BASIC,
        dtype="float32",
        description="Total bytes in the forward direction",
        cicids2017_column="total_length_of_fwd_packets",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="tot_bwd_bytes",
        category=FeatureCategory.FLOW_BASIC,
        dtype="float32",
        description="Total bytes in the backward direction",
        cicids2017_column="total_length_of_bwd_packets",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="tot_pkts",
        category=FeatureCategory.FLOW_BASIC,
        dtype="float32",
        description="Total bidirectional packet count",
        cicids2017_column=None,  # Derived as tot_fwd_pkts + tot_bwd_pkts
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="tot_bytes",
        category=FeatureCategory.FLOW_BASIC,
        dtype="float32",
        description="Total bidirectional byte count",
        cicids2017_column=None,  # Derived as tot_fwd_bytes + tot_bwd_bytes
        available_in_live=True,
        is_common_selected=True,
    ),

    # 2. Packet Statistics
    FeatureDefinition(
        name="fwd_pkt_len_max",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Maximum size of packet in forward direction",
        cicids2017_column="fwd_packet_length_max",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="fwd_pkt_len_min",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Minimum size of packet in forward direction",
        cicids2017_column="fwd_packet_length_min",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="fwd_pkt_len_mean",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Mean size of packet in forward direction",
        cicids2017_column="fwd_packet_length_mean",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="fwd_pkt_len_std",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Standard deviation of packet size in forward direction",
        cicids2017_column="fwd_packet_length_std",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="bwd_pkt_len_max",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Maximum size of packet in backward direction",
        cicids2017_column="bwd_packet_length_max",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="bwd_pkt_len_min",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Minimum size of packet in backward direction",
        cicids2017_column="bwd_packet_length_min",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="bwd_pkt_len_mean",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Mean size of packet in backward direction",
        cicids2017_column="bwd_packet_length_mean",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="bwd_pkt_len_std",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Standard deviation of packet size in backward direction",
        cicids2017_column="bwd_packet_length_std",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="pkt_len_min",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Minimum packet length across flow",
        cicids2017_column="min_packet_length",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="pkt_len_max",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Maximum packet length across flow",
        cicids2017_column="max_packet_length",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="pkt_len_mean",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Mean packet length across flow",
        cicids2017_column="packet_length_mean",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="pkt_len_std",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Standard deviation of packet length",
        cicids2017_column="packet_length_std",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="avg_pkt_size",
        category=FeatureCategory.PACKET_SIZE,
        dtype="float32",
        description="Average packet size across flow",
        cicids2017_column="average_packet_size",
        available_in_live=True,
        is_common_selected=True,
    ),

    # 3. Traffic Rates
    FeatureDefinition(
        name="flow_pkts_per_sec",
        category=FeatureCategory.TRAFFIC_RATE,
        dtype="float32",
        description="Flow throughput in packets per second",
        cicids2017_column="flow_packets_s",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="flow_bytes_per_sec",
        category=FeatureCategory.TRAFFIC_RATE,
        dtype="float32",
        description="Flow throughput in bytes per second",
        cicids2017_column="flow_bytes_s",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="fwd_pkts_per_sec",
        category=FeatureCategory.TRAFFIC_RATE,
        dtype="float32",
        description="Forward throughput in packets per second",
        cicids2017_column="fwd_packets_s",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="bwd_pkts_per_sec",
        category=FeatureCategory.TRAFFIC_RATE,
        dtype="float32",
        description="Backward throughput in packets per second",
        cicids2017_column="bwd_packets_s",
        available_in_live=True,
        is_common_selected=True,
    ),

    # 4. Timing / Inter-Arrival Times (IAT)
    FeatureDefinition(
        name="flow_iat_mean",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Mean inter-arrival time across entire flow (microseconds)",
        cicids2017_column="flow_iat_mean",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="flow_iat_std",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Standard deviation of inter-arrival time across flow",
        cicids2017_column="flow_iat_std",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="flow_iat_max",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Maximum inter-arrival time across flow",
        cicids2017_column="flow_iat_max",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="flow_iat_min",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Minimum inter-arrival time across flow",
        cicids2017_column="flow_iat_min",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="fwd_iat_mean",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Mean inter-arrival time of forward packets",
        cicids2017_column="fwd_iat_mean",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="fwd_iat_std",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Standard deviation of forward inter-arrival times",
        cicids2017_column="fwd_iat_std",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="bwd_iat_mean",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Mean inter-arrival time of backward packets",
        cicids2017_column="bwd_iat_mean",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="bwd_iat_std",
        category=FeatureCategory.INTER_ARRIVAL_TIME,
        dtype="float32",
        description="Standard deviation of backward inter-arrival times",
        cicids2017_column="bwd_iat_std",
        available_in_live=True,
        is_common_selected=True,
    ),

    # 5. TCP Flags
    FeatureDefinition(
        name="fin_flag_cnt",
        category=FeatureCategory.TCP_FLAGS,
        dtype="float32",
        description="Number of packets with FIN flag set",
        cicids2017_column="fin_flag_count",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="syn_flag_cnt",
        category=FeatureCategory.TCP_FLAGS,
        dtype="float32",
        description="Number of packets with SYN flag set",
        cicids2017_column="syn_flag_count",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="rst_flag_cnt",
        category=FeatureCategory.TCP_FLAGS,
        dtype="float32",
        description="Number of packets with RST flag set",
        cicids2017_column="rst_flag_count",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="psh_flag_cnt",
        category=FeatureCategory.TCP_FLAGS,
        dtype="float32",
        description="Number of packets with PSH flag set",
        cicids2017_column="psh_flag_count",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="ack_flag_cnt",
        category=FeatureCategory.TCP_FLAGS,
        dtype="float32",
        description="Number of packets with ACK flag set",
        cicids2017_column="ack_flag_count",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="urg_flag_cnt",
        category=FeatureCategory.TCP_FLAGS,
        dtype="float32",
        description="Number of packets with URG flag set",
        cicids2017_column="urg_flag_count",
        available_in_live=True,
        is_common_selected=True,
    ),
    FeatureDefinition(
        name="down_up_ratio",
        category=FeatureCategory.SUBFLOW,
        dtype="float32",
        description="Download to upload packet ratio (bwd_pkts / fwd_pkts)",
        cicids2017_column="down_up_ratio",
        available_in_live=True,
        is_common_selected=True,
    ),
]


class FeatureSchema:
    """Provides lookup, indexing, and validation for canonical flow features."""

    def __init__(self, selected_only: bool = True) -> None:
        self.selected_only = selected_only
        if selected_only:
            self.features = [f for f in CANONICAL_FEATURES if f.is_common_selected]
        else:
            self.features = list(CANONICAL_FEATURES)

        self.feature_names = [f.name for f in self.features]
        self.name_to_index = {name: idx for idx, name in enumerate(self.feature_names)}
        self.cicids_to_canonical = {
            f.cicids2017_column: f.name for f in self.features if f.cicids2017_column
        }

    @property
    def num_features(self) -> int:
        return len(self.features)

    def get_feature(self, name: str) -> Optional[FeatureDefinition]:
        for f in self.features:
            if f.name == name:
                return f
        return None

    def generate_compatibility_report(self) -> Dict[str, Any]:
        """Generates a structured report detailing offline vs. live feature compatibility."""
        cicids_available = [f.name for f in CANONICAL_FEATURES if f.cicids2017_column is not None or f.name in ("tot_pkts", "tot_bytes")]
        live_available = [f.name for f in CANONICAL_FEATURES if f.available_in_live]
        common = [f.name for f in CANONICAL_FEATURES if f.is_common_selected]
        offline_only = [f.name for f in CANONICAL_FEATURES if f.cicids2017_column and not f.available_in_live]
        live_only = [f.name for f in CANONICAL_FEATURES if f.available_in_live and f.cicids2017_column is None and f.name not in ("tot_pkts", "tot_bytes")]

        return {
            "total_canonical_features": len(CANONICAL_FEATURES),
            "common_selected_for_ml": len(common),
            "common_selected_names": common,
            "cicids2017_available_count": len(cicids_available),
            "live_available_count": len(live_available),
            "offline_only_count": len(offline_only),
            "live_only_count": len(live_only),
            "offline_only_features": offline_only,
            "live_only_features": live_only,
        }

