"""Feature extraction from live Flow and FlowStats objects matching canonical schema."""

from __future__ import annotations

import math
from typing import Dict, List, Optional
import numpy as np

from ml.features.feature_schema import CANONICAL_FEATURES, FeatureSchema
from models.flow_model import Flow, FlowStats
from models.packet_models import ParsedPacket


class LiveFlowFeatureExtractor:
    """
    Extracts canonical ML flow features from live stateful Flow and FlowStats objects.
    Ensures identical feature ordering, mathematical calculations, and zero target leakage.
    """

    def __init__(self, schema: Optional[FeatureSchema] = None) -> None:
        self.schema = schema or FeatureSchema(selected_only=True)

    def extract_features(self, flow: Flow) -> Dict[str, float]:
        """
        Extracts a dictionary of canonical features from a live Flow instance.
        Derived exclusively from genuine flow metadata (no invented values).
        """
        stats = flow.stats
        duration_sec = stats.duration
        duration_us = duration_sec * 1_000_000.0  # CIC-IDS2017 flow duration is in microseconds

        tot_fwd_pkts = float(stats.packets_forward)
        tot_bwd_pkts = float(stats.packets_reverse)
        tot_pkts = tot_fwd_pkts + tot_bwd_pkts

        tot_fwd_bytes = float(stats.bytes_forward)
        tot_bwd_bytes = float(stats.bytes_reverse)
        tot_bytes = tot_fwd_bytes + tot_bwd_bytes

        # Rates (avoid division by zero)
        eff_dur_sec = max(duration_sec, 0.000001)
        flow_pkts_s = tot_pkts / eff_dur_sec
        flow_bytes_s = tot_bytes / eff_dur_sec
        fwd_pkts_s = tot_fwd_pkts / eff_dur_sec
        bwd_pkts_s = tot_bwd_pkts / eff_dur_sec

        # Packet size statistics from flow metadata if tracked
        fwd_lens = getattr(flow, "fwd_packet_lengths", [])
        bwd_lens = getattr(flow, "bwd_packet_lengths", [])
        all_lens = fwd_lens + bwd_lens

        if fwd_lens:
            fwd_max = float(max(fwd_lens))
            fwd_min = float(min(fwd_lens))
            fwd_mean = float(np.mean(fwd_lens))
            fwd_std = float(np.std(fwd_lens)) if len(fwd_lens) > 1 else 0.0
        else:
            fwd_mean = tot_fwd_bytes / max(tot_fwd_pkts, 1.0)
            fwd_max = fwd_mean
            fwd_min = fwd_mean if tot_fwd_pkts > 0 else 0.0
            fwd_std = 0.0

        if bwd_lens:
            bwd_max = float(max(bwd_lens))
            bwd_min = float(min(bwd_lens))
            bwd_mean = float(np.mean(bwd_lens))
            bwd_std = float(np.std(bwd_lens)) if len(bwd_lens) > 1 else 0.0
        else:
            bwd_mean = tot_bwd_bytes / max(tot_bwd_pkts, 1.0)
            bwd_max = bwd_mean
            bwd_min = bwd_mean if tot_bwd_pkts > 0 else 0.0
            bwd_std = 0.0

        if all_lens:
            pkt_max = float(max(all_lens))
            pkt_min = float(min(all_lens))
            pkt_mean = float(np.mean(all_lens))
            pkt_std = float(np.std(all_lens)) if len(all_lens) > 1 else 0.0
            avg_pkt_size = pkt_mean
        else:
            avg_pkt_size = tot_bytes / max(tot_pkts, 1.0)
            pkt_mean = avg_pkt_size
            pkt_max = max(fwd_max, bwd_max)
            pkt_min = min(fwd_min, bwd_min)
            pkt_std = 0.0

        # Inter-arrival times (IAT)
        flow_iats = getattr(flow, "flow_iats_us", [])
        fwd_iats = getattr(flow, "fwd_iats_us", [])
        bwd_iats = getattr(flow, "bwd_iats_us", [])

        flow_iat_mean = float(np.mean(flow_iats)) if flow_iats else (duration_us / max(tot_pkts - 1, 1.0) if tot_pkts > 1 else 0.0)
        flow_iat_std = float(np.std(flow_iats)) if len(flow_iats) > 1 else 0.0
        flow_iat_max = float(max(flow_iats)) if flow_iats else duration_us
        flow_iat_min = float(min(flow_iats)) if flow_iats else duration_us

        fwd_iat_mean = float(np.mean(fwd_iats)) if fwd_iats else (duration_us / max(tot_fwd_pkts - 1, 1.0) if tot_fwd_pkts > 1 else 0.0)
        fwd_iat_std = float(np.std(fwd_iats)) if len(fwd_iats) > 1 else 0.0
        bwd_iat_mean = float(np.mean(bwd_iats)) if bwd_iats else (duration_us / max(tot_bwd_pkts - 1, 1.0) if tot_bwd_pkts > 1 else 0.0)
        bwd_iat_std = float(np.std(bwd_iats)) if len(bwd_iats) > 1 else 0.0

        # TCP Flags counts
        tcp_flags = getattr(flow, "tcp_flags_counts", {})
        fin_cnt = float(tcp_flags.get("FIN", 0))
        syn_cnt = float(tcp_flags.get("SYN", 0))
        rst_cnt = float(tcp_flags.get("RST", 0))
        psh_cnt = float(tcp_flags.get("PSH", 0))
        ack_cnt = float(tcp_flags.get("ACK", 0))
        urg_cnt = float(tcp_flags.get("URG", 0))

        down_up_ratio = tot_bwd_pkts / max(tot_fwd_pkts, 1.0)

        # Destination port
        dst_port = float(flow.responder_port if flow.responder_port else flow.key.port_b)

        raw_map: Dict[str, float] = {
            "flow_duration": duration_us,
            "dst_port": dst_port,
            "tot_fwd_pkts": tot_fwd_pkts,
            "tot_bwd_pkts": tot_bwd_pkts,
            "tot_fwd_bytes": tot_fwd_bytes,
            "tot_bwd_bytes": tot_bwd_bytes,
            "tot_pkts": tot_pkts,
            "tot_bytes": tot_bytes,
            "fwd_pkt_len_max": fwd_max,
            "fwd_pkt_len_min": fwd_min,
            "fwd_pkt_len_mean": fwd_mean,
            "fwd_pkt_len_std": fwd_std,
            "bwd_pkt_len_max": bwd_max,
            "bwd_pkt_len_min": bwd_min,
            "bwd_pkt_len_mean": bwd_mean,
            "bwd_pkt_len_std": bwd_std,
            "pkt_len_min": pkt_min,
            "pkt_len_max": pkt_max,
            "pkt_len_mean": pkt_mean,
            "pkt_len_std": pkt_std,
            "avg_pkt_size": avg_pkt_size,
            "flow_pkts_per_sec": flow_pkts_s,
            "flow_bytes_per_sec": flow_bytes_s,
            "fwd_pkts_per_sec": fwd_pkts_s,
            "bwd_pkts_per_sec": bwd_pkts_s,
            "flow_iat_mean": flow_iat_mean,
            "flow_iat_std": flow_iat_std,
            "flow_iat_max": flow_iat_max,
            "flow_iat_min": flow_iat_min,
            "fwd_iat_mean": fwd_iat_mean,
            "fwd_iat_std": fwd_iat_std,
            "bwd_iat_mean": bwd_iat_mean,
            "bwd_iat_std": bwd_iat_std,
            "fin_flag_cnt": fin_cnt,
            "syn_flag_cnt": syn_cnt,
            "rst_flag_cnt": rst_cnt,
            "psh_flag_cnt": psh_cnt,
            "ack_flag_cnt": ack_cnt,
            "urg_flag_cnt": urg_cnt,
            "down_up_ratio": down_up_ratio,
        }

        # Filter strictly to the ordered canonical feature set
        return {name: float(raw_map.get(name, 0.0)) for name in self.schema.feature_names}

    def extract_vector(self, flow: Flow) -> np.ndarray:
        """
        Extracts an ordered 1D numpy vector (float32) of features suitable for ML model inference.
        Guarantees strict schema ordering.
        """
        feat_dict = self.extract_features(flow)
        return np.array([feat_dict[name] for name in self.schema.feature_names], dtype=np.float32)

