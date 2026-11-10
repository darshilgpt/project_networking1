"""Heuristic Domain Generation Algorithm (DGA) detector.

Explicitly non-ML: relies on statistical and linguistic character metrics.
Evaluates normalized entropy, consonant-to-vowel ratio, consonant runs, and digit ratios.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from ids.dns.common import (
    calculate_entropy,
    calculate_normalized_entropy,
    compute_consonant_vowel_ratio,
    compute_digit_ratio,
    compute_longest_consonant_run,
    extract_apex_and_subdomain,
    get_packet_endpoints,
    is_cdn_or_cloud_domain,
)
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from models.packet_models import ParsedPacket

logger = logging.getLogger(__name__)


class DNSDGADetector:
    """Detects algorithmic domain name generation patterns using heuristic scoring."""

    def __init__(self) -> None:
        # Minimum label length to evaluate (short labels are ignored to avoid false positives)
        self.MIN_LABEL_LENGTH = 12

    def evaluate(
        self,
        domain_name: str,
        packet: ParsedPacket,
        next_alert_id_fn: callable,
        now: float,
    ) -> List[IDSAlert]:
        """
        Evaluates a queried domain for DGA characteristics.
        
        Returns:
            List of IDSAlert (at most 1) if heuristic threshold is met.
        """
        clean_domain = domain_name.strip().lower().rstrip(".")
        if not clean_domain:
            return []

        # Skip local, infrastructure, or reverse-lookup domains
        if any(clean_domain.endswith(ext) for ext in (".arpa", ".local", ".internal", ".lan", ".localhost")):
            return []

        apex, subdomain = extract_apex_and_subdomain(clean_domain)
        
        # Candidate label selection: evaluate the longest subdomain label if present,
        # otherwise evaluate the eSLD label of the apex.
        candidate_label = ""
        if subdomain:
            sub_parts = subdomain.split(".")
            candidate_label = max(sub_parts, key=len)
        elif apex:
            apex_parts = apex.split(".")
            candidate_label = apex_parts[0]

        # Minimum length gate: never evaluate labels shorter than 12 characters
        if len(candidate_label) < self.MIN_LABEL_LENGTH:
            return []

        # Feature 1: Normalized Shannon Entropy (Weight: 1.0)
        norm_entropy = calculate_normalized_entropy(candidate_label)
        raw_entropy = calculate_entropy(candidate_label)
        f1_triggered = (norm_entropy >= 0.82 and raw_entropy >= 3.85)

        # Feature 2: Consonant-to-Vowel Ratio (Weight: 1.0)
        # Note: Absence of vowels or high ratio ALONE NEVER triggers classification.
        cv_ratio, c_count, v_count = compute_consonant_vowel_ratio(candidate_label)
        f2_triggered = (cv_ratio >= 4.5 or (v_count == 0 and c_count >= self.MIN_LABEL_LENGTH))

        # Feature 3: Longest Consecutive Consonant Run (Weight: 1.0)
        c_run = compute_longest_consonant_run(candidate_label)
        f3_triggered = (c_run >= 5)

        # Feature 4: Digit-to-Length Ratio & Alternating Transitions (Weight: 1.0)
        digit_ratio, transitions = compute_digit_ratio(candidate_label)
        f4_triggered = (digit_ratio >= 0.35 and transitions >= 3)

        # Calculate composite score
        score = (
            (1.0 if f1_triggered else 0.0)
            + (1.0 if f2_triggered else 0.0)
            + (1.0 if f3_triggered else 0.0)
            + (1.0 if f4_triggered else 0.0)
        )

        # CDN Confidence Attenuation:
        # Standard threshold is 3.0 (requires at least 3 distinct features to agree).
        # For CDN domains, threshold is elevated to 4.0 (requires all 4 features).
        is_cdn = is_cdn_or_cloud_domain(clean_domain)
        required_threshold = 4.0 if is_cdn else 3.0

        if score >= required_threshold:
            features_desc = []
            if f1_triggered:
                features_desc.append(f"NormEntropy={norm_entropy:.2f}")
            if f2_triggered:
                features_desc.append(f"C/VRatio={cv_ratio:.1f}")
            if f3_triggered:
                features_desc.append(f"ConsRun={c_run}")
            if f4_triggered:
                features_desc.append(f"DigitRatio={digit_ratio:.2f}")

            evidence = (
                f"Heuristic DGA indicator (non-ML statistical scoring: {score:.1f}/{required_threshold:.1f}): "
                f"Domain '{clean_domain[:64]}' label '{candidate_label[:32]}' matched [{', '.join(features_desc)}]. "
                f"Heuristic observation, not confirmed malware."
            )

            src_ip, dst_ip, src_port, dst_port = get_packet_endpoints(packet)

            alert = IDSAlert.create(
                alert_id=next_alert_id_fn(),
                timestamp=now,
                source_ip=src_ip,
                destination_ip=dst_ip,
                source_port=src_port,
                destination_port=dst_port,
                protocol="DNS",
                category=DetectionCategory.SUSPICIOUS_DNS,
                severity=Severity.MEDIUM,
                matched_rule="Heuristic DGA Domain Pattern (Statistical Indicator)",
                evidence=evidence[:256],
                recommended_action=DecisionAction.ALERT,
                packet_id=packet.packet_id,
            )
            return [alert]

        return []
