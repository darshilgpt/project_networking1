"""Attack label normalization, taxonomy mapping, and label encoding for ML."""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple


# Canonical Attack Category Taxonomy
class AttackCategory:
    BENIGN = "BENIGN"
    DOS = "DoS"
    DDOS = "DDoS"
    PORTSCAN = "PortScan"
    BOT = "Bot"
    BRUTE_FORCE = "Brute Force"
    WEB_ATTACK = "Web Attack"
    INFILTRATION = "Infiltration"
    HEARTBLEED = "Heartbleed"
    UNKNOWN = "UNKNOWN"


# Mapping table from raw CIC-IDS2017 label variants to canonical categories
RAW_LABEL_MAPPINGS: Dict[str, str] = {
    # Benign
    "benign": AttackCategory.BENIGN,

    # DDoS & DoS
    "ddos": AttackCategory.DDOS,
    "dos": AttackCategory.DOS,
    "dos goldeneye": AttackCategory.DOS,
    "dos hulk": AttackCategory.DOS,
    "dos slowhttptest": AttackCategory.DOS,
    "dos slowloris": AttackCategory.DOS,

    # PortScan
    "portscan": AttackCategory.PORTSCAN,
    "port scan": AttackCategory.PORTSCAN,

    # Bot
    "bot": AttackCategory.BOT,
    "botnet": AttackCategory.BOT,

    # Brute Force (Patator & Web)
    "ftp-patator": AttackCategory.BRUTE_FORCE,
    "ssh-patator": AttackCategory.BRUTE_FORCE,
    "brute force": AttackCategory.BRUTE_FORCE,

    # Web Attacks
    "web attack": AttackCategory.WEB_ATTACK,
    "web attack - brute force": AttackCategory.WEB_ATTACK,
    "web attack - sql injection": AttackCategory.WEB_ATTACK,
    "web attack - xss": AttackCategory.WEB_ATTACK,
    "web attack brute force": AttackCategory.WEB_ATTACK,
    "web attack sql injection": AttackCategory.WEB_ATTACK,
    "web attack xss": AttackCategory.WEB_ATTACK,

    # Infiltration & Exploits
    "infiltration": AttackCategory.INFILTRATION,
    "infilteration": AttackCategory.INFILTRATION,  # Handle CIC-IDS2017 typo
    "heartbleed": AttackCategory.HEARTBLEED,
}


def clean_raw_label(raw_label: str) -> str:
    """Cleans encoding artifacts, non-ascii characters, whitespace, and case from raw CSV labels."""
    if not raw_label:
        return "UNKNOWN"
    # Replace non-ascii artifacts (e.g.  or smart dashes) with standard dash
    s = re.sub(r"[^\x00-\x7F]+", "-", raw_label.strip())
    # Standardize multiple spaces or dashes
    s = re.sub(r"\s+", " ", s).lower().strip()
    return s


class AttackLabelMapper:
    """Normalizes and maps raw dataset attack labels into consistent canonical categories."""

    def __init__(self) -> None:
        self.mappings: Dict[str, str] = dict(RAW_LABEL_MAPPINGS)
        self.discovered_unknown_labels: Set[str] = set()

    def map_label(self, raw_label: str) -> Tuple[str, str]:
        """
        Maps a raw dataset label into (canonical_category, original_cleaned_label).
        If unknown, returns (AttackCategory.UNKNOWN, original_cleaned_label) and records it.
        """
        cleaned = clean_raw_label(raw_label)

        # 1. Exact match in mapping
        if cleaned in self.mappings:
            return self.mappings[cleaned], raw_label.strip()

        # 2. Fuzzy substring heuristic matching
        if "benign" in cleaned:
            return AttackCategory.BENIGN, raw_label.strip()
        elif "ddos" in cleaned:
            return AttackCategory.DDOS, raw_label.strip()
        elif "dos" in cleaned:
            return AttackCategory.DOS, raw_label.strip()
        elif "portscan" in cleaned or "port scan" in cleaned:
            return AttackCategory.PORTSCAN, raw_label.strip()
        elif "bot" in cleaned:
            return AttackCategory.BOT, raw_label.strip()
        elif "patator" in cleaned or "brute" in cleaned:
            return AttackCategory.BRUTE_FORCE, raw_label.strip()
        elif "web attack" in cleaned or "sql" in cleaned or "xss" in cleaned:
            return AttackCategory.WEB_ATTACK, raw_label.strip()
        elif "infil" in cleaned:
            return AttackCategory.INFILTRATION, raw_label.strip()
        elif "heartbleed" in cleaned:
            return AttackCategory.HEARTBLEED, raw_label.strip()

        # Unknown label detected
        self.discovered_unknown_labels.add(raw_label.strip())
        return AttackCategory.UNKNOWN, raw_label.strip()

    def get_category_list(self) -> List[str]:
        """Returns the canonical ordered list of attack categories."""
        return [
            AttackCategory.BENIGN,
            AttackCategory.DOS,
            AttackCategory.DDOS,
            AttackCategory.PORTSCAN,
            AttackCategory.BOT,
            AttackCategory.BRUTE_FORCE,
            AttackCategory.WEB_ATTACK,
            AttackCategory.INFILTRATION,
            AttackCategory.HEARTBLEED,
        ]

