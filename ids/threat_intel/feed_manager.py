"""Feed Manager for loading, validating, and atomically reloading local IOC feeds."""

from __future__ import annotations

import csv
import json
import logging
import os
import time
from typing import Dict, List, Optional, Set, Tuple

from ids.threat_intel.common import (
    ThreatIndicator,
    normalize_domain,
    normalize_ip,
    normalize_network,
)
from models.alert_model import Severity

logger = logging.getLogger("dpi_ids_ips.ids.threat_intel.feed")


class FeedManager:
    """
    Manages loading, parsing, and atomic updating of threat intelligence feeds.
    Supports Plaintext, CSV, and JSON file formats with strict validation.
    """

    def __init__(self) -> None:
        self.feed_files: List[str] = []
        self.last_load_timestamp: float = 0.0

    def parse_plain_text(
        self,
        filepath: str,
        default_category: str = "MALWARE",
        default_severity: Severity = Severity.HIGH,
    ) -> List[ThreatIndicator]:
        """Parses a plaintext file containing one indicator (IP, CIDR, or domain) per line."""
        indicators: List[ThreatIndicator] = []
        source_name = os.path.basename(filepath)

        with open(filepath, "r", encoding="utf-8") as f:
            for line_no, raw_line in enumerate(f, start=1):
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue

                # Check if line contains inline comment
                if "#" in line:
                    line = line.split("#")[0].strip()

                ind = self._build_indicator(
                    indicator_str=line,
                    category=default_category,
                    severity=default_severity,
                    source=source_name,
                    confidence=1.0,
                    description=f"Listed in {source_name}:{line_no}",
                )
                if ind:
                    indicators.append(ind)
                else:
                    logger.debug(f"Skipping invalid plaintext indicator in {source_name}:{line_no}: '{line}'")

        return indicators

    def parse_csv(self, filepath: str) -> List[ThreatIndicator]:
        """
        Parses a CSV feed.
        Recognizes headers: indicator, ioc_type, category, severity, confidence, source, description, expires_at.
        If no header is present, expects format: indicator, category, severity, description.
        """
        indicators: List[ThreatIndicator] = []
        source_name = os.path.basename(filepath)

        with open(filepath, "r", encoding="utf-8") as f:
            # Check for header
            sample = f.read(2048)
            f.seek(0)
            has_header = False
            if sample:
                first_line = sample.splitlines()[0].lower()
                if any(k in first_line for k in ("indicator", "ip", "domain")):
                    has_header = True

            reader = csv.reader(f)
            if has_header:
                header = [h.strip().lower() for h in next(reader, [])]
                ind_idx = header.index("indicator") if "indicator" in header else (header.index("ip") if "ip" in header else header.index("domain"))
                cat_idx = header.index("category") if "category" in header else -1
                sev_idx = header.index("severity") if "severity" in header else -1
                conf_idx = header.index("confidence") if "confidence" in header else -1
                desc_idx = header.index("description") if "description" in header else -1
                exp_idx = header.index("expires_at") if "expires_at" in header else -1

                for line_no, row in enumerate(reader, start=2):
                    if not row or len(row) <= ind_idx:
                        continue
                    ind_val = row[ind_idx].strip()
                    if not ind_val:
                        continue
                    cat_val = row[cat_idx].strip() if cat_idx >= 0 and len(row) > cat_idx else "MALWARE"
                    sev_str = row[sev_idx].strip().upper() if sev_idx >= 0 and len(row) > sev_idx else "HIGH"
                    sev_val = Severity[sev_str] if sev_str in Severity.__members__ else Severity.HIGH
                    conf_val = float(row[conf_idx]) if conf_idx >= 0 and len(row) > conf_idx and row[conf_idx].replace(".", "", 1).isdigit() else 1.0
                    desc_val = row[desc_idx].strip() if desc_idx >= 0 and len(row) > desc_idx else f"Listed in {source_name}:{line_no}"
                    exp_val = float(row[exp_idx]) if exp_idx >= 0 and len(row) > exp_idx and row[exp_idx].replace(".", "", 1).isdigit() else None

                    ind = self._build_indicator(
                        indicator_str=ind_val,
                        category=cat_val,
                        severity=sev_val,
                        source=source_name,
                        confidence=conf_val,
                        description=desc_val,
                        expires_at=exp_val,
                    )
                    if ind:
                        indicators.append(ind)
            else:
                # Headerless fallback
                for line_no, row in enumerate(reader, start=1):
                    if not row or not row[0].strip():
                        continue
                    ind_val = row[0].strip()
                    cat_val = row[1].strip() if len(row) > 1 else "MALWARE"
                    sev_str = row[2].strip().upper() if len(row) > 2 else "HIGH"
                    sev_val = Severity[sev_str] if sev_str in Severity.__members__ else Severity.HIGH
                    desc_val = row[3].strip() if len(row) > 3 else f"Listed in {source_name}:{line_no}"

                    ind = self._build_indicator(
                        indicator_str=ind_val,
                        category=cat_val,
                        severity=sev_val,
                        source=source_name,
                        confidence=1.0,
                        description=desc_val,
                    )
                    if ind:
                        indicators.append(ind)

        return indicators

    def parse_json(self, filepath: str) -> List[ThreatIndicator]:
        """
        Parses a structured JSON feed.
        Supports:
        - List of dicts: `[{"indicator": "...", "category": "...", ...}, ...]`
        - Categorized dict: `{"ips": [...], "domains": [...]}`
        """
        indicators: List[ThreatIndicator] = []
        source_name = os.path.basename(filepath)

        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)

        raw_items: List[Dict] = []
        if isinstance(data, list):
            raw_items = data
        elif isinstance(data, dict):
            if "indicators" in data and isinstance(data["indicators"], list):
                raw_items = data["indicators"]
            else:
                for item in data.get("ips", []):
                    if isinstance(item, str):
                        raw_items.append({"indicator": item})
                    elif isinstance(item, dict):
                        raw_items.append(dict(item, indicator=item.get("indicator") or item.get("ip")))
                for item in data.get("domains", []):
                    if isinstance(item, str):
                        raw_items.append({"indicator": item})
                    elif isinstance(item, dict):
                        raw_items.append(dict(item, indicator=item.get("indicator") or item.get("domain")))

        for item in raw_items:
            if not isinstance(item, dict):
                continue
            ind_val = item.get("indicator") or item.get("ip") or item.get("domain")
            if not ind_val:
                continue
            cat_val = item.get("category", "MALWARE")
            sev_str = str(item.get("severity", "HIGH")).upper()
            sev_val = Severity[sev_str] if sev_str in Severity.__members__ else Severity.HIGH
            conf_val = float(item.get("confidence", 1.0))
            desc_val = item.get("description", f"Listed in {source_name}")
            source_override = item.get("source", source_name)
            exp_val = float(item["expires_at"]) if "expires_at" in item else None

            ind = self._build_indicator(
                indicator_str=ind_val,
                category=cat_val,
                severity=sev_val,
                source=source_override,
                confidence=conf_val,
                description=desc_val,
                expires_at=exp_val,
            )
            if ind:
                indicators.append(ind)

        return indicators

    def _build_indicator(
        self,
        indicator_str: str,
        category: str,
        severity: Severity,
        source: str,
        confidence: float = 1.0,
        description: str = "",
        expires_at: Optional[float] = None,
    ) -> Optional[ThreatIndicator]:
        """Validates and constructs a ThreatIndicator object."""
        val = indicator_str.strip()
        if not val:
            return None

        # 1. CIDR Network check
        if "/" in val:
            net = normalize_network(val)
            if net is not None:
                ioc_t = "IPv4_CIDR" if net.version == 4 else "IPv6_CIDR"
                return ThreatIndicator(
                    indicator=str(net),
                    ioc_type=ioc_t,
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    source=source,
                    description=description,
                    expires_at=expires_at,
                )
            return None

        # 2. IP Address check
        norm_ip = normalize_ip(val)
        if norm_ip is not None:
            ioc_t = "IPv4" if ":" not in norm_ip else "IPv6"
            return ThreatIndicator(
                indicator=norm_ip,
                ioc_type=ioc_t,
                category=category,
                severity=severity,
                confidence=confidence,
                source=source,
                description=description,
                expires_at=expires_at,
            )

        # 3. Domain Name check
        norm_dom = normalize_domain(val)
        # Validate domain: at least one dot, valid chars, and TLD cannot be purely numeric
        if "." in norm_dom and all(c.isalnum() or c in ".-" for c in norm_dom):
            parts = norm_dom.split(".")
            # A valid domain must have at least 2 non-empty labels and the TLD must not be purely numeric
            if len(parts) >= 2 and all(bool(p) for p in parts) and not parts[-1].isdigit() and not all(p.isdigit() for p in parts):
                return ThreatIndicator(
                    indicator=norm_dom,
                    ioc_type="DOMAIN",
                    category=category,
                    severity=severity,
                    confidence=confidence,
                    source=source,
                    description=description,
                    expires_at=expires_at,
                )

        return None
