"""Shared utilities, constants, normalization, and feature extractors for DNS threat detection."""

from __future__ import annotations

import math
import re
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# Curated table of multi-part public suffixes (ordered by specificity: longest first).
# Limitation: Domains using unlisted multi-part private suffixes (e.g. specialized dynamic DNS providers)
# fall back conservatively to two-part extraction (labels[-2:]).
CURATED_PUBLIC_SUFFIXES: Tuple[str, ...] = (
    # 3-part suffixes
    "nom.co.uk",
    "sch.uk",
    # 2-part ccTLD suffixes
    "co.uk",
    "org.uk",
    "gov.uk",
    "me.uk",
    "ltd.uk",
    "net.uk",
    "plc.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "edu.au",
    "gov.au",
    "asn.au",
    "id.au",
    "co.jp",
    "ne.jp",
    "or.jp",
    "ac.jp",
    "ad.jp",
    "ed.jp",
    "go.jp",
    "gr.jp",
    "lg.jp",
    "co.nz",
    "net.nz",
    "org.nz",
    "govt.nz",
    "ac.nz",
    "geek.nz",
    "gen.nz",
    "kiwi.nz",
    "school.nz",
    "com.br",
    "net.br",
    "org.br",
    "gov.br",
    "edu.br",
    "adv.br",
    "ind.br",
    "inf.br",
    "jus.br",
    "mil.br",
    "psi.br",
    "rec.br",
    "srv.br",
    "tmp.br",
    "tur.br",
    "tv.br",
    "etc.br",
    "com.sg",
    "net.sg",
    "org.sg",
    "gov.sg",
    "edu.sg",
    "per.sg",
    "co.in",
    "net.in",
    "org.in",
    "gen.in",
    "firm.in",
    "ind.in",
    "nic.in",
    "ac.in",
    "edu.in",
    "res.in",
    "gov.in",
    "mil.in",
    "com.cn",
    "net.cn",
    "org.cn",
    "gov.cn",
    "edu.cn",
    "ac.cn",
    "mil.cn",
    "com.de",
    "co.de",
    "com.fr",
    "asso.fr",
    "nom.fr",
    "prd.fr",
    "presse.fr",
    "tm.fr",
    "com.hk",
    "net.hk",
    "org.hk",
    "gov.hk",
    "edu.hk",
    "idv.hk",
    "com.tw",
    "net.tw",
    "org.tw",
    "idv.tw",
    "gov.tw",
    "edu.tw",
    "co.za",
    "net.za",
    "org.za",
    "gov.za",
    "ac.za",
    "edu.za",
    "law.za",
    "mil.za",
    "nom.za",
    "school.za",
    "co.kr",
    "ne.kr",
    "or.kr",
    "re.kr",
    "pe.kr",
    "go.kr",
    "mil.kr",
    "ac.kr",
    "hs.kr",
    "ms.kr",
    "es.kr",
    "sc.kr",
    "kg.kr",
    "seoul.kr",
    "busan.kr",
    "daegu.kr",
    "incheon.kr",
    "gwangju.kr",
    "daejeon.kr",
    "ulsan.kr",
    "gyeonggi.kr",
    "gangwon.kr",
    "chungbuk.kr",
    "chungnam.kr",
    "jeonbuk.kr",
    "jeonnam.kr",
    "gyeongbuk.kr",
    "gyeongnam.kr",
    "jeju.kr",
)

# Known legitimate high-entropy / deep subdomain CDN & cloud providers
# Note on confidence attenuation: For these domains, the DGA score threshold is elevated from 3.0 to 4.0.
# Sensitivity trade-off: Setting the threshold to 4.0 eliminates false positives on randomized CDN edge hostnames,
# but it requires all 4 independent DGA heuristics to trigger simultaneously. It does NOT suppress independent
# anomalous behavior such as excessive query floods, abnormal response codes, or unauthorized zone transfers.
CDN_PROVIDER_DOMAINS: Tuple[str, ...] = (
    "cloudfront.net",
    "amazonaws.com",
    "akamai.net",
    "akamaiedge.net",
    "akadns.net",
    "azure.com",
    "trafficmanager.net",
    "azureedge.net",
    "1e100.net",
    "googlevideo.com",
    "googleusercontent.com",
    "cloudflare.com",
    "fastly.net",
    "github.io",
    "gitlab.io",
)

# Standard legitimate email and domain ownership verification prefixes in TXT records
LEGITIMATE_TXT_PREFIXES: Tuple[str, ...] = (
    "v=spf1",
    "v=dkim1",
    "v=dmarc1",
    "include:_spf",
    "google-site-verification=",
    "ms=ms",
    "apple-domain-verification=",
    "cisco-ci-domain-verification=",
    "facebook-domain-verification=",
    "statuspage-domain-verification=",
    "atlassian-domain-verification=",
    "docusign=",
    "stripe-verification=",
    "yandex-verification=",
    "adobe-idp-site-verification=",
)

# Precompiled regex patterns for encoding detection
# Note: Hex requires digits and hex letters to prevent pure alphabetic strings (like "aaaaa...") from matching as hex
HEX_REGEX = re.compile(r"^(?=.*[0-9])[0-9a-fA-F]{24,}$")
# Base32 requires a mixture of digits 2-7 and letters, or padding
BASE32_REGEX = re.compile(r"^(?=.*[2-7])[a-z2-7]{24,}$", re.IGNORECASE)
# Base64 requires either padding ('=') or alphanumeric without words separated by hyphens
BASE64_SUBDOMAIN_REGEX = re.compile(r"^(?!.*--)[a-zA-Z0-9+/]{30,}={0,2}$")


def extract_apex_and_subdomain(domain: str) -> Tuple[str, str]:
    """
    Extracts the apex domain (eSLD + public suffix) and subdomain prefix.
    Uses the longest matching suffix from CURATED_PUBLIC_SUFFIXES.
    
    Returns:
        Tuple of (apex_domain, subdomain_prefix).
        If domain is empty or single-label, returns (domain, "").
    """
    clean_domain = domain.strip().lower().rstrip(".")
    if not clean_domain:
        return "", ""

    labels = clean_domain.split(".")
    if len(labels) <= 1:
        return clean_domain, ""

    # Find the longest matching suffix from the curated table
    matched_suffix_parts = 0
    for suffix in CURATED_PUBLIC_SUFFIXES:
        s_parts = suffix.split(".")
        if len(labels) > len(s_parts):
            if labels[-len(s_parts):] == s_parts:
                matched_suffix_parts = len(s_parts)
                break  # Curated list is sorted with longest suffixes first

    if matched_suffix_parts > 0 and len(labels) > matched_suffix_parts:
        # Apex consists of the label right before suffix + suffix parts
        apex_labels = labels[-(matched_suffix_parts + 1):]
        subdomain_labels = labels[:-(matched_suffix_parts + 1)]
    else:
        # Default conservative fallback: last 2 labels as apex
        apex_labels = labels[-2:]
        subdomain_labels = labels[:-2]

    apex = ".".join(apex_labels)
    subdomain = ".".join(subdomain_labels)
    return apex, subdomain


def calculate_entropy(text: str) -> float:
    """Calculates standard Shannon entropy for a given text."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def calculate_normalized_entropy(text: str) -> float:
    """
    Calculates length-normalized Shannon entropy to avoid bias on short strings.
    Divides actual entropy by the maximum theoretical entropy for a string of that length.
    """
    if not text or len(text) <= 1:
        return 0.0
    raw_entropy = calculate_entropy(text)
    # Alphabet size upper bound for DNS labels: 37 (a-z, 0-9, '-')
    max_entropy = math.log2(min(len(text), 37))
    if max_entropy <= 0:
        return 0.0
    return raw_entropy / max_entropy


def compute_consonant_vowel_ratio(label: str) -> Tuple[float, int, int]:
    """
    Computes (consonant_to_vowel_ratio, consonant_count, vowel_count).
    If no vowels are present and consonants exist, returns (float('inf'), cons, 0).
    """
    vowels = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")
    v_count = 0
    c_count = 0
    for c in label.lower():
        if c in vowels:
            v_count += 1
        elif c in consonants:
            c_count += 1

    if v_count == 0:
        ratio = float("inf") if c_count > 0 else 0.0
    else:
        ratio = c_count / v_count
    return ratio, c_count, v_count


def compute_longest_consonant_run(label: str) -> int:
    """Returns the maximum consecutive run of consonants in a label."""
    consonants = set("bcdfghjklmnpqrstvwxyz")
    max_run = 0
    current_run = 0
    for c in label.lower():
        if c in consonants:
            current_run += 1
            if current_run > max_run:
                max_run = current_run
        else:
            current_run = 0
    return max_run


def compute_digit_ratio(label: str) -> Tuple[float, int]:
    """Returns (digit_ratio, alternating_transitions)."""
    if not label:
        return 0.0, 0
    digits = sum(1 for c in label if c.isdigit())
    ratio = digits / len(label)
    
    # Count transitions between letter and digit
    transitions = 0
    for i in range(len(label) - 1):
        c1, c2 = label[i], label[i + 1]
        if (c1.isalpha() and c2.isdigit()) or (c1.isdigit() and c2.isalpha()):
            transitions += 1
    return ratio, transitions


def is_cdn_or_cloud_domain(domain: str) -> bool:
    """Checks if the domain belongs to known high-entropy CDN/cloud infrastructure."""
    clean = domain.strip().lower().rstrip(".")
    for provider in CDN_PROVIDER_DOMAINS:
        if clean == provider or clean.endswith(f".{provider}"):
            return True
    return False


def get_packet_endpoints(packet: Any) -> Tuple[str, str, int, int]:
    """Extracts (src_ip, dst_ip, src_port, dst_port) from a ParsedPacket."""
    if hasattr(packet, "ipv4") and packet.ipv4:
        src_ip = packet.ipv4.src_ip
        dst_ip = packet.ipv4.dst_ip
    elif hasattr(packet, "ipv6") and packet.ipv6:
        src_ip = packet.ipv6.src_ip
        dst_ip = packet.ipv6.dst_ip
    elif hasattr(packet, "ip") and packet.ip:
        src_ip = packet.ip.src_ip
        dst_ip = packet.ip.dst_ip
    else:
        src_ip = "0.0.0.0"
        dst_ip = "0.0.0.0"

    if hasattr(packet, "udp") and packet.udp:
        src_port = packet.udp.src_port
        dst_port = packet.udp.dst_port
    elif hasattr(packet, "tcp") and packet.tcp:
        src_port = packet.tcp.src_port
        dst_port = packet.tcp.dst_port
    else:
        src_port = 0
        dst_port = 53

    return src_ip, dst_ip, src_port, dst_port


def is_legitimate_txt_record(txt_content: str) -> bool:
    """
    Checks if a TXT record payload matches recognized legitimate email authentication
    or domain ownership verification tokens (SPF, DKIM, DMARC, site verification).
    """
    clean = txt_content.strip().lower()
    for prefix in LEGITIMATE_TXT_PREFIXES:
        if clean.startswith(prefix) or prefix in clean:
            return True
    return False


class BoundedLRUCache:
    """A bounded FIFO/LRU tracking cache with capacity eviction and TTL support."""

    def __init__(self, max_size: int = 2000, ttl_seconds: float = 60.0) -> None:
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
            # Evict oldest 10%
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

    def __len__(self) -> int:
        return len(self._data)
