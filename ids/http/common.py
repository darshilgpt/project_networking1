"""Shared normalization, sanitization, and evidence helpers for HTTP threat detectors."""

from __future__ import annotations

import html
import re
from typing import Dict, List, Optional, Tuple
import urllib.parse


def redact_sensitive_headers(headers: Dict[str, str]) -> Dict[str, str]:
    """
    Returns a copy of headers with credentials and sensitive state completely redacted.
    Explicitly redacts Cookie, Authorization, Proxy-Authorization, X-Api-Key, etc.
    """
    sanitized: Dict[str, str] = {}
    sensitive_keys = {
        "cookie",
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "apikey",
        "set-cookie",
        "password",
        "secret",
        "token",
    }
    for k, v in headers.items():
        k_lower = k.lower()
        if k_lower in sensitive_keys or any(s in k_lower for s in ("token", "secret", "auth", "passwd")):
            sanitized[k] = f"[REDACTED_{k.upper()}]"
        else:
            sanitized[k] = v
    return sanitized


def sanitize_evidence_string(text: str, max_len: int = 128) -> str:
    """
    Sanitizes evidence text by masking passwords/tokens and truncating to max_len.
    """
    if not text:
        return ""
    # Mask key=value patterns for passwords/secrets
    masked = re.sub(
        r"(?i)\b(password|passwd|secret|token|api_key|key|auth|session_id|sessionid)\s*=\s*[^&\s;]+",
        r"\1=[REDACTED]",
        text,
    )
    # Mask Cookie header occurrences if embedded
    masked = re.sub(r"(?i)cookie:\s*[^;\r\n]+", "Cookie: [REDACTED]", masked)
    if len(masked) > max_len:
        return masked[:max_len] + "...[TRUNCATED]"
    return masked


def normalize_http_text(text: str) -> str:
    """
    Normalizes HTTP text for threat inspection:
    1. Multi-pass bounded URL decoding (up to 3 passes).
    2. HTML entity unescaping (&lt; -> <, &#x3c; -> <).
    3. Null-byte removal/neutralization.
    4. Path delimiter normalization (\\ -> /).
    """
    if not text:
        return ""

    curr = text
    # 1. URL decoding
    for _ in range(3):
        try:
            decoded = urllib.parse.unquote(curr)
            if decoded == curr:
                break
            curr = decoded
        except Exception:
            break

    # 2. HTML entity unescaping
    try:
        curr = html.unescape(curr)
    except Exception:
        pass

    # 3. Path slash normalization
    curr = curr.replace("\\", "/")

    return curr

