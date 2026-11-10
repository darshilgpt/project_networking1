"""HTTP Threat Detection package exporting specialized modular detectors."""

from __future__ import annotations

from ids.http.common import normalize_http_text, redact_sensitive_headers, sanitize_evidence_string
from ids.http.sqli_detector import SQLiDetector
from ids.http.xss_detector import XSSDetector
from ids.http.traversal_detector import PathTraversalDetector
from ids.http.command_injection_detector import CommandInjectionDetector

__all__ = [
    "SQLiDetector",
    "XSSDetector",
    "PathTraversalDetector",
    "CommandInjectionDetector",
    "normalize_http_text",
    "redact_sensitive_headers",
    "sanitize_evidence_string",
]

