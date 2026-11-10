"""Notification configuration loaded safely from environment variables."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import List, Set


@dataclass
class NotificationConfig:
    """Configuration contract for security email notifications."""
    email_enabled: bool = False
    smtp_host: str = ""
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    alert_email_from: str = "ids-alerts@security.local"
    alert_email_to: List[str] = field(default_factory=lambda: ["kanvav.ec23@bmsce.ac.in"])
    email_cooldown_seconds: float = 300.0
    smtp_timeout_seconds: float = 10.0
    max_queue_size: int = 500
    max_retries: int = 2
    qualifying_categories: Set[str] = field(
        default_factory=lambda: {
            "PORT_SCAN",
            "SYN_SCAN",
            "SYN_FLOOD",
            "SQL_INJECTION",
            "XSS",
            "PATH_TRAVERSAL",
            "COMMAND_INJECTION",
            "DNS_TUNNELING",
            "MALICIOUS_IP",
            "MALICIOUS_DOMAIN",
        }
    )
    notify_on_ml: bool = False  # ML alerts do not trigger emails unless explicitly enabled

    @classmethod
    def from_env(cls) -> NotificationConfig:
        """Loads configuration from environment variables with safe defaults."""
        enabled_str = os.getenv("EMAIL_ENABLED", "false").strip().lower()
        email_enabled = enabled_str in ("true", "1", "yes", "on")

        smtp_host = os.getenv("SMTP_HOST", "").strip()
        port_raw = os.getenv("SMTP_PORT", "587").strip()
        try:
            smtp_port = int(port_raw)
        except ValueError:
            smtp_port = 587

        smtp_username = os.getenv("SMTP_USERNAME", "").strip()
        smtp_password = os.getenv("SMTP_PASSWORD", "").strip()

        from_addr = os.getenv("ALERT_EMAIL_FROM", "").strip() or "ids-alerts@security.local"

        # Recipients parsing (comma-separated, default: kanvav.ec23@bmsce.ac.in)
        to_raw = os.getenv("ALERT_EMAIL_TO", "").strip()
        if to_raw:
            recipients = [r.strip() for r in to_raw.split(",") if r.strip() and "@" in r]
            if not recipients:
                recipients = ["kanvav.ec23@bmsce.ac.in"]
        else:
            recipients = ["kanvav.ec23@bmsce.ac.in"]

        cooldown_raw = os.getenv("EMAIL_COOLDOWN_SECONDS", "300").strip()
        try:
            cooldown = max(10.0, float(cooldown_raw))
        except ValueError:
            cooldown = 300.0

        notify_ml = os.getenv("EMAIL_NOTIFY_ON_ML", "false").strip().lower() in ("true", "1", "yes")

        return cls(
            email_enabled=email_enabled,
            smtp_host=smtp_host,
            smtp_port=smtp_port,
            smtp_username=smtp_username,
            smtp_password=smtp_password,
            alert_email_from=from_addr,
            alert_email_to=recipients,
            email_cooldown_seconds=cooldown,
            notify_on_ml=notify_ml,
        )

