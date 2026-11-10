"""Notification manager orchestrating qualification, duplicate suppression, and routing."""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, Optional, Tuple

from backend.services.notification.notification_config import NotificationConfig
from backend.services.notification.notification_worker import NotificationWorker
from models.alert_model import IDSAlert, Severity

logger = logging.getLogger("dpi_ids_ips.backend.notification.manager")


class NotificationManager:
    """
    Evaluates incoming IDS security alerts against qualification criteria,
    applies bounded cooldown duplicate suppression, and dispatches to NotificationWorker.
    """

    def __init__(
        self,
        config: Optional[NotificationConfig] = None,
        worker: Optional[NotificationWorker] = None,
    ) -> None:
        self.config = config or NotificationConfig()
        self.worker = worker or NotificationWorker(self.config)

        # Cooldown cache: (source_ip, category_name) -> last_notified_timestamp
        self._cooldown_lock = threading.Lock()
        self._cooldown_cache: Dict[Tuple[str, str], float] = {}
        self._max_cooldown_entries = 10000

        # Monotonic counters
        self._stats_lock = threading.Lock()
        self.total_received = 0
        self.total_qualified = 0
        self.total_suppressed_cooldown = 0
        self.total_suppressed_unqualified = 0

    def start(self) -> None:
        """Starts underlying background delivery worker."""
        self.worker.start()

    def stop(self, timeout: float = 2.0) -> None:
        """Stops underlying worker safely."""
        self.worker.stop(timeout=timeout)

    def is_alert_qualifying(self, alert: IDSAlert) -> bool:
        """
        Determines if an alert qualifies for developer notification.

        Conditions:
        - Must NOT be benign or normal informational events.
        - By default, ML alerts (ML_CLASSIFICATION / ML_ANOMALY) are excluded unless notify_on_ml is True.
        - Must match qualifying categories (e.g., PORT_SCAN, SYN_SCAN, SYN_FLOOD, SQLI, XSS, etc.)
          OR hold HIGH / CRITICAL severity.
        """
        cat_str = getattr(alert.category, "value", str(alert.category)).upper()

        # Handle ML alerts
        if cat_str in ("ML_CLASSIFICATION", "ML_ANOMALY"):
            if not self.config.notify_on_ml:
                return False

        # Severity check
        sev = getattr(alert, "severity", Severity.LOW)
        if sev in (Severity.HIGH, Severity.CRITICAL):
            return True

        # Category check
        if cat_str in self.config.qualifying_categories:
            return True

        return False

    def handle_alert(self, alert: IDSAlert) -> bool:
        """
        Main entry point for incoming IDS alerts.
        Non-blocking: evaluates qualification and cooldown, then submits to worker queue.
        Returns True if enqueued for notification, False if filtered or suppressed.
        """
        with self._stats_lock:
            self.total_received += 1

        if not self.config.email_enabled:
            return False

        if not self.is_alert_qualifying(alert):
            with self._stats_lock:
                self.total_suppressed_unqualified += 1
            return False

        with self._stats_lock:
            self.total_qualified += 1

        cat_str = getattr(alert.category, "value", str(alert.category)).upper()
        cache_key = (alert.source_ip, cat_str)
        now = time.time()

        # Check cooldown duplicate suppression
        with self._cooldown_lock:
            last_sent = self._cooldown_cache.get(cache_key)
            if last_sent is not None and (now - last_sent) < self.config.email_cooldown_seconds:
                with self._stats_lock:
                    self.total_suppressed_cooldown += 1
                logger.debug(
                    f"Suppressed duplicate alert notification for {cache_key}: cooldown active ({(now - last_sent):.1f}s / {self.config.email_cooldown_seconds}s)"
                )
                return False

            # Bounded cache management: evict oldest half if reaching capacity
            if len(self._cooldown_cache) >= self._max_cooldown_entries:
                remove_count = len(self._cooldown_cache) // 2
                it = iter(list(self._cooldown_cache.keys()))
                for _ in range(remove_count):
                    try:
                        del self._cooldown_cache[next(it)]
                    except (StopIteration, KeyError):
                        break

            # Record notification timestamp
            self._cooldown_cache[cache_key] = now

        # Enqueue for delivery
        return self.worker.enqueue(alert)

    def get_stats(self) -> Dict[str, Any]:
        """Returns snapshot telemetry for notification system."""
        worker_stats = self.worker.get_stats()
        with self._stats_lock:
            with self._cooldown_lock:
                cooldown_count = len(self._cooldown_cache)
            return {
                "email_enabled": self.config.email_enabled,
                "recipients": self.config.alert_email_to,
                "cooldown_seconds": self.config.email_cooldown_seconds,
                "active_cooldown_entries": cooldown_count,
                "total_received": self.total_received,
                "total_qualified": self.total_qualified,
                "total_suppressed_cooldown": self.total_suppressed_cooldown,
                "total_suppressed_unqualified": self.total_suppressed_unqualified,
                "worker": worker_stats,
            }

