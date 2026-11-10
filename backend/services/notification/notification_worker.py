"""Notification worker executing asynchronous SMTP deliveries via a bounded thread-safe queue."""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Any, Callable, Dict, Optional

from backend.services.notification.email_service import EmailDeliveryService
from backend.services.notification.email_templates import generate_security_alert_email
from backend.services.notification.notification_config import NotificationConfig
from models.alert_model import IDSAlert

logger = logging.getLogger("dpi_ids_ips.backend.notification.worker")


class NotificationDeliveryJob:
    """Encapsulates a queued email alert delivery task."""

    def __init__(self, alert: IDSAlert, retry_count: int = 0) -> None:
        self.alert = alert
        self.retry_count = retry_count
        self.enqueued_at = time.time()


class NotificationWorker:
    """
    Background worker thread pool handling email generation and SMTP transmission.

    Guarantees:
    - Never blocks packet capture or IDS alert processing.
    - Bounded memory queue.
    - Controlled retry attempts for transient transport failures.
    - Graceful bounded shutdown.
    """

    def __init__(
        self,
        config: Optional[NotificationConfig] = None,
        email_service: Optional[EmailDeliveryService] = None,
        on_success: Optional[Callable[[IDSAlert], None]] = None,
        on_failure: Optional[Callable[[IDSAlert], None]] = None,
    ) -> None:
        self.config = config or NotificationConfig()
        self.email_service = email_service or EmailDeliveryService(self.config)
        self.on_success = on_success
        self.on_failure = on_failure

        self._queue: queue.Queue[Optional[NotificationDeliveryJob]] = queue.Queue(
            maxsize=self.config.max_queue_size
        )
        self._is_running = False
        self._worker_thread: Optional[threading.Thread] = None

        # Monotonic metrics
        self._metrics_lock = threading.Lock()
        self.total_enqueued = 0
        self.total_delivered = 0
        self.total_failed = 0
        self.total_dropped_queue_full = 0

    def start(self) -> None:
        """Starts the background worker thread."""
        if self._is_running:
            return

        self._is_running = True
        self._worker_thread = threading.Thread(
            target=self._worker_loop,
            name="NotificationWorkerThread",
            daemon=True,
        )
        self._worker_thread.start()
        logger.info("NotificationWorker background thread started.")

    def stop(self, timeout: float = 2.0) -> None:
        """Gracefully halts the worker thread, allowing pending deliveries up to timeout."""
        if not self._is_running:
            return

        self._is_running = False
        try:
            self._queue.put_nowait(None)  # Poison pill
        except queue.Full:
            pass

        if self._worker_thread and self._worker_thread.is_alive():
            self._worker_thread.join(timeout=timeout)
        self._worker_thread = None
        logger.info("NotificationWorker background thread halted.")

    def enqueue(self, alert: IDSAlert) -> bool:
        """
        Non-blocking submission of a security alert for email transmission.
        Returns True if enqueued, False if dropped due to queue saturation.
        """
        if not self.config.email_enabled:
            return False

        job = NotificationDeliveryJob(alert=alert)
        try:
            self._queue.put_nowait(job)
            with self._metrics_lock:
                self.total_enqueued += 1
            return True
        except queue.Full:
            with self._metrics_lock:
                self.total_dropped_queue_full += 1
            logger.warning("Notification queue full; security alert email dropped.")
            return False

    def _worker_loop(self) -> None:
        """Consumes queued alerts and transmits emails safely."""
        while self._is_running:
            try:
                job = self._queue.get(timeout=0.5)
            except queue.Empty:
                continue

            if job is None:
                self._queue.task_done()
                break

            try:
                self._deliver_job(job)
            except Exception as e:
                logger.error(f"Unexpected error in notification worker: {e}", exc_info=True)
                with self._metrics_lock:
                    self.total_failed += 1
                if self.on_failure:
                    self.on_failure(job.alert)
            finally:
                self._queue.task_done()

    def _deliver_job(self, job: NotificationDeliveryJob) -> None:
        """Renders templates and executes SMTP send with retry."""
        alert = job.alert
        subject, plain_text, html_body = generate_security_alert_email(alert)

        success = self.email_service.send_alert_email(
            subject=subject,
            plain_text_body=plain_text,
            html_body=html_body,
        )

        if success:
            with self._metrics_lock:
                self.total_delivered += 1
            if self.on_success:
                self.on_success(alert)
        else:
            if job.retry_count < self.config.max_retries:
                job.retry_count += 1
                logger.info(
                    f"Retrying email notification for alert {alert.alert_id} (Attempt {job.retry_count}/{self.config.max_retries})"
                )
                try:
                    self._queue.put_nowait(job)
                except queue.Full:
                    with self._metrics_lock:
                        self.total_failed += 1
                    if self.on_failure:
                        self.on_failure(alert)
            else:
                with self._metrics_lock:
                    self.total_failed += 1
                if self.on_failure:
                    self.on_failure(alert)

    def get_stats(self) -> Dict[str, Any]:
        """Returns thread-safe snapshot metrics."""
        with self._metrics_lock:
            return {
                "is_running": self._is_running,
                "queue_depth": self._queue.qsize(),
                "queue_capacity": self.config.max_queue_size,
                "total_enqueued": self.total_enqueued,
                "total_delivered": self.total_delivered,
                "total_failed": self.total_failed,
                "total_dropped_queue_full": self.total_dropped_queue_full,
            }

