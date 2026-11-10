"""Notification service package."""

from backend.services.notification.email_service import EmailDeliveryService
from backend.services.notification.email_templates import generate_security_alert_email
from backend.services.notification.notification_config import NotificationConfig
from backend.services.notification.notification_manager import NotificationManager
from backend.services.notification.notification_worker import NotificationWorker

__all__ = [
    "NotificationConfig",
    "EmailDeliveryService",
    "generate_security_alert_email",
    "NotificationWorker",
    "NotificationManager",
]

