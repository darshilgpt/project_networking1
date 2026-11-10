"""Unit and integration tests for Phase 7.1 FastAPI Backend and Email Notification Foundation."""

from __future__ import annotations

import os
import time
from unittest.mock import MagicMock, patch
import pytest

from backend.api.dependencies import ServiceContainer
from backend.api.main import create_app
from backend.integrations.pipeline_adapter import PipelineAdapter
from backend.services.notification.email_service import EmailDeliveryService
from backend.services.notification.email_templates import generate_security_alert_email, sanitize_text
from backend.services.notification.notification_config import NotificationConfig
from backend.services.notification.notification_manager import NotificationManager
from backend.services.notification.notification_worker import NotificationWorker
from models.alert_model import DecisionAction, DetectionCategory, IDSAlert, Severity
from server.client_manager import ClientManager
from server.server import NetworkSecurityServer, ServerConfig
from server.worker_pool import PipelineWorkerPool


def make_test_alert(
    alert_id: int = 1,
    source_ip: str = "10.10.0.50",
    category: DetectionCategory = DetectionCategory.PORT_SCAN,
    severity: Severity = Severity.HIGH,
    action: DecisionAction = DecisionAction.BLOCK,
    evidence: str = "SYN probes to 20 ports",
) -> IDSAlert:
    return IDSAlert(
        alert_id=alert_id,
        timestamp=time.time(),
        datetime_str="12:00:00",
        source_ip=source_ip,
        destination_ip="10.10.0.1",
        source_port=45678,
        destination_port=80,
        protocol="TCP",
        category=category,
        severity=severity,
        matched_rule="Test Port Scan Rule",
        evidence=evidence,
        recommended_action=action,
        packet_id=100,
    )


# ==============================================================================
# 1. Configuration & Email Service Tests
# ==============================================================================

def test_notification_config_defaults():
    """Verify default notification settings and default recipient."""
    cfg = NotificationConfig()
    assert cfg.email_enabled is False
    assert cfg.alert_email_to == ["kanvav.ec23@bmsce.ac.in"]
    assert cfg.email_cooldown_seconds == 300.0


def test_notification_config_from_env_multiple_recipients(monkeypatch):
    """Verify comma-separated recipient parsing and environment variable overrides."""
    monkeypatch.setenv("EMAIL_ENABLED", "true")
    monkeypatch.setenv("SMTP_HOST", "smtp.test.com")
    monkeypatch.setenv("SMTP_PORT", "2525")
    monkeypatch.setenv("ALERT_EMAIL_TO", "dev1@bmsce.ac.in, dev2@bmsce.ac.in , invalid-email")
    monkeypatch.setenv("EMAIL_COOLDOWN_SECONDS", "120")

    cfg = NotificationConfig.from_env()
    assert cfg.email_enabled is True
    assert cfg.smtp_host == "smtp.test.com"
    assert cfg.smtp_port == 2525
    assert cfg.alert_email_to == ["dev1@bmsce.ac.in", "dev2@bmsce.ac.in"]
    assert cfg.email_cooldown_seconds == 120.0


def test_email_template_sanitization():
    """Verify HTML escaping and credential redaction in email templates."""
    raw_evidence = "<script>alert('xss')</script> Authorization: Bearer secret_token_123"
    sanitized = sanitize_text(raw_evidence)
    assert "&lt;script&gt;" in sanitized
    assert "secret_token_123" not in sanitized
    assert "[REDACTED]" in sanitized

    alert = make_test_alert(evidence=raw_evidence)
    subj, plain, html = generate_security_alert_email(alert)
    assert "[SECURITY ALERT - HIGH]" in subj
    assert "10.10.0.50" in plain
    assert "secret_token_123" not in html
    assert "BMSCE Project" in html


def test_email_delivery_service_disabled_mode():
    """Verify email delivery returns False immediately without touching network when disabled."""
    cfg = NotificationConfig(email_enabled=False)
    svc = EmailDeliveryService(config=cfg)
    delivered = svc.send_alert_email(
        subject="Test",
        plain_text_body="Test",
        html_body="<p>Test</p>",
    )
    assert delivered is False


def test_email_delivery_service_mock_smtp():
    """Verify SMTP connection, STARTTLS, and delivery via mock SMTP."""
    cfg = NotificationConfig(
        email_enabled=True,
        smtp_host="smtp.mock.com",
        smtp_port=587,
        smtp_username="user@mock.com",
        smtp_password="safe_password",
        alert_email_to=["kanvav.ec23@bmsce.ac.in"],
    )
    svc = EmailDeliveryService(config=cfg)

    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_server = MagicMock()
        mock_server.has_extn.return_value = True
        mock_smtp_cls.return_value.__enter__.return_value = mock_server

        success = svc.send_alert_email(
            subject="Test Subject",
            plain_text_body="Test Body",
            html_body="<p>Test Body</p>",
        )

        assert success is True
        mock_server.ehlo.assert_called()
        mock_server.starttls.assert_called()
        mock_server.login.assert_called_with("user@mock.com", "safe_password")
        mock_server.sendmail.assert_called_once()


def test_email_delivery_service_handles_smtp_error_safely():
    """Verify SMTP exceptions are logged without leaking passwords and return False."""
    cfg = NotificationConfig(
        email_enabled=True,
        smtp_host="smtp.mock.com",
        smtp_username="user",
        smtp_password="secret_pass",
    )
    svc = EmailDeliveryService(config=cfg)

    with patch("smtplib.SMTP") as mock_smtp_cls:
        mock_server = MagicMock()
        mock_server.login.side_effect = Exception("Auth Failure secret_pass")
        mock_smtp_cls.return_value.__enter__.return_value = mock_server

        # Must not raise exception
        success = svc.send_alert_email(
            subject="Test Subject",
            plain_text_body="Body",
            html_body="<p>Body</p>",
        )
        assert success is False


# ==============================================================================
# 2. Notification Manager & Worker Tests
# ==============================================================================

def test_notification_manager_qualification():
    """Verify only qualifying security alerts enter notification pipeline."""
    cfg = NotificationConfig(email_enabled=True)
    mgr = NotificationManager(config=cfg)

    # 1. Port scan qualifies
    alert_ps = make_test_alert(category=DetectionCategory.PORT_SCAN, severity=Severity.HIGH)
    assert mgr.is_alert_qualifying(alert_ps) is True

    # 2. SYN flood qualifies
    alert_sf = make_test_alert(category=DetectionCategory.SYN_FLOOD, severity=Severity.CRITICAL)
    assert mgr.is_alert_qualifying(alert_sf) is True

    # 3. Informational or low severity non-qualifying
    alert_low = make_test_alert(category=DetectionCategory.PARSER_WARNING, severity=Severity.LOW)
    assert mgr.is_alert_qualifying(alert_low) is False

    # 4. ML alert does not qualify by default
    alert_ml = make_test_alert(category=DetectionCategory.ML_CLASSIFICATION, severity=Severity.HIGH)
    assert mgr.is_alert_qualifying(alert_ml) is False

    # 5. ML alert qualifies if notify_on_ml is True
    cfg.notify_on_ml = True
    assert mgr.is_alert_qualifying(alert_ml) is True


def test_notification_cooldown_and_duplicate_suppression():
    """Verify duplicate alert suppression within cooldown window."""
    cfg = NotificationConfig(
        email_enabled=True,
        email_cooldown_seconds=60.0,
    )
    # Mock worker so no real thread/send occurs
    mock_worker = MagicMock(spec=NotificationWorker)
    mock_worker.enqueue.return_value = True

    mgr = NotificationManager(config=cfg, worker=mock_worker)

    alert1 = make_test_alert(alert_id=1, source_ip="10.10.0.99", category=DetectionCategory.PORT_SCAN)
    alert2 = make_test_alert(alert_id=2, source_ip="10.10.0.99", category=DetectionCategory.PORT_SCAN)
    alert_diff_cat = make_test_alert(alert_id=3, source_ip="10.10.0.99", category=DetectionCategory.SYN_FLOOD)
    alert_diff_ip = make_test_alert(alert_id=4, source_ip="10.10.0.100", category=DetectionCategory.PORT_SCAN)

    # First alert submitted -> succeeds
    assert mgr.handle_alert(alert1) is True
    assert mock_worker.enqueue.call_count == 1

    # Second alert identical (IP, category) inside cooldown -> suppressed
    assert mgr.handle_alert(alert2) is False
    assert mock_worker.enqueue.call_count == 1
    assert mgr.total_suppressed_cooldown == 1

    # Different category from same IP -> allowed
    assert mgr.handle_alert(alert_diff_cat) is True
    assert mock_worker.enqueue.call_count == 2

    # Same category from different IP -> allowed
    assert mgr.handle_alert(alert_diff_ip) is True
    assert mock_worker.enqueue.call_count == 3


def test_notification_worker_queue_saturation_and_shutdown():
    """Verify bounded queue saturation drops cleanly and worker stops gracefully."""
    cfg = NotificationConfig(
        email_enabled=True,
        max_queue_size=2,
    )
    mock_svc = MagicMock()
    worker = NotificationWorker(config=cfg, email_service=mock_svc)
    worker.start()

    try:
        alert1 = make_test_alert(alert_id=1)
        alert2 = make_test_alert(alert_id=2)
        alert3 = make_test_alert(alert_id=3)

        # Worker starts consuming, but queue put_nowait should handle immediate bursts safely
        worker.enqueue(alert1)
        worker.enqueue(alert2)
        worker.enqueue(alert3)

        stats = worker.get_stats()
        assert stats["total_enqueued"] >= 2
    finally:
        worker.stop(timeout=1.0)
        assert worker._is_running is False


# ==============================================================================
# 3. FastAPI Application & Health Endpoint Tests
# ==============================================================================

def test_fastapi_health_endpoint():
    """Verify GET /api/v1/health returns operational status and accurate subsystem states."""
    from backend.api.routes.health import check_health

    adapter = PipelineAdapter()
    notif_mgr = NotificationManager()
    data = check_health(pipeline_adapter=adapter, notification_mgr=notif_mgr)

    assert data.api_status == "operational"
    assert data.version == "1.0.0"
    assert data.dpi_pipeline.status == "uninitialized"
    assert data.dpi_pipeline.operational is False
    assert data.ml_runtime.status == "uninitialized"
    assert data.ml_runtime.operational is False
    assert data.email_notification.status in ("disabled", "operational")


def test_fastapi_health_with_active_pipeline_adapter():
    """Verify health endpoint accurately reflects active worker pool metrics."""
    from backend.api.routes.health import check_health

    cm = ClientManager()
    wp = PipelineWorkerPool(client_manager=cm, num_workers=1, queue_size=10)
    adapter = PipelineAdapter(worker_pool=wp, client_manager=cm)
    notif_mgr = NotificationManager()

    try:
        data = check_health(pipeline_adapter=adapter, notification_mgr=notif_mgr)
        assert data.dpi_pipeline.status == "active"
        assert data.dpi_pipeline.operational is True
        assert data.dpi_pipeline.details is not None
        assert "total_processed" in data.dpi_pipeline.details
    finally:
        wp.stop()


# ==============================================================================
# 4. End-to-End Alert to Notification Pipeline Integration
# ==============================================================================

def test_ids_alert_to_notification_pipeline_integration():
    """Verify that an alert raised in NetworkSecurityServer routes non-blocking to NotificationManager."""
    mock_notif_mgr = MagicMock()

    cfg = ServerConfig(
        interface="1",  # Explicit non-interactive interface choice
        workers=1,
        enable_dashboard=False,
        notification_manager=mock_notif_mgr,
    )
    server = NetworkSecurityServer(cfg)

    test_alert = make_test_alert(alert_id=999)
    dummy_client = server.client_manager._get_or_create_client("10.10.0.50")

    # Raise alert
    server._on_alert_raised(test_alert, dummy_client)

    # Verify notification manager received alert
    mock_notif_mgr.handle_alert.assert_called_once_with(test_alert)

