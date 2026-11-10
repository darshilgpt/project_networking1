"""SMTP Email delivery service with STARTTLS, connection timeouts, and safe error handling."""

from __future__ import annotations

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import logging
import smtplib
from typing import List, Optional

from backend.services.notification.notification_config import NotificationConfig

logger = logging.getLogger("dpi_ids_ips.backend.notification.email")


class EmailDeliveryService:
    """Delivers MIME multipart (HTML + plain text fallback) security alerts via SMTP."""

    def __init__(self, config: Optional[NotificationConfig] = None) -> None:
        self.config = config or NotificationConfig()

    def send_alert_email(
        self,
        subject: str,
        plain_text_body: str,
        html_body: str,
        recipients: Optional[List[str]] = None,
    ) -> bool:
        """
        Transmits security alert email using configured SMTP host.

        Never logs SMTP passwords or sensitive authentication credentials.
        Returns True on successful handoff to MTA, False otherwise.
        """
        if not self.config.email_enabled:
            logger.debug("Email delivery skipped: email notifications are disabled.")
            return False

        if not self.config.smtp_host:
            logger.warning("Email delivery failed: SMTP_HOST is not configured.")
            return False

        target_recipients = recipients or self.config.alert_email_to
        if not target_recipients:
            logger.warning("Email delivery failed: No destination recipient configured.")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.config.alert_email_from
        msg["To"] = ", ".join(target_recipients)

        part_plain = MIMEText(plain_text_body, "plain", "utf-8")
        part_html = MIMEText(html_body, "html", "utf-8")
        msg.attach(part_plain)
        msg.attach(part_html)

        timeout = self.config.smtp_timeout_seconds

        try:
            # 1. Connect to SMTP server
            with smtplib.SMTP(host=self.config.smtp_host, port=self.config.smtp_port, timeout=timeout) as server:
                server.ehlo()

                # 2. Upgrade to TLS if supported and configured on port 587 or standard submission
                if server.has_extn("STARTTLS") or self.config.smtp_port == 587:
                    try:
                        server.starttls()
                        server.ehlo()
                    except Exception as tls_err:
                        logger.warning(f"STARTTLS upgrade encountered error: {tls_err}. Proceeding with connection.")

                # 3. Authenticate if username is provided (passwords never logged)
                if self.config.smtp_username and self.config.smtp_password:
                    server.login(self.config.smtp_username, self.config.smtp_password)

                # 4. Deliver message
                server.sendmail(
                    from_addr=self.config.alert_email_from,
                    to_addrs=target_recipients,
                    msg=msg.as_string(),
                )

            logger.info(f"Security alert email delivered successfully to {target_recipients}.")
            return True

        except smtplib.SMTPAuthenticationError:
            logger.error(
                f"SMTP Authentication Error: check SMTP_USERNAME ({self.config.smtp_username}) and password."
            )
            return False
        except (smtplib.SMTPConnectError, TimeoutError, smtplib.SMTPServerDisconnected) as conn_err:
            logger.error(f"SMTP Connection Error to {self.config.smtp_host}:{self.config.smtp_port} - {conn_err}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error delivering security alert email: {e}")
            return False

