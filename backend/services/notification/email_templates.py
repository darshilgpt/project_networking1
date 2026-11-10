"""Email templates for structured, professional, and sanitized security notifications."""

from __future__ import annotations

import html
import re
from typing import Optional, Tuple
from models.alert_model import IDSAlert


def sanitize_text(val: Optional[str]) -> str:
    """Escapes HTML special characters and strips non-printable control characters."""
    if not val:
        return "N/A"
    clean = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", "", str(val))
    # Redact common authorization and cookie credentials if present in evidence
    clean = re.sub(r"(?i)(authorization:\s*bearer\s+)[^\r\n]+", r"\1[REDACTED]", clean)
    clean = re.sub(r"(?i)(cookie:\s*)[^\r\n]+", r"\1[REDACTED]", clean)
    return html.escape(clean)


def generate_security_alert_email(alert: IDSAlert) -> Tuple[str, str, str]:
    """
    Generates subject, plain-text fallback, and HTML formatted email body.

    Returns:
        (subject, plain_text_body, html_body)
    """
    cat_str = getattr(alert.category, "value", str(alert.category))
    sev_str = getattr(alert.severity, "value", str(alert.severity))
    action_str = getattr(alert.recommended_action, "value", str(alert.recommended_action)) if alert.recommended_action else "ALERT"

    subject = f"[SECURITY ALERT - {sev_str}] {cat_str} detected from {alert.source_ip}"

    # Safe sanitized strings
    src_ip = sanitize_text(alert.source_ip)
    dst_ip = sanitize_text(alert.destination_ip)
    src_port = str(alert.source_port) if alert.source_port else "N/A"
    dst_port = str(alert.destination_port) if alert.destination_port else "N/A"
    proto = sanitize_text(alert.protocol)
    rule = sanitize_text(alert.matched_rule)
    evidence = sanitize_text(alert.evidence)
    timestamp = sanitize_text(alert.datetime_str or str(alert.timestamp))

    # Plain-text version
    plain_text = f"""======================================================================
               NETWORK INTRUSION SECURITY ALERT
======================================================================
Category       : {cat_str}
Severity       : {sev_str}
Action Taken   : {action_str}
Timestamp      : {timestamp}

Source         : {src_ip}:{src_port}
Destination    : {dst_ip}:{dst_port}
Protocol       : {proto}

Matched Rule   : {rule}
Evidence       : {evidence}

----------------------------------------------------------------------
This is an automated security advisory from your DPI/IDS Central Server.
======================================================================
"""

    # Severity accent styling
    sev_color = {
        "CRITICAL": "#d32f2f",
        "HIGH": "#e65100",
        "MEDIUM": "#f57c00",
        "LOW": "#0288d1",
    }.get(sev_str, "#546e7a")

    html_body = f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>{html.escape(subject)}</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f4f6f9; margin: 0; padding: 24px; color: #333; }}
    .container {{ max-width: 650px; margin: 0 auto; background: #ffffff; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 12px rgba(0,0,0,0.08); border-top: 6px solid {sev_color}; }}
    .header {{ padding: 24px 32px; background: #1a2232; color: #ffffff; }}
    .header h1 {{ margin: 0 0 8px 0; font-size: 20px; font-weight: 700; letter-spacing: 0.5px; }}
    .badge {{ display: inline-block; padding: 4px 10px; border-radius: 4px; font-weight: 700; font-size: 12px; background: {sev_color}; color: #ffffff; }}
    .content {{ padding: 28px 32px; }}
    .table-details {{ width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px; }}
    .table-details th, .table-details td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid #e0e6ed; }}
    .table-details th {{ width: 30%; color: #607274; font-weight: 600; background: #fafbfc; }}
    .table-details td {{ font-family: Consolas, 'Liberation Mono', Menlo, monospace; color: #1e293b; }}
    .evidence-block {{ background: #f8fafc; border: 1px solid #cbd5e1; border-radius: 6px; padding: 12px 16px; font-family: Consolas, monospace; font-size: 13px; color: #0f172a; word-break: break-all; max-height: 180px; overflow-y: auto; white-space: pre-wrap; }}
    .footer {{ padding: 16px 32px; background: #f1f5f9; font-size: 12px; color: #64748b; text-align: center; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>Central Network Security Alert</h1>
      <span class="badge">{html.escape(sev_str)} SEVERITY</span>
      <span style="margin-left: 8px; font-size: 13px; color: #94a3b8;">Action: <strong>{html.escape(action_str)}</strong></span>
    </div>
    <div class="content">
      <p style="margin-top: 0; font-size: 15px; line-height: 1.5;">
        A suspicious or malicious event matching detection rule <strong>{rule}</strong> was detected by the real-time DPI/IDS pipeline.
      </p>
      <table class="table-details">
        <tr><th>Alert Category</th><td>{html.escape(cat_str)}</td></tr>
        <tr><th>Timestamp</th><td>{timestamp}</td></tr>
        <tr><th>Source</th><td>{src_ip}:{src_port}</td></tr>
        <tr><th>Destination</th><td>{dst_ip}:{dst_port}</td></tr>
        <tr><th>Protocol</th><td>{proto}</td></tr>
        <tr><th>Action Taken</th><td>{html.escape(action_str)}</td></tr>
      </table>

      <h3 style="font-size: 14px; margin: 24px 0 8px 0; color: #334155;">Detection Evidence / Payload</h3>
      <div class="evidence-block">{evidence}</div>
    </div>
    <div class="footer">
      Automated Network Intrusion Detection System &bull; BMSCE Project &bull; Developer Advisory
    </div>
  </div>
</body>
</html>
"""

    return subject, plain_text, html_body

