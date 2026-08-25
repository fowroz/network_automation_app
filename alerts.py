"""
========================================================================
 Email / Slack alerting
========================================================================
Sends a notification when something the user cares about happens --
today that's "a scheduled or manual run had failures" and "a health
check regression was detected after a config change" -- via:

  - Email, using Python's stdlib smtplib/email (no extra packages
    required) over SMTP with STARTTLS or implicit TLS.
  - Slack, via an Incoming Webhook URL (a single HTTPS POST of a JSON
    payload, using urllib so no extra packages are required there
    either).

Both are entirely optional and independently configurable. Settings are
stored via storage.py's generic settings key/value table (see app.py's
/settings/alerts routes) with secrets (SMTP password, webhook URL)
encrypted at rest the same way schedule credentials are.

This module never raises out of its public send_* functions -- a failed
alert must never take down the automation run that triggered it. Errors
are returned as (False, "message") so the caller can log/surface them.
========================================================================
"""
import json
import smtplib
import ssl
import urllib.request
import urllib.error
from email.mime.text import MIMEText

ALERT_REQUEST_TIMEOUT = 15  # seconds


def send_email_alert(smtp_config: dict, subject: str, body: str):
    """
    smtp_config keys: host, port, username, password, use_tls (bool),
    from_addr, to_addrs (list[str] or comma-separated str).
    Returns (True, None) or (False, "error message").
    """
    try:
        host = (smtp_config.get("host") or "").strip()
        if not host:
            return False, "SMTP host is not configured."
        port = int(smtp_config.get("port") or 587)
        username = smtp_config.get("username") or ""
        password = smtp_config.get("password") or ""
        use_tls = bool(smtp_config.get("use_tls", True))
        from_addr = (smtp_config.get("from_addr") or username or "").strip()
        to_raw = smtp_config.get("to_addrs") or ""
        to_addrs = to_raw if isinstance(to_raw, list) else [a.strip() for a in to_raw.split(",") if a.strip()]

        if not from_addr:
            return False, "A 'from' address is required."
        if not to_addrs:
            return False, "At least one recipient address is required."

        msg = MIMEText(body, "plain", "utf-8")
        msg["Subject"] = subject
        msg["From"] = from_addr
        msg["To"] = ", ".join(to_addrs)

        if port == 465:
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(host, port, timeout=ALERT_REQUEST_TIMEOUT, context=context) as server:
                if username:
                    server.login(username, password)
                server.sendmail(from_addr, to_addrs, msg.as_string())
        else:
            with smtplib.SMTP(host, port, timeout=ALERT_REQUEST_TIMEOUT) as server:
                server.ehlo()
                if use_tls:
                    context = ssl.create_default_context()
                    server.starttls(context=context)
                    server.ehlo()
                if username:
                    server.login(username, password)
                server.sendmail(from_addr, to_addrs, msg.as_string())
        return True, None
    except smtplib.SMTPAuthenticationError as exc:
        return False, f"SMTP authentication failed: {exc}"
    except (smtplib.SMTPException, OSError, TimeoutError) as exc:
        return False, f"Could not send email: {exc}"
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Unexpected error sending email: {exc}"


def send_slack_alert(webhook_url: str, text: str):
    """
    Posts a simple text message to a Slack Incoming Webhook URL.
    Returns (True, None) or (False, "error message").
    """
    webhook_url = (webhook_url or "").strip()
    if not webhook_url:
        return False, "Slack webhook URL is not configured."
    try:
        body = json.dumps({"text": text}).encode("utf-8")
        req = urllib.request.Request(webhook_url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=ALERT_REQUEST_TIMEOUT) as resp:
            resp_body = resp.read().decode("utf-8", errors="replace")
            if resp.status != 200:
                return False, f"Slack returned HTTP {resp.status}: {resp_body}"
        return True, None
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode("utf-8", errors="replace")
        except Exception:
            detail = str(exc)
        return False, f"Slack returned HTTP {exc.code}: {detail}"
    except urllib.error.URLError as exc:
        return False, f"Could not reach Slack: {exc.reason}"
    except Exception as exc:  # pragma: no cover - defensive
        return False, f"Unexpected error sending Slack alert: {exc}"


def build_failure_alert_text(source_label: str, failed_devices: list, report_summary: str = ""):
    """Builds a consistent, human-readable alert body used by both email
    and Slack for 'a run had failures' notifications."""
    lines = [
        f"⚠ Network Automation Console: '{source_label}' completed with failures.",
        "",
        f"Failed device(s): {', '.join(failed_devices) if failed_devices else '(see report)'}",
    ]
    if report_summary:
        lines.append("")
        lines.append(report_summary)
    return "\n".join(lines)


def build_health_regression_alert_text(host: str, port: int, issues: list):
    lines = [
        f"⚠ Network Automation Console: health check regression detected on {host}:{port} after a configuration change.",
        "",
    ]
    lines.extend(f"- {issue}" for issue in issues)
    lines.append("")
    lines.append("Consider reviewing the change and rolling back if needed.")
    return "\n".join(lines)
