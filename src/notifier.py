"""
Notification layer.

- Slack: posts a short status line to an Incoming Webhook at each stage. If no
  webhook is configured it is a safe no-op, so the pipeline always runs.
- Email: produces a reviewable .eml DRAFT in the outbox (never auto-sent). A
  human opens and sends it - the human-in-the-loop rule applied to send actions.
"""

import os
from email.message import EmailMessage

import requests
from . import config


def post_slack(text: str) -> dict:
    """Post a status line to Slack. No-op (skipped) if no webhook is set."""
    if not config.SLACK_WEBHOOK_URL:
        return {"channel": "slack", "ok": False, "skipped": True, "text": text}
    try:
        r = requests.post(config.SLACK_WEBHOOK_URL, json={"text": text}, timeout=8)
        return {"channel": "slack", "ok": r.status_code == 200, "status": r.status_code, "text": text}
    except Exception as e:  # never break the pipeline on a notification failure
        return {"channel": "slack", "ok": False, "error": str(e), "text": text}


def write_email_draft(state: dict) -> dict:
    """Write an .eml incident draft to the outbox for an analyst to review/send."""
    alert = state.get("alert", {})
    aid = alert.get("id", "INCIDENT")
    band = state.get("severity_band", "unknown")
    subject = f"[SOC] {aid} - {alert.get('title', 'incident')} ({band.upper()})"
    body = (
        f"Incident: {aid}\n"
        f"Host: {alert.get('host')}\n"
        f"CVE: {state.get('cve_id')}\n"
        f"CVSS: {state.get('cvss_score')} ({band})   Actively exploited (KEV): {state.get('on_kev')}\n"
        f"Gate decision: {state.get('gate_decision')}   Human: {state.get('human_decision')}\n"
        f"Action taken: {state.get('action_result', {}).get('status')}\n\n"
        f"----- Incident report -----\n{state.get('report', '')}\n"
    )
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.INCIDENT_EMAIL_FROM
    msg["To"] = config.INCIDENT_EMAIL_TO
    msg.set_content(body)

    os.makedirs(config.OUTBOX_DIR, exist_ok=True)
    path = os.path.join(config.OUTBOX_DIR, f"{aid}.eml")
    with open(path, "wb") as f:
        f.write(bytes(msg))
    return {"path": path, "subject": subject, "to": config.INCIDENT_EMAIL_TO, "body": body}
