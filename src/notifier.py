import os
import smtplib
import ssl
from email.message import EmailMessage


def format_changed_areas(summary):
    return ", ".join(summary.changed_areas) if summary.changed_areas else "Not clearly identified"


def format_anomalies(summary):
    return ", ".join(summary.anomalies) if summary.anomalies else "None noted"


def build_email_body(role, event, summary):
    changed_areas = format_changed_areas(summary)
    anomalies = format_anomalies(summary)

    if role == "executive":
        return f"""
Network configuration change detected

Summary:
{summary.plain_summary}

Potential impact:
{summary.potential_impact}

Recommended action:
{summary.recommended_action}

Details:
- Device: {event["device_name"]}
- Role: {event.get("device_role", "unknown")}
- Time detected: {event["timestamp"]}
- Risk level: {summary.risk_level}
""".strip()

    if role == "technical_manager":
        return f"""
Network configuration change detected

Summary:
{summary.plain_summary}

Technical summary:
{summary.technical_summary}

Potential impact:
{summary.potential_impact}

Recommended action:
{summary.recommended_action}

Technical details:
- Device: {event["device_name"]}
- Role: {event.get("device_role", "unknown")}
- Time detected: {event["timestamp"]}
- Risk level: {summary.risk_level}
- Changed areas: {changed_areas}
- Anomalies: {anomalies}
""".strip()

    return f"""
Network configuration change detected

Summary:
{summary.technical_summary}

Potential impact:
{summary.potential_impact}

Recommended action:
{summary.recommended_action}

Technical details:
- Device: {event["device_name"]}
- Role: {event.get("device_role", "unknown")}
- Time detected: {event["timestamp"]}
- Risk level: {summary.risk_level}
- Changed areas: {changed_areas}
- Anomalies: {anomalies}
- Diff file: {event.get("diff_file", "N/A")}
- Log file: {event.get("log_file", "N/A")}
- AI summary file: {event.get("ai_summary_file", "N/A")}
""".strip()


def build_email_subject(settings, event, summary):
    subject_prefix = settings.get("notifications", {}).get("email", {}).get("subject_prefix", "[NetConfig AI]")
    return f"{subject_prefix} {summary.risk_level} risk change on {event['device_name']}"


def send_role_based_email_notifications(settings, event, summary):
    email_cfg = settings.get("notifications", {}).get("email", {})
    if not email_cfg.get("enabled", False):
        return False

    smtp_user_env_var = email_cfg.get("smtp_user_env_var", "EMAIL_USERNAME")
    smtp_pass_env_var = email_cfg.get("smtp_pass_env_var", "EMAIL_PASSWORD")

    smtp_user = os.getenv(smtp_user_env_var)
    smtp_pass = os.getenv(smtp_pass_env_var)

    if not smtp_user or not smtp_pass:
        raise ValueError(
            f"Missing required email environment variables: "
            f"{smtp_user_env_var} and/or {smtp_pass_env_var}"
        )

    smtp_host = email_cfg["smtp_host"]
    smtp_port = int(email_cfg["smtp_port"])
    sender = email_cfg["sender"]
    use_tls = email_cfg.get("use_tls", True)
    use_ssl = email_cfg.get("use_ssl", False)
    groups = email_cfg.get("groups", {})
    subject = build_email_subject(settings, event, summary)
    context = ssl.create_default_context()

    messages = []

    for role, group_cfg in groups.items():
        recipients = group_cfg.get("recipients", [])
        if not recipients:
            continue

        body = build_email_body(role, event, summary)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg.set_content(body)

        messages.append(msg)

    if not messages:
        return False

    if use_ssl:
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
            server.login(smtp_user, smtp_pass)
            for msg in messages:
                server.send_message(msg)
    else:
        with smtplib.SMTP(smtp_host, smtp_port) as server:
            server.ehlo()
            if use_tls:
                server.starttls(context=context)
                server.ehlo()
            server.login(smtp_user, smtp_pass)
            for msg in messages:
                server.send_message(msg)

    return True