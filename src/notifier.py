import os
import smtplib
import ssl
from email.message import EmailMessage


def format_list(items, fallback="None noted"):
    if not items:
        return fallback

    return ", ".join(items)


def format_multiline_list(items, fallback="None noted"):
    if not items:
        return fallback

    return "\n".join(f"- {item}" for item in items)


def build_email_body(role, event, summary):
    changed_areas = format_list(
        summary.changed_areas,
        fallback="Not clearly identified",
    )

    affected_services = format_list(
        summary.affected_services,
        fallback="Not clearly identified",
    )

    anomalies = format_list(
        summary.anomalies,
        fallback="None noted",
    )

    validation_checks = format_multiline_list(
        summary.validation_checks,
        fallback="No validation checks provided",
    )

    if role == "executive":
        return f"""
Network configuration change detected

Summary:
{summary.executive_summary}

Potential impact:
{summary.potential_impact}

Risk:
{summary.risk_level} - {summary.risk_reason}

Recommended action:
{summary.recommended_action}

Details:
- Device: {event["device_name"]}
- Role: {event.get("device_role", "unknown")}
- Platform: {event.get("platform", "unknown")}
- Time detected: {event["timestamp"]}
- Change type: {summary.change_type}
- Affected services: {affected_services}
""".strip()

    if role == "technical_manager":
        return f"""
Network configuration change detected

Summary:
{summary.executive_summary}

Technical summary:
{summary.technical_summary}

Potential impact:
{summary.potential_impact}

Risk:
{summary.risk_level} - {summary.risk_reason}

Recommended action:
{summary.recommended_action}

Rollback recommendation:
{summary.rollback_recommendation}

Technical details:
- Device: {event["device_name"]}
- Role: {event.get("device_role", "unknown")}
- Platform: {event.get("platform", "unknown")}
- Time detected: {event["timestamp"]}
- Change type: {summary.change_type}
- Changed areas: {changed_areas}
- Affected services: {affected_services}
- Anomalies: {anomalies}

Validation checks:
{validation_checks}
""".strip()

    return f"""
Network configuration change detected

Summary:
{summary.technical_summary}

Potential impact:
{summary.potential_impact}

Risk:
{summary.risk_level} - {summary.risk_reason}

Recommended action:
{summary.recommended_action}

Rollback recommendation:
{summary.rollback_recommendation}

Technical details:
- Device: {event["device_name"]}
- Role: {event.get("device_role", "unknown")}
- Platform: {event.get("platform", "unknown")}
- Time detected: {event["timestamp"]}
- Change type: {summary.change_type}
- Changed areas: {changed_areas}
- Affected services: {affected_services}
- Anomalies: {anomalies}
- Diff file: {event.get("diff_file", "N/A")}
- Log file: {event.get("log_file", "N/A")}
- AI summary file: {event.get("ai_summary_file", "N/A")}
- Archive file: {event.get("archive_file", "N/A")}

Validation checks:
{validation_checks}
""".strip()


def build_email_subject(settings, event, summary):
    subject_prefix = settings.get(
        "notifications",
        {},
    ).get(
        "email",
        {},
    ).get(
        "subject_prefix",
        "[NetConfig AI]",
    )

    return (
        f"{subject_prefix} {summary.risk_level} risk "
        f"{summary.change_type} on {event['device_name']}"
    )


def send_role_based_email_notifications(settings, event, summary):
    email_cfg = settings.get("notifications", {}).get("email", {})

    if not email_cfg.get("enabled", False):
        return False

    smtp_user_env_var = email_cfg.get(
        "smtp_user_env_var",
        "EMAIL_USERNAME",
    )

    smtp_pass_env_var = email_cfg.get(
        "smtp_pass_env_var",
        "EMAIL_PASSWORD",
    )

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

    with smtplib.SMTP_SSL(
        smtp_host,
        smtp_port,
        context=context,
    ) as server:
        server.login(smtp_user, smtp_pass)

        for msg in messages:
            server.send_message(msg)

    return True
