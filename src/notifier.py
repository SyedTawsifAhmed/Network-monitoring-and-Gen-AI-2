import os
import smtplib
import ssl
from email.message import EmailMessage
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
if ENV_FILE.exists():
    load_dotenv(ENV_FILE)


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


def send_combined_email_notifications(settings, event, subject, body):
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

    context = ssl.create_default_context()
    messages = []

    for role, group_cfg in groups.items():
        recipients = group_cfg.get("recipients", [])

        if not recipients:
            continue

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


# ---------------------------------------------------------------------------
# Scored role-based notifications
# ---------------------------------------------------------------------------

def _scored_fmt(items, fallback="None noted"):
    if not items:
        return fallback
    cleaned = [str(i).strip() for i in items if str(i).strip()]
    return ", ".join(cleaned) if cleaned else fallback


def _build_engineer_email_body(device_name, result):
    """Full technical detail - uses the scoring engine's pre-built notification message."""
    notification = result.get("notification", {})
    return notification.get(
        "message",
        f"Risk assessment completed for {device_name}. No detail available.",
    )


def _build_technical_manager_email_body(device_name, result):
    """Explanatory body for technical managers — all details included, written to be
    understood rather than parsed. No information is invented; everything here comes
    directly from the scoring engine result dict."""
    risk_level = result.get("risk_level", "unknown")
    final_score = result.get("final_score", "N/A")
    decision = result.get("decision", "unknown")
    decision_reason = result.get("decision_reason", "Not provided.")
    affected_areas = [a for a in result.get("affected_areas", []) if a.lower() != "none"]
    destructive = result.get("destructive_operations", [])
    hard_stop = result.get("hard_stop_triggered", False)
    src_scores = result.get("source_scores", {})
    src_levels = result.get("source_levels", {})
    src_reasons = result.get("source_reasons", {})
    overrides = result.get("overrides_applied", [])

    decision_label = {
        "deny": "blocked from proceeding",
        "manual_review": "flagged for manual review",
        "warn": "approved with a caution flag",
        "approve": "approved",
    }.get(decision, decision.replace("_", " "))

    # --- Opening ---
    lines = [
        f"Configuration Change Assessment — {device_name}",
        "",
        f"A configuration change on {device_name} was assessed by three independent systems: "
        f"a rule-based engine, a local AI model, and a cloud AI model. The combined result "
        f"rated this change as {risk_level} risk with a final score of {final_score}/100.",
        "",
        f"This change has been {decision_label}.",
        f"Reason: {decision_reason}",
    ]

    # --- Hard stop ---
    if hard_stop:
        lines += [
            "",
            "A hard stop was triggered by a deterministic safety rule, which automatically blocked "
            "this change. Hard stops indicate a condition that policy does not permit to proceed "
            "under any circumstances without senior engineer sign-off.",
        ]

    # --- Affected areas / destructive ops ---
    areas_str = ", ".join(affected_areas) if affected_areas else None
    if destructive:
        dest_str = ", ".join(destructive)
        lines += [
            "",
            f"Areas of the device configuration affected: {areas_str or 'none identified'}.",
            f"Potentially destructive operations detected: {dest_str}. These are changes that "
            "could remove or disable active network functions and warrant close attention.",
        ]
    elif areas_str:
        lines += [
            "",
            f"Areas of the device configuration affected: {areas_str}. "
            "No destructive operations (such as interface shutdowns or route deletions) were detected.",
        ]
    else:
        lines += ["", "No specific affected areas or destructive operations were identified."]

    # --- Per-source breakdown ---
    source_meta = {
        "rule_engine": ("Rule engine",  "enforces deterministic safety policies against known-bad patterns"),
        "local_ai":    ("Local AI",     "analysed the change text directly on this system"),
        "cloud_ai":    ("Cloud AI",     "provided an independent assessment using a larger hosted model"),
    }
    lines += ["", "How the risk score was determined:"]
    for source, (label, description) in source_meta.items():
        score = src_scores.get(source, "N/A")
        level = src_levels.get(source, "unknown")
        reasons = [r.strip() for r in src_reasons.get(source, []) if r.strip()]
        reason_str = " ".join(r if r.endswith(".") else r + "." for r in reasons) if reasons else "No specific findings noted."
        lines.append(f"  {label} — score {score}/100 ({level} risk): {description}. {reason_str}")

    # --- Override explanation ---
    if "rule_engine_safety_floor" in overrides:
        lines += [
            "",
            "Note: The rule engine score was applied as a minimum (safety floor) because it exceeded "
            "the weighted average of all three sources. This safeguard prevents deterministic policy "
            "findings from being diluted by lower AI scores.",
        ]

    # --- Action ---
    action = {
        "deny":          ("This change has been blocked by the automated assessment. The system does not "
                          "roll back changes automatically. If this change needs to be reversed, an engineer "
                          "must run the rollback tool manually. Review the findings above with your team "
                          "before deciding whether to re-apply or roll back."),
        "manual_review": ("Your approval or rejection is required before this change can proceed. "
                          "Review the findings above and confirm with your engineering team. "
                          "Note: rollback is not automatic. If the change needs to be reversed, "
                          "an engineer must run the rollback tool manually."),
        "warn":          ("This change has been allowed to proceed but is flagged for awareness. "
                          "Review the findings when convenient and confirm the outcome is expected with your team."),
        "approve":       "No action is required. The change was within normal risk parameters.",
    }.get(decision, "Review the findings above with your engineering team.")

    lines += ["", "What this means for you:", action]
    return "\n".join(lines)


def _build_executive_email_body(device_name, result):
    """Plain-language body for executives - no scores, no CLI commands, facts from result only."""
    risk_level = result.get("risk_level", "unknown")
    decision = result.get("decision", "unknown")
    decision_reason = result.get("decision_reason", "Not provided.")
    hard_stop = result.get("hard_stop_triggered", False)
    destructive = result.get("destructive_operations", [])

    risk_plain = {
        "critical": "Critical - immediate attention required",
        "high": "High - may affect network services or connectivity",
        "medium": "Medium - warrants review before proceeding",
        "low": "Low - routine change",
    }.get(risk_level, risk_level.title())

    decision_plain = {
        "deny": "Blocked - the change has been prevented from proceeding automatically",
        "manual_review": "Pending review - an engineer must approve before the change can proceed",
        "warn": "Approved with caution - the change can proceed but has been flagged for awareness",
        "approve": "Approved - the change is within normal risk parameters",
    }.get(decision, decision.replace("_", " ").title())

    lines = [
        f"Network Change Notification - {device_name}",
        "",
        "A configuration change was detected on one of your network devices and has been",
        "assessed by the automated monitoring system.",
        "",
        f"Risk level:  {risk_plain}",
        f"Status:      {decision_plain}",
        f"Assessment:  {decision_reason}",
    ]

    if hard_stop or destructive:
        lines += [
            "",
            "This change triggered an automatic block due to its potential network impact.",
            "Your engineering team has been notified and is handling this.",
        ]
    else:
        lines += [
            "",
            "Your engineering team has been notified and is handling next steps.",
        ]

    lines += [
        "",
        "No action is required from you at this time unless your team escalates directly.",
        "For questions, please contact your Network Operations Centre.",
    ]

    return "\n".join(lines)


def send_scored_role_notifications(settings, device_name, result):
    """Send a tailored email to every configured audience group for a device assessment.

    All three groups (engineering, technical_manager, executive) are always notified
    when recipients are configured. Each receives a body appropriate to their level:
      - engineering:        full technical detail from the scoring engine output
      - technical_manager:  decision rationale, affected areas, per-source breakdown
      - executive:          plain-language status, no scores or CLI commands

    Content is derived solely from the scoring engine result dict; no information
    is invented or inferred beyond what the result contains.

    Args:
        settings:    Loaded settings.yaml dict.
        device_name: Name of the device whose change was assessed.
        result:      Final score output dict from the scoring engine.

    Returns True if at least one email was sent, False otherwise.
    """
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
    groups = email_cfg.get("groups", {})

    risk_label = result.get("risk_level", "unknown").upper()
    decision = result.get("decision", "unknown")
    decision_label = decision.replace("_", " ").title()
    subject_prefix = email_cfg.get("subject_prefix", "[NetConfig AI]")
    subject = f"{subject_prefix} [{risk_label}] {decision_label} - {device_name}"

    body_builders = {
        "engineering": _build_engineer_email_body,
        "technical_manager": _build_technical_manager_email_body,
        "executive": _build_executive_email_body,
    }

    messages = []
    for role, builder in body_builders.items():
        group_cfg = groups.get(role, {})
        recipients = group_cfg.get("recipients", [])
        if not recipients:
            continue
        body = builder(device_name, result)
        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg.set_content(body)
        messages.append(msg)

    if not messages:
        return False

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
        server.login(smtp_user, smtp_pass)
        for msg in messages:
            server.send_message(msg)

    return True


# ---------------------------------------------------------------------------
# Combined cycle-end notifications
# ---------------------------------------------------------------------------

def _build_executive_combined_body(device_results):
    """Plain-language cycle summary for executives across all assessed devices.

    Produces a single cohesive narrative covering the overall impact of the
    cycle rather than a per-device breakdown. Scores are included where they
    add useful context. Content is derived solely from the result dicts.
    """
    num = len(device_results)
    device_list = ", ".join(device_results.keys())

    decision_counts = {}
    for result in device_results.values():
        d = result.get("decision", "unknown")
        decision_counts[d] = decision_counts.get(d, 0) + 1

    decision_plain_map = {
        "deny": "Blocked",
        "manual_review": "Pending review",
        "warn": "Approved with caution",
        "approve": "Approved",
    }
    risk_plain_map = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
    }

    device_lines = []
    for device_name, result in device_results.items():
        risk_level = result.get("risk_level", "unknown")
        final_score = result.get("final_score", "N/A")
        decision = result.get("decision", "unknown")
        decision_reason = result.get("decision_reason", "")
        hard_stop = result.get("hard_stop_triggered", False)
        destructive = result.get("destructive_operations", [])

        risk_plain = risk_plain_map.get(risk_level, risk_level.title())
        decision_plain = decision_plain_map.get(decision, decision.replace("_", " ").title())

        line = f"  {device_name} \u2014 {risk_plain} risk ({final_score}/100) \u2014 {decision_plain}"
        if decision_reason:
            line += f"\n      {decision_reason}"
        if hard_stop or destructive:
            line += "\n      [Automatic block applied due to detected network impact]"
        device_lines.append(line)

    status_parts = []
    if decision_counts.get("deny", 0):
        status_parts.append(f"{decision_counts['deny']} blocked")
    if decision_counts.get("manual_review", 0):
        status_parts.append(f"{decision_counts['manual_review']} pending review")
    if decision_counts.get("warn", 0):
        status_parts.append(f"{decision_counts['warn']} approved with caution")
    if decision_counts.get("approve", 0):
        status_parts.append(f"{decision_counts['approve']} approved")
    overall_status = ", ".join(status_parts) if status_parts else "all assessed"

    lines = [
        "Network Configuration Change Summary",
        "",
        f"{num} device(s) were assessed in this monitoring cycle: {device_list}",
        "",
        "Device Status:",
        *device_lines,
        "",
        f"Overall: {overall_status}.",
        "Your engineering team has been notified and is handling next steps.",
        "",
        "No action is required from you unless your team escalates directly.",
        "For questions, contact your Network Operations Centre.",
    ]
    return "\n".join(lines)


def send_combined_role_notifications(settings, device_results):
    """Send one combined email per configured role after a full orchestration cycle.

    Each role receives a single email whose body contains one section per device,
    separated by '=== DEVICE_NAME ===' headers. Body content per device is derived
    solely from the scoring engine result dicts — nothing is invented.

    Args:
        settings:       Loaded settings.yaml dict.
        device_results: Mapping of {device_name: final_score_result_dict} for
                        every device that completed scoring this cycle.

    Returns True if at least one email was sent, False otherwise.
    """
    if not device_results:
        return False

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
    groups = email_cfg.get("groups", {})
    subject_prefix = email_cfg.get("subject_prefix", "[NetConfig AI]")

    num = len(device_results)
    device_list = ", ".join(device_results.keys())
    subject = f"{subject_prefix} Cycle summary: {num} device(s) assessed - {device_list}"

    body_builders = {
        "engineering": _build_engineer_email_body,
        "technical_manager": _build_technical_manager_email_body,
        "executive": _build_executive_email_body,
    }

    messages = []
    for role, builder in body_builders.items():
        group_cfg = groups.get(role, {})
        recipients = group_cfg.get("recipients") or []
        if not recipients:
            continue

        if role == "executive":
            body = _build_executive_combined_body(device_results)
        else:
            sections = [
                f"=== {device_name} ===\n{builder(device_name, result)}"
                for device_name, result in device_results.items()
            ]
            body = "\n\n".join(sections)

        msg = EmailMessage()
        msg["Subject"] = subject
        msg["From"] = sender
        msg["To"] = ", ".join(recipients)
        msg.set_content(body)
        messages.append(msg)

    if not messages:
        return False

    context = ssl.create_default_context()
    with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context) as server:
        server.login(smtp_user, smtp_pass)
        for msg in messages:
            server.send_message(msg)

    return True
