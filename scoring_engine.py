"""Combine cloud AI, local AI, and deterministic rule-engine risk outputs.

Usage:
    python scoring_engine.py \
        --cloud gemini_output.json \
        --local risk_assessment_output.json \
        --rules rule_engine_output.json \
        --output final_score_output.json

Optional notification delivery:
    Set NOTIFICATION_WEBHOOK_URL to an HTTP endpoint. The engine always prints
    the notification and sends it to the webhook when the variable is present.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


WEIGHTS = {
    "cloud_ai": 0.25,
    "local_ai": 0.35,
    "rule_engine": 0.40,
}

DESTRUCTIVE_OPERATIONS = {
    "interface_shutdown",
    "routing_protocol_removal",
    "default_route_removal",
    "management_access_removal",
    "acl_permit_any",
    "authentication_disable",
}

DECISION_RANK = {
    "approve": 0,
    "warn": 1,
    "manual_review": 2,
    "deny": 3,
}


@dataclass(frozen=True)
class SourceAssessment:
    name: str
    score: float
    level: str
    decision_hint: str
    reasons: list[str]
    affected_areas: list[str]
    destructive_operations: list[str]
    hard_stop: bool = False


def load_json(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            value = json.load(file)
    except FileNotFoundError as exc:
        raise ValueError(f"Input file not found: {path}") from exc
    except json.JSONDecodeError as exc:
        raise ValueError(f"Invalid JSON in {path}: {exc}") from exc

    if not isinstance(value, dict):
        raise ValueError(f"Expected a JSON object in {path}")
    return value


def clamp_score(value: Any, field_name: str) -> float:
    try:
        score = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be numeric; received {value!r}") from exc
    if not 0 <= score <= 100:
        raise ValueError(f"{field_name} must be between 0 and 100; received {score}")
    return score


def normalize_text(value: Any) -> str:
    return str(value or "").strip().lower().replace("-", "_").replace(" ", "_")


def unique_strings(*collections: Any) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    for collection in collections:
        if not isinstance(collection, list):
            continue
        for item in collection:
            text = str(item).strip()
            key = text.lower()
            if text and key not in seen:
                seen.add(key)
                output.append(text)
    return output


def parse_cloud(data: dict[str, Any]) -> SourceAssessment:
    return SourceAssessment(
        name="cloud_ai",
        score=clamp_score(data.get("risk_score"), "cloud risk_score"),
        level=normalize_text(data.get("risk_level")),
        decision_hint=normalize_text(data.get("decision_recommendation")),
        reasons=unique_strings([data.get("risk_reason")], [data.get("potential_impact")]),
        affected_areas=unique_strings(data.get("changed_areas"), data.get("affected_services")),
        destructive_operations=[],
    )


def parse_local(data: dict[str, Any]) -> SourceAssessment:
    risk = data.get("risk") if isinstance(data.get("risk"), dict) else {}
    decision = data.get("decision") if isinstance(data.get("decision"), dict) else {}
    change = data.get("change") if isinstance(data.get("change"), dict) else {}

    destructive = unique_strings(change.get("destructive_operations"))
    return SourceAssessment(
        name="local_ai",
        score=clamp_score(risk.get("score"), "local risk.score"),
        level=normalize_text(risk.get("level")),
        decision_hint=normalize_text(decision.get("recommended_action")),
        reasons=unique_strings([data.get("reason")]),
        affected_areas=unique_strings(change.get("affected_areas")),
        destructive_operations=destructive,
    )


def parse_rules(data: dict[str, Any]) -> SourceAssessment:
    findings = data.get("findings") if isinstance(data.get("findings"), list) else []
    reasons: list[str] = []
    destructive: list[str] = []
    finding_areas: list[str] = []

    for finding in findings:
        if not isinstance(finding, dict):
            continue
        if finding.get("reason"):
            reasons.append(str(finding["reason"]))
        finding_areas.extend(unique_strings(finding.get("affected_areas")))
        rule_id = normalize_text(finding.get("rule_id"))
        if finding.get("hard_stop") or "shutdown" in rule_id or "remove" in rule_id:
            destructive.append(rule_id)

    return SourceAssessment(
        name="rule_engine",
        score=clamp_score(data.get("rule_score"), "rule rule_score"),
        level=normalize_text(data.get("risk_level")),
        decision_hint=normalize_text(data.get("decision_hint")),
        reasons=unique_strings(reasons),
        affected_areas=unique_strings(data.get("affected_areas"), finding_areas),
        destructive_operations=unique_strings(destructive),
        hard_stop=bool(data.get("hard_stop_triggered")),
    )


def risk_level(score: float) -> str:
    if score <= 20:
        return "low"
    if score <= 50:
        return "medium"
    if score <= 80:
        return "high"
    return "critical"


def score_based_decision(score: float) -> str:
    if score <= 20:
        return "approve"
    if score <= 50:
        return "warn"
    if score <= 80:
        return "manual_review"
    return "deny"


def hinted_decision(hint: str) -> str | None:
    hint = normalize_text(hint)
    if any(token in hint for token in ("deny", "reject", "block")):
        return "deny"
    if any(token in hint for token in ("manual_review", "senior_approval", "approval_required")):
        return "manual_review"
    if "warn" in hint:
        return "warn"
    if any(token in hint for token in ("approve", "auto_approval")):
        return "approve"
    return None


def most_restrictive(*decisions: str | None) -> str:
    valid = [decision for decision in decisions if decision in DECISION_RANK]
    return max(valid, key=lambda item: DECISION_RANK[item]) if valid else "manual_review"


def format_summary_list(items: list[str] | None, fallback: str = "None noted") -> str:
    if not items:
        return fallback
    return "; ".join(str(item).strip() for item in items if str(item).strip()) or fallback


def build_notification(result: dict[str, Any]) -> dict[str, Any]:
    level = result["risk_level"].upper()
    decision = result["decision"].replace("_", " ").title()
    title = f"[{level}] Network change decision: {decision}"

    cloud_reasons = format_summary_list(result["source_reasons"].get("cloud_ai", []))
    cloud_areas = format_summary_list(result["source_affected_areas"].get("cloud_ai", []))
    local_reasons = format_summary_list(result["source_reasons"].get("local_ai", []))
    local_areas = format_summary_list(result["source_affected_areas"].get("local_ai", []))
    local_destructive = format_summary_list(result["source_destructive_operations"].get("local_ai", []), fallback="None noted")
    rule_reasons = format_summary_list(result["source_reasons"].get("rule_engine", []))
    rule_areas = format_summary_list(result["source_affected_areas"].get("rule_engine", []))

    body_lines = [
        f"Final risk score: {result['final_score']}/100.",
        f"Overall decision: {decision}.",
        "",
        "Cloud AI summary:",
        f"  - Score: {result['source_scores']['cloud_ai']}",
        f"  - Risk level: {result['source_levels']['cloud_ai'] or 'unknown'}",
        f"  - Recommendation: {result['source_decision_hints']['cloud_ai'] or 'unknown'}",
        f"  - Key findings: {cloud_reasons}",
        f"  - Changed or affected areas: {cloud_areas}",
        "",
        "Local AI summary:",
        f"  - Score: {result['source_scores']['local_ai']}",
        f"  - Risk level: {result['source_levels']['local_ai'] or 'unknown'}",
        f"  - Recommendation: {result['source_decision_hints']['local_ai'] or 'unknown'}",
        f"  - Key findings: {local_reasons}",
        f"  - Changed or affected areas: {local_areas}",
        f"  - Destructive operations: {local_destructive}",
        "",
        "Rule-engine summary:",
        f"  - Score: {result['source_scores']['rule_engine']}",
        f"  - Risk level: {result['source_levels']['rule_engine'] or 'unknown'}",
        f"  - Decision hint: {result['source_decision_hints']['rule_engine'] or 'none'}",
        f"  - Findings: {rule_reasons}",
        f"  - Affected areas: {rule_areas}",
        "",
        f"Aggregate affected areas: {format_summary_list(result['affected_areas'], fallback='None noted')}",
        f"Supporting reasons: {format_summary_list(result['supporting_reasons'], fallback='No supporting reasons captured')}",
    ]

    if result.get("hard_stop_triggered"):
        body_lines.append("Hard stop condition triggered by the rule engine.")

    if result.get("destructive_operations"):
        body_lines.append(
            f"Destructive operations detected: {format_summary_list(result['destructive_operations'], fallback='None noted')}"
        )

    body_lines.append("")
    body_lines.append(
        "Notification generated from existing cloud, local, and rule-engine outputs. "
        "No additional cloud model call was made to assemble this summary."
    )

    body = "\n".join(body_lines)
    return {
        "severity": result["risk_level"],
        "title": title,
        "message": body,
        "requires_acknowledgement": result["decision"] in {"manual_review", "deny"},
    }


def send_notification(notification: dict[str, Any]) -> dict[str, Any]:
    print(json.dumps(notification, indent=2))
    webhook_url = os.getenv("NOTIFICATION_WEBHOOK_URL")
    if not webhook_url:
        return {"channel": "console", "status": "printed"}

    request = Request(
        webhook_url,
        data=json.dumps(notification).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=10) as response:
            return {"channel": "webhook", "status": "sent", "http_status": response.status}
    except HTTPError as exc:
        return {"channel": "webhook", "status": "failed", "error": f"HTTP {exc.code}"}
    except URLError as exc:
        return {"channel": "webhook", "status": "failed", "error": str(exc.reason)}


def evaluate(cloud: SourceAssessment, local: SourceAssessment, rules: SourceAssessment) -> dict[str, Any]:
    assessments = {item.name: item for item in (cloud, local, rules)}
    weighted_score = sum(assessments[name].score * weight for name, weight in WEIGHTS.items())

    overrides: list[str] = []
    final_score = weighted_score

    # Deterministic findings are a safety floor; they cannot be averaged below their score.
    if rules.score > final_score:
        final_score = rules.score
        overrides.append("rule_engine_safety_floor")

    all_destructive = unique_strings(
        cloud.destructive_operations,
        local.destructive_operations,
        rules.destructive_operations,
    )
    normalized_destructive = {normalize_text(item) for item in all_destructive}
    known_destructive = bool(normalized_destructive & DESTRUCTIVE_OPERATIONS) or bool(all_destructive)

    if rules.hard_stop:
        final_score = 100.0
        overrides.append("hard_stop_triggered")
    elif known_destructive and max(cloud.score, local.score, rules.score) >= 81:
        final_score = max(final_score, 81.0)
        overrides.append("critical_destructive_change_floor")

    final_score = round(min(100.0, max(0.0, final_score)), 1)
    level = risk_level(final_score)

    base_decision = score_based_decision(final_score)
    source_decisions = [hinted_decision(item.decision_hint) for item in assessments.values()]
    decision = most_restrictive(base_decision, *source_decisions)

    if rules.hard_stop:
        decision = "deny"
    elif known_destructive and level == "critical":
        decision = "deny"
    elif known_destructive and DECISION_RANK[decision] < DECISION_RANK["manual_review"]:
        decision = "manual_review"

    affected_areas = unique_strings(*(item.affected_areas for item in assessments.values()))
    reasons = unique_strings(*(item.reasons for item in assessments.values()))

    if rules.hard_stop:
        decision_reason = "A deterministic hard-stop rule was triggered."
    elif known_destructive and level == "critical":
        decision_reason = "A destructive operation was identified and the combined assessment reached critical risk."
    elif decision == "manual_review":
        decision_reason = "The change has material or unclear service impact and requires operator approval."
    elif decision == "warn":
        decision_reason = "The change is not blocked, but its potential impact should be acknowledged."
    else:
        decision_reason = "The change is routine and remained within the low-risk threshold."

    result: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "final_score": final_score,
        "risk_level": level,
        "decision": decision,
        "decision_reason": decision_reason,
        "weighted_score_before_overrides": round(weighted_score, 1),
        "weights": WEIGHTS,
        "source_scores": {name: assessment.score for name, assessment in assessments.items()},
        "source_levels": {name: assessment.level for name, assessment in assessments.items()},
        "source_decision_hints": {name: assessment.decision_hint for name, assessment in assessments.items()},
        "source_reasons": {name: assessment.reasons for name, assessment in assessments.items()},
        "source_affected_areas": {name: assessment.affected_areas for name, assessment in assessments.items()},
        "source_destructive_operations": {name: assessment.destructive_operations for name, assessment in assessments.items()},
        "overrides_applied": overrides,
        "hard_stop_triggered": rules.hard_stop,
        "destructive_operations": all_destructive,
        "affected_areas": affected_areas,
        "supporting_reasons": reasons,
    }
    result["notification"] = build_notification(result)
    return result


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cloud", type=Path, default=None, help="Cloud AI JSON output")
    parser.add_argument("--local", type=Path, default=None, help="Local AI JSON output")
    parser.add_argument("--rules", type=Path, required=True, help="Rule-engine JSON output")
    parser.add_argument("--output", type=Path, default=Path("final_score_output.json"))
    parser.add_argument("--no-notify", action="store_true", help="Do not print or send a notification")
    return parser.parse_args()


def main() -> int:
    args = parse_arguments()
    try:
        cloud_input = load_json(args.cloud) if args.cloud else None
        local_input = load_json(args.local) if args.local else None
        rules_input = load_json(args.rules)

        cloud_assessment = parse_cloud(cloud_input) if cloud_input else None
        local_assessment = parse_local(local_input) if local_input else None
        rules_assessment = parse_rules(rules_input)

        if cloud_assessment is None and local_assessment is None:
            raise ValueError("At least one of --cloud or --local must be provided")

        result = evaluate(
            cloud_assessment or SourceAssessment(
                name="cloud_ai",
                score=0.0,
                level="low",
                decision_hint="approve",
                reasons=[],
                affected_areas=[],
                destructive_operations=[],
            ),
            local_assessment or SourceAssessment(
                name="local_ai",
                score=0.0,
                level="low",
                decision_hint="approve",
                reasons=[],
                affected_areas=[],
                destructive_operations=[],
            ),
            rules_assessment,
        )
        if not args.no_notify:
            result["notification_delivery"] = send_notification(result["notification"])
        args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        print(f"Final result written to {args.output}")
        return 0
    except (OSError, ValueError) as exc:
        print(f"Scoring engine error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())