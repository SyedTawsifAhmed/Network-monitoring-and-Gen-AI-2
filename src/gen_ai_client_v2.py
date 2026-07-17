import json
import os
from pathlib import Path
from typing import List, Literal, Optional

from google import genai
from google.genai import types
from pydantic import BaseModel, Field


class ChangeSummary(BaseModel):
    headline: str = Field(
        description="Short alert title for the configuration change"
    )

    executive_summary: str = Field(
        description=(
            "Plain-language summary for a technical manager or "
            "informed non-technical manager"
        )
    )

    technical_summary: str = Field(
        description="Short technical summary for engineering audiences"
    )

    change_type: Literal[
        "Interface Change",
        "Routing Change",
        "VLAN Change",
        "Telemetry Change",
        "Security Change",
        "Multiple Changes",
        "Unknown",
    ] = Field(
        description="Main category of the detected configuration change"
    )

    affected_services: List[str] = Field(
        description=(
            "Services that may be affected, such as routing, telemetry, "
            "management access, or user traffic"
        )
    )

    changed_areas: List[str] = Field(
        description=(
            "Short list of affected configuration domains such as "
            "OSPF, interfaces, VLANs, SNMP, gNMI, or ACLs"
        )
    )

    risk_level: Literal["Low", "Medium", "High"] = Field(
        description="Overall cloud-model risk rating"
    )

    risk_score: int = Field(
        ge=0,
        le=100,
        description=(
            "Cloud-model numeric risk score from 0 to 100, "
            "where 0 is no risk and 100 is critical risk"
        ),
    )

    decision_recommendation: Literal[
        "Approve",
        "Warn",
        "Manual Review",
        "Deny",
    ] = Field(
        description="Cloud model's recommended action before ensemble scoring"
    )

    risk_reason: str = Field(
        description="Reason why this risk level and risk score were selected"
    )

    potential_impact: str = Field(
        description=(
            "Likely operational impact, or a clear statement that "
            "the impact is uncertain"
        )
    )

    validation_checks: List[str] = Field(
        description=(
            "Recommended post-change verification checks or show commands"
        )
    )

    recommended_action: str = Field(
        description="Suggested next step or review action"
    )

    rollback_recommendation: str = Field(
        description=(
            "Rollback guidance if the change causes issues or "
            "validation fails"
        )
    )

    anomalies: List[str] = Field(
        description=(
            "Short list of anomalies or unusual observations, "
            "empty if none"
        )
    )


class DeviceChangeAnalysis(BaseModel):
    device_name: str = Field(description="Device name from the input payload")
    summary: ChangeSummary


class BatchChangeAnalysis(BaseModel):
    results: List[DeviceChangeAnalysis]


def get_gemini_client(api_env_var: str) -> genai.Client:
    api_key = os.getenv(api_env_var)

    if not api_key:
        raise ValueError(
            f"Missing required environment variable: {api_env_var}"
        )

    return genai.Client(api_key=api_key)


def build_prompt(payload: dict) -> str:
    return f"""
You are a Gen-AI assistant for a Network Configuration Management and Reporting System.

Your job is to analyze Cisco/Arista network configuration changes and generate a structured change report.

The system is used for:
- Network configuration monitoring
- Configuration change reporting
- Risk assessment
- Operational impact analysis
- Post-change validation guidance
- Optional remediation or rollback recommendations
- Ensemble risk scoring with a cloud model, local model, and rule engine

Analyze only the supplied configuration diff, old config context, topology context, and device logs.
Do not invent missing facts.
If the operational impact cannot be confirmed, clearly say it is uncertain.

Device Information:
Device Name: {payload["device_name"]}
Device Role: {payload["device_role"]}
Vendor/Platform: {payload.get("platform", "Unknown")}

Topology Context:
{payload["topology_context"]}

Old Configuration Context:
{payload["old_config"]}

Configuration Diff:
{payload["diff"]}

Recent Device Logs:
{payload["logs"]}

Return JSON matching the schema.

Risk scoring rules:
- risk_score must be an integer from 0 to 100.
- Risk scoring:
- 0-20 = low
- 21-50 = medium
- 51-80 = high
- 81-100 = critical
- risk_level must be consistent with risk_score:
  - 0-39 = Low
  - 40-69 = Medium
  - 70-100 = High

Decision recommendation rules:
- Approve: routine or low-risk changes with minimal expected impact.
- Warn: low-to-medium risk changes that should be noted but not blocked.
- Manual Review: unclear impact, routing changes, service-impacting changes, or incomplete evidence.
- Deny: high-risk changes, suspicious changes, management-access risk, major routing disruption risk, or unsafe changes.

Guidelines:
- executive_summary should be understandable to a technical manager.
- technical_summary should be short and suitable for engineers.
- changed_areas should use short labels such as OSPF, Interface, VLAN, SNMP, gNMI, ACL, Routing.
- affected_services should identify services that may be impacted, such as management access, routing reachability, telemetry, or user traffic.
- validation_checks should list commands or checks that should be performed after the change.
- rollback_recommendation should explain whether rollback is needed or only if validation fails.
- anomalies should include unusual observations from the diff or logs, or be empty.
- Do not overstate certainty. If evidence is limited, use Manual Review.
""".strip()


def build_batch_prompt(payloads: List[dict]) -> str:
    serialized = json.dumps(payloads, indent=2)

    return f"""
You are a Gen-AI assistant for a Network Configuration Management and Reporting System.

Your job is to analyze Cisco/Arista network configuration changes and generate a structured change report for each device.

The system is used for:
- Network configuration monitoring
- Configuration change reporting
- Risk assessment
- Operational impact analysis
- Post-change validation guidance
- Optional remediation or rollback recommendations
- Ensemble risk scoring with a cloud model, local model, and rule engine

Analyze only the supplied configuration diff, old config context, topology context, and device logs for each device.
Do not invent missing facts.
If the operational impact cannot be confirmed, clearly say it is uncertain.

Return JSON matching the schema.

Batch rules:
- Return exactly one result for each input device.
- Preserve the exact device_name from the input.
- Each result must be under the summary field for that device.
- Do not omit any device.

Risk scoring rules:
- risk_score must be an integer from 0 to 100.
- Risk scoring:
- 0-20 = low
- 21-50 = medium
- 51-80 = high
- 81-100 = critical
- risk_level must be consistent with risk_score:
  - 0-39 = Low
  - 40-69 = Medium
  - 70-100 = High

Decision recommendation rules:
- Approve: routine or low-risk changes with minimal expected impact.
- Warn: low-to-medium risk changes that should be noted but not blocked.
- Manual Review: unclear impact, routing changes, service-impacting changes, or incomplete evidence.
- Deny: high-risk changes, suspicious changes, management-access risk, major routing disruption risk, or unsafe changes.

Guidelines:
- executive_summary should be understandable to a technical manager.
- technical_summary should be short and suitable for engineers.
- changed_areas should use short labels such as OSPF, Interface, VLAN, SNMP, gNMI, ACL, Routing.
- affected_services should identify services that may be impacted, such as management access, routing reachability, telemetry, or user traffic.
- validation_checks should list commands or checks that should be performed after the change.
- rollback_recommendation should explain whether rollback is needed or only if validation fails.
- anomalies should include unusual observations from the diff or logs, or be empty.
- Do not overstate certainty. If evidence is limited, use Manual Review.

Input device changes:
{serialized}
""".strip()


def save_analysis_result(
    result: ChangeSummary,
    output_file: str = "gemini_output.json",
) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            result.model_dump(),
            file,
            indent=4,
            ensure_ascii=False,
        )


def save_batch_analysis_result(
    result: BatchChangeAnalysis,
    output_file: str = "gemini_batch_output.json",
) -> None:
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            result.model_dump(),
            file,
            indent=4,
            ensure_ascii=False,
        )


def analyze_change(
    settings: dict,
    payload: dict,
    output_file: Optional[str] = "gemini_output.json",
) -> ChangeSummary:
    model_name = settings["ai"]["model"]
    api_env_var = settings["ai"]["api_env_var"]
    temperature = settings["ai"].get("temperature", 0.2)

    client = get_gemini_client(api_env_var)
    prompt = build_prompt(payload)

    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=temperature,
            max_output_tokens=1000,
            response_mime_type="application/json",
            response_json_schema=ChangeSummary.model_json_schema(),
        ),
    )

    if not response.text:
        raise ValueError("Gemini returned an empty response.")

    result = ChangeSummary.model_validate_json(response.text)

    if output_file:
        save_analysis_result(
            result=result,
            output_file=output_file,
        )

    return result


def analyze_changes_batch(
    settings: dict,
    payloads: List[dict],
    output_file: Optional[str] = "gemini_batch_output.json",
) -> BatchChangeAnalysis:
    model_name = settings["ai"]["model"]
    api_env_var = settings["ai"]["api_env_var"]
    temperature = settings["ai"].get("temperature", 0.2)

    client = get_gemini_client(api_env_var)
    prompt = build_batch_prompt(payloads)

    response = client.models.generate_content(
        model=model_name,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=temperature,
            max_output_tokens=4000,
            response_mime_type="application/json",
            response_json_schema=BatchChangeAnalysis.model_json_schema(),
        ),
    )

    if not response.text:
        raise ValueError("Gemini returned an empty response.")

    result = BatchChangeAnalysis.model_validate_json(response.text)

    if output_file:
        save_batch_analysis_result(
            result=result,
            output_file=output_file,
        )

    return result


def estimate_payload_size(payload: dict) -> int:
    return len(json.dumps(payload, ensure_ascii=False))


def chunk_ai_payloads(
    payloads: List[dict],
    max_chars: int = 250000,
) -> List[List[dict]]:
    batches = []
    current_batch = []
    current_size = 0

    for payload in payloads:
        payload_size = estimate_payload_size(payload)

        if current_batch and current_size + payload_size > max_chars:
            batches.append(current_batch)
            current_batch = [payload]
            current_size = payload_size
        else:
            current_batch.append(payload)
            current_size += payload_size

    if current_batch:
        batches.append(current_batch)

    return batches