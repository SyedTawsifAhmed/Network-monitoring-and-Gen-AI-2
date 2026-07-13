import json
import os
from pathlib import Path
from typing import List, Literal, Optional
from google import genai
from google.genai import types
from pydantic import BaseModel, Field


# -------------------------------------------------------------------
# Structured Gemini response model
# -------------------------------------------------------------------

class ChangeSummary(BaseModel):
    """
    Defines the exact JSON structure Gemini must return.

    Pydantic validates the response to ensure required fields are
    present and values such as risk scores remain within valid ranges.
    """

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
        description=(
            "Cloud model's recommended action before ensemble scoring"
        )
    )

    risk_reason: str = Field(
        description=(
            "Reason why this risk level and risk score were selected"
        )
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


# -------------------------------------------------------------------
# Gemini client creation
# -------------------------------------------------------------------

def get_gemini_client(api_env_var: str) -> genai.Client:
    """
    Create and return a Gemini API client.

    The API key is loaded from the environment variable identified by
    api_env_var. A ValueError is raised when the variable is missing.
    """

    api_key = os.getenv(api_env_var)

    if not api_key:
        raise ValueError(
            f"Missing required environment variable: {api_env_var}"
        )

    return genai.Client(api_key=api_key)


# -------------------------------------------------------------------
# Prompt construction
# -------------------------------------------------------------------

def build_prompt(payload: dict) -> str:
    """
    Build the network change analysis prompt sent to Gemini.

    The payload should contain device information, configuration data,
    topology context, and recent device logs.
    """

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
- 0-24 = Low risk, usually safe to approve.
- 25-49 = Low to moderate risk, usually warn.
- 50-74 = Medium risk, usually manual review.
- 75-100 = High risk, usually deny or require strict approval.
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


# -------------------------------------------------------------------
# JSON output handling
# -------------------------------------------------------------------

def save_analysis_result(
    result: ChangeSummary,
    output_file: str = "gemini_output.json",
) -> None:
    """
    Save the validated Gemini analysis result to a formatted JSON file.

    Args:
        result:
            Validated ChangeSummary object returned by Gemini.

        output_file:
            Name or path of the JSON output file. By default, the file
            is saved as gemini_output.json in the current working
            directory.
    """

    output_path = Path(output_file)

    # Create the parent directory when a directory path is provided.
    output_path.parent.mkdir(parents=True, exist_ok=True)

    # Convert the Pydantic object to a dictionary and write formatted JSON.
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(
            result.model_dump(),
            file,
            indent=4,
            ensure_ascii=False,
        )


# -------------------------------------------------------------------
# Gemini change analysis
# -------------------------------------------------------------------

def analyze_change(
    settings: dict,
    payload: dict,
    output_file: Optional[str] = "gemini_output.json",
) -> ChangeSummary:
    """
    Analyze a proposed network configuration change using Gemini.

    The function:
    1. Reads Gemini settings.
    2. Creates the Gemini API client.
    3. Builds the network-change prompt.
    4. Requests structured JSON from Gemini.
    5. Validates the JSON using the ChangeSummary model.
    6. Saves the formatted result to a JSON file.
    7. Returns the validated ChangeSummary object.

    Args:
        settings:
            Application settings containing the Gemini model name,
            environment variable name, and optional temperature.

        payload:
            Network change information, including device details,
            topology context, old configuration, configuration diff,
            and logs.

        output_file:
            JSON file used to save the Gemini result. Set this to None
            when file output is not required.

    Returns:
        A validated ChangeSummary object.

    Raises:
        ValueError:
            If the Gemini API environment variable is missing or Gemini
            returns an empty response.
    """

    model_name = settings["ai"]["model"]
    api_env_var = settings["ai"]["api_env_var"]
    temperature = settings["ai"].get("temperature", 0.2)

    # Create the Gemini API client using the configured environment variable.
    client = get_gemini_client(api_env_var)

    # Build the analysis prompt from the supplied change information.
    prompt = build_prompt(payload)

    # Request structured JSON matching the ChangeSummary schema.
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

    # Ensure Gemini returned usable response text.
    if not response.text:
        raise ValueError("Gemini returned an empty response.")

    # Validate Gemini's JSON response against the Pydantic model.
    result = ChangeSummary.model_validate_json(response.text)

    # Save the validated result as formatted JSON.
    if output_file:
        save_analysis_result(
            result=result,
            output_file=output_file,
        )

    return result
```
