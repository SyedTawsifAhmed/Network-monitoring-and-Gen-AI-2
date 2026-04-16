import os
from typing import List, Literal
from pydantic import BaseModel, Field
from google import genai
from google.genai import types


class ChangeSummary(BaseModel):
    headline: str = Field(description="Short alert title for the configuration change")
    plain_summary: str = Field(description="Plain-language summary for a technical or informed non-technical manager")
    technical_summary: str = Field(description="Short technical summary for engineering audiences")
    potential_impact: str = Field(description="Likely operational impact, or state clearly if impact is uncertain")
    recommended_action: str = Field(description="Suggested next step or review action")
    risk_level: Literal["Low", "Medium", "High"] = Field(description="Overall risk rating")
    changed_areas: List[str] = Field(description="Short list of affected config domains such as OSPF, interfaces, SNMP")
    anomalies: List[str] = Field(description="Short list of anomalies or unusual observations, empty if none")


def get_gemini_client(api_env_var):
    api_key = os.getenv(api_env_var)
    if not api_key:
        raise ValueError(f"Missing required environment variable: {api_env_var}")
    return genai.Client(api_key=api_key)


def build_prompt(payload):
    return f"""
You are a network configuration analysis assistant.

Analyze the following Cisco network configuration change.

Return a structured JSON response that matches the provided schema.

Rules:
- Write for infrastructure change notification use.
- Keep plain_summary understandable to a technical manager or informed non-technical manager.
- Keep technical_summary concise and technical.
- Use only the supplied diff and logs.
- Do not invent facts.
- If impact is uncertain, say so clearly.
- changed_areas should contain only short labels.
- anomalies should contain only short observations and may be empty.

Device: {payload["device_name"]}
Role: {payload["device_role"]}

Topology Context:
{payload["topology_context"]}

Old Config Context:
{payload["old_config"]}

Configuration Diff:
{payload["diff"]}

Recent Device Logs:
{payload["logs"]}
""".strip()


def analyze_change(settings, payload):
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
            max_output_tokens=700,
            response_mime_type="application/json",
            response_json_schema=ChangeSummary.model_json_schema(),
        ),
    )

    return ChangeSummary.model_validate_json(response.text)