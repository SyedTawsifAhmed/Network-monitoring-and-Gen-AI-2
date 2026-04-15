import os
from google import genai
from google.genai import types


def get_gemini_client(api_env_var):
    api_key = os.getenv(api_env_var)
    if not api_key:
        raise ValueError(f"Missing required environment variable: {api_env_var}")
    return genai.Client(api_key=api_key)


def build_prompt(payload):
    return f"""
You are a network configuration analysis assistant.

Analyze the following Cisco network configuration change.

Return your response in this format:
1. What changed
2. Potential impact
3. Any anomalies detected
4. Recommended action
5. Risk level (Low/Medium/High)

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
        ),
    )

    return response.text