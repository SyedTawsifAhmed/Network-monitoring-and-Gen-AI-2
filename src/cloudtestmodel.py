from pathlib import Path
import os

from dotenv import load_dotenv

from gen_ai_client import analyze_change
from utils import load_yaml


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
SETTINGS_FILE = PROJECT_ROOT / "configs" / "settings.yaml"

print(f"Project root: {PROJECT_ROOT}")
print(f".env path: {ENV_FILE}")
print(f".env exists: {ENV_FILE.exists()}")

loaded = load_dotenv(
    dotenv_path=ENV_FILE,
    override=True,
)

print(f".env loaded: {loaded}")

api_key = os.getenv("GEMINI_API_KEY")

if api_key:
    print(f"GEMINI_API_KEY found: yes, length={len(api_key)}")
else:
    print("GEMINI_API_KEY found: no")

settings = load_yaml(SETTINGS_FILE)

payload = {
    "device_name": "R1",
    "device_role": "Edge Router",
    "platform": "Cisco IOS-XE",
    "topology_context": """
R1 is connected to the Core Switch via GigabitEthernet0/1.
The interface provides Layer 3 connectivity to the core network.
""",
    "old_config": """
interface GigabitEthernet0/1
 description Connection to Core Switch
 ip address 10.1.1.1 255.255.255.252
 no shutdown
""",
    "diff": """
Current Configuration:

interface GigabitEthernet0/1
 description Connection to Core Switch
 ip address 10.1.1.1 255.255.255.252
 no shutdown

Proposed Change:

interface GigabitEthernet0/1
 shutdown
END
""",
    "logs": """
No recent interface errors or routing events detected.
"""
}

summary = analyze_change(settings, payload)

print(summary.model_dump_json(indent=2))