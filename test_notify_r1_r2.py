"""Quick test: send combined scored role notifications for R1 and R2 using their latest final score JSON."""

import copy
import json
from pathlib import Path
import yaml
from src.notifier import send_combined_role_notifications

SETTINGS_PATH = Path("configs/settings.yaml")
DEVICES = {
    "R1": Path("data/orchestrator/R1/R1_final_score.json"),
    "R2": Path("data/orchestrator/R2/R2_final_score.json"),
}


def main():
    settings = yaml.safe_load(SETTINGS_PATH.read_text(encoding="utf-8"))

    device_results = {}
    for device_name, score_path in DEVICES.items():
        if not score_path.exists():
            print(f"[SKIP] {device_name}: final score file not found at {score_path}")
            continue
        result = json.loads(score_path.read_text(encoding="utf-8"))
        decision = result.get("decision", "unknown")
        risk = result.get("risk_level", "unknown")
        score = result.get("final_score", "N/A")
        print(f"[{device_name}] Risk={risk.upper()}  Score={score}  Decision={decision}")
        device_results[device_name] = result

    if not device_results:
        print("No device results to send.")
        return

    # Only send to technical_manager this run
    exec_settings = copy.deepcopy(settings)
    for role, grp in exec_settings["notifications"]["email"]["groups"].items():
        if role != "technical_manager":
            grp["recipients"] = []

    try:
        sent = send_combined_role_notifications(exec_settings, device_results)
        if sent:
            print(f"\nTechnical manager email sent for: {', '.join(device_results)}")
        else:
            print("\nNo emails sent (notifications disabled or no recipients configured).")
    except Exception as exc:
        print(f"\nERROR: {exc}")


if __name__ == "__main__":
    main()
