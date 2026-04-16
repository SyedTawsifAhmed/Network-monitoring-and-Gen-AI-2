from datetime import datetime
import subprocess

from utils import load_yaml, load_json, ensure_dir, write_text, read_text
from collector import collect_device_data
from gen_ai_client import analyze_change
from notifier import send_role_based_email_notifications
from dotenv import load_dotenv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
load_dotenv(ENV_FILE)


SETTINGS_PATH = "configs/settings.yaml"
INVENTORY_PATH = "inventory/devices.yaml"
TOPOLOGY_PATH = "configs/topology.json"


def normalize_config(config_text):
    lines = []
    for line in config_text.splitlines():
        stripped = line.rstrip()
        if stripped:
            lines.append(stripped)
    return "\n".join(lines)


def build_topology_context(device_name, topology):
    device_info = topology["devices"].get(device_name, {})
    role = device_info.get("role", "unknown")
    neighbors = device_info.get("neighbors", [])

    neighbor_lines = []
    for n in neighbors:
        neighbor_lines.append(
            f'- {n["device"]} via {n["local_interface"]} ({n["relationship"]})'
        )

    context = f"Device role: {role}\nNeighbors:\n"
    context += "\n".join(neighbor_lines) if neighbor_lines else "- None"
    return context


def run_git_command(args):
    result = subprocess.run(
        ["git"] + args,
        capture_output=True,
        text=True,
        check=True
    )
    return result.stdout.strip()


def git_add_and_commit(file_path, message):
    run_git_command(["add", str(file_path)])
    try:
        run_git_command(["commit", "-m", message])
        return True
    except subprocess.CalledProcessError as e:
        if "nothing to commit" in (e.stderr or "").lower():
            return False
        raise


def git_diff_last_commit(file_path):
    try:
        return run_git_command(["diff", "HEAD~1", "HEAD", "--", str(file_path)])
    except subprocess.CalledProcessError:
        return ""


def build_ai_payload(device_name, device_role, topology_context, old_config, diff, logs):
    return {
        "device_name": device_name,
        "device_role": device_role,
        "topology_context": topology_context,
        "old_config": old_config[:8000] if old_config else "No previous config available.",
        "diff": diff[:8000] if diff else "No diff available.",
        "logs": logs[:3000] if logs else "No logs collected."
    }


def main():
    settings = load_yaml(SETTINGS_PATH)
    inventory = load_yaml(INVENTORY_PATH)
    topology = load_json(TOPOLOGY_PATH)

    current_config_dir = Path(settings["storage"]["current_config_path"])
    archive_config_dir = Path(settings["storage"]["archive_config_path"])
    diff_dir = Path(settings["storage"]["diff_path"])
    log_dir = Path(settings["storage"]["log_path"])

    ensure_dir(current_config_dir)
    ensure_dir(archive_config_dir)
    ensure_dir(diff_dir)
    ensure_dir(log_dir)

    devices = inventory["devices"]
    config_cmd = settings["polling"]["command_config"]
    logs_cmd = settings["polling"]["command_logs"]

    for device_name, device_data in devices.items():
        print(f"[+] Polling {device_name}...")

        collected = collect_device_data(device_data, config_cmd, logs_cmd)
        new_config = normalize_config(collected["running_config"])
        logs = collected["logs"]

        current_file = current_config_dir / f"{device_name}.cfg"
        old_config = read_text(current_file)

        if old_config == new_config:
            print(f"[=] No change detected for {device_name}")
            continue

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_file = archive_config_dir / device_name / f"{device_name}_{timestamp}.cfg"
        diff_file = diff_dir / device_name / f"{device_name}_{timestamp}.diff"
        device_log_file = log_dir / f"{device_name}_{timestamp}.log"

        write_text(current_file, new_config)
        write_text(archive_file, new_config)
        write_text(device_log_file, logs)

        commit_message = f"Update {device_name} config at {timestamp}"
        committed = git_add_and_commit(current_file, commit_message)

        if not committed:
            print(f"[=] Git reports no commit needed for {device_name}")
            continue

        diff_text = git_diff_last_commit(current_file)
        write_text(diff_file, diff_text)

        topology_context = build_topology_context(device_name, topology)
        payload = build_ai_payload(
            device_name=device_name,
            device_role=device_data.get("role", "unknown"),
            topology_context=topology_context,
            old_config=old_config,
            diff=diff_text,
            logs=logs
        )

        summary = analyze_change(settings, payload)

        event = {
            "device_name": device_name,
            "device_role": device_data.get("role", "unknown"),
            "timestamp": timestamp,
            "diff_file": str(diff_file),
            "log_file": str(device_log_file),
            "ai_summary_file": "Not saved yet"
        }

        print(f"[!] Change detected for {device_name}")
        print(summary.model_dump_json(indent=2))
        print("-" * 80)

        try:
            sent = send_role_based_email_notifications(settings, event, summary)
            if sent:
                print(f"[+] Role-based email notifications sent for {device_name}")
        except Exception as e:
            print(f"[!] Email notification failed for {device_name}: {e}")


if __name__ == "__main__":
    main()