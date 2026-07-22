from datetime import datetime
import argparse
import json
import subprocess
import time

from utils import load_yaml, load_json, ensure_dir, write_text, read_text
from collector_nornir import collect_device_data_parallel
from gen_ai_client import analyze_changes_batch, chunk_ai_payloads
from notifier import send_role_based_email_notifications
from dotenv import load_dotenv
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = PROJECT_ROOT / ".env"
load_dotenv(ENV_FILE)

SETTINGS_PATH = "configs/settings.yaml"
TOPOLOGY_PATH = "configs/topology.json"

HOSTS_FILE = "inventory/hosts.yaml"
GROUPS_FILE = "inventory/groups.yaml"
DEFAULTS_FILE = "inventory/defaults.yaml"


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


def load_nornir_host_roles(hosts_path):
    hosts_data = load_yaml(hosts_path)
    role_map = {}

    for host_name, host_def in hosts_data.items():
        data = host_def.get("data", {})
        role_map[host_name] = {
            "role": data.get("role", "unknown"),
        }

    return role_map


def persist_poller_metrics(polling_seconds: float) -> Path:
    telemetry_dir = Path("data/telemetry")
    telemetry_dir.mkdir(parents=True, exist_ok=True)
    metrics_path = telemetry_dir / "poller_metrics.json"
    payload = {"polling_seconds": round(polling_seconds, 3)}

    cloud_metrics_path = telemetry_dir / "cloud_ai_metrics.json"
    if cloud_metrics_path.exists():
        try:
            cloud_metrics = json.loads(cloud_metrics_path.read_text(encoding="utf-8"))
            if isinstance(cloud_metrics, dict):
                payload["cloud_seconds"] = cloud_metrics.get("cloud_seconds")
        except Exception:
            pass

    metrics_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return metrics_path


def parse_args():
    parser = argparse.ArgumentParser(description="Poll network devices and optionally analyze config changes.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Collect configs/logs and write files, but skip AI analysis and notifications.",
    )
    parser.add_argument(
        "--skip-notifications",
        action="store_true",
        help="Skip sending email notifications from the poller. Useful when orchestration will send combined notifications later.",
    )
    parser.add_argument(
        "--ai-mode",
        choices=["cloud", "local"],
        default=None,
        help="Run only the cloud AI path or only the local AI path. Defaults to running both.",
    )
    args = parser.parse_args()
    args.ai_mode = args.ai_mode or "both"
    return args


def main():
    args = parse_args()

    settings = load_yaml(SETTINGS_PATH)
    topology = load_json(TOPOLOGY_PATH)
    host_metadata = load_nornir_host_roles(HOSTS_FILE)

    current_config_dir = Path(settings["storage"]["current_config_path"])
    archive_config_dir = Path(settings["storage"]["archive_config_path"])
    diff_dir = Path(settings["storage"]["diff_path"])
    log_dir = Path(settings["storage"]["log_path"])

    ensure_dir(current_config_dir)
    ensure_dir(archive_config_dir)
    ensure_dir(diff_dir)
    ensure_dir(log_dir)

    config_cmd = settings["polling"]["command_config"]
    logs_cmd = settings["polling"]["command_logs"]
    num_workers = settings.get("polling", {}).get("nornir_num_workers", 20)
    max_batch_chars = settings.get("ai", {}).get("max_batch_chars", 250000)

    print(f"[+] Polling {len(host_metadata)} devices with Nornir ({num_workers} workers)...")

    polling_started_at = time.perf_counter()
    all_collected, failures = collect_device_data_parallel(
        config_cmd=config_cmd,
        logs_cmd=logs_cmd,
        hosts_file=HOSTS_FILE,
        groups_file=GROUPS_FILE,
        defaults_file=DEFAULTS_FILE,
        num_workers=num_workers,
    )

    print(f"[+] Collection complete. Successful: {len(all_collected)}, Failed: {len(failures)}")
    polling_elapsed = round(time.perf_counter() - polling_started_at, 3)
    print(f"[+] Polling elapsed: {polling_elapsed}s")

    for device_name, errors in failures.items():
        print(f"[!] Poll failed for {device_name}")
        for err in errors:
            print(f"    - {err}")

    changed_devices = []

    for device_name, collected in all_collected.items():
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

        changed_devices.append({
            "device_name": device_name,
            "role": host_metadata.get(device_name, {}).get("role", collected.get("role", "unknown")),
            "timestamp": timestamp,
            "old_config": old_config,
            "new_config": new_config,
            "logs": logs,
            "diff_text": diff_text,
            "diff_file": diff_file,
            "device_log_file": device_log_file,
        })

    print(f"[+] Changed devices queued: {len(changed_devices)}")

    if args.dry_run:
        print("[+] Dry run enabled. Skipping AI analysis and notifications.")
        return

    if not changed_devices:
        print("[+] No changed devices to analyze.")
        return

    if args.ai_mode == "local":
        print("[+] AI mode 'local' selected. Skipping cloud AI analysis and notifications.")
        persist_poller_metrics(polling_elapsed)
        return

    ai_payloads = []
    changed_device_lookup = {}

    for item in changed_devices:
        device_name = item["device_name"]
        role = item["role"]
        topology_context = build_topology_context(device_name, topology)

        payload = build_ai_payload(
            device_name=device_name,
            device_role=role,
            topology_context=topology_context,
            old_config=item["old_config"],
            diff=item["diff_text"],
            logs=item["logs"]
        )

        ai_payloads.append(payload)
        changed_device_lookup[device_name] = item

    batches = chunk_ai_payloads(ai_payloads, max_chars=max_batch_chars)
    print(f"[+] Sending {len(ai_payloads)} changed devices to AI in {len(batches)} batch(es)...")

    for index, batch in enumerate(batches, start=1):
        print(f"[+] Processing AI batch {index}/{len(batches)} with {len(batch)} device(s)...")
        batch_result = analyze_changes_batch(settings, batch)

        for result in batch_result.results:
            device_name = result.device_name
            summary = result.summary
            item = changed_device_lookup[device_name]

            event = {
                "device_name": device_name,
                "device_role": item["role"],
                "timestamp": item["timestamp"],
                "diff_file": str(item["diff_file"]),
                "log_file": str(item["device_log_file"]),
                "ai_summary_file": "Not saved yet"
            }

            print(f"[!] Change detected for {device_name}")
            print(summary.model_dump_json(indent=2))
            print("-" * 80)

            if args.skip_notifications:
                print(f"[+] Skipping poller notifications for {device_name} because orchestrator will send the final combined notification.")
            else:
                try:
                    sent = send_role_based_email_notifications(settings, event, summary)
                    if sent:
                        print(f"[+] Role-based email notifications sent for {device_name}")
                except Exception as e:
                    print(f"[!] Email notification failed for {device_name}: {e}")


if __name__ == "__main__":
    main()