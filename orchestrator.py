#!/usr/bin/env python3
"""Orchestrator: run poller, rule engine, local AI, and scoring for changed devices.

Usage: python orchestrator.py [--dry-run] [--device DEVICE]

This script invokes existing project scripts without modifying them.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from pathlib import Path
from typing import List, Optional

from src.notifier import send_combined_email_notifications
from src.utils import load_yaml, load_json, read_text, write_json


def run_git_show(path: Path) -> Optional[str]:
    """Return the file contents from HEAD~1 for the given repo-relative path, or None."""
    try:
        result = subprocess.run(
            ["git", "show", "HEAD~1:" + str(path)],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode == 0:
            return result.stdout
    except Exception:
        pass
    return None


def run_cmd(cmd: List[str], allow_failure: bool = False) -> int:
    print(f"Running: {' '.join(cmd)}")
    result = subprocess.run(cmd, check=False)
    if result.returncode != 0 and not allow_failure:
        raise subprocess.CalledProcessError(result.returncode, cmd)
    return result.returncode


def persist_metrics(metrics: dict, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    metrics_path = output_dir / f"orchestrator_metrics_{timestamp}.json"
    metrics_path.write_text(json.dumps(metrics, indent=2), encoding="utf-8")
    return metrics_path


def load_existing_metrics(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def parse_args():
    p = argparse.ArgumentParser(description="Orchestrate collection, analysis, and scoring")
    p.add_argument("--dry-run", action="store_true", help="Run poller in dry-run mode")
    p.add_argument("--device", help="Process only a single device name")
    p.add_argument(
        "--force",
        action="store_true",
        help="Force re-run local/cloud/scoring even if outputs already exist.",
    )
    p.add_argument(
        "--ai-mode",
        choices=["cloud", "local"],
        default=None,
        help="Run only the cloud AI path or only the local AI path. Defaults to running both.",
    )
    args = p.parse_args()
    args.ai_mode = args.ai_mode or "both"
    return args


def should_run_output(path: Path, force: bool, source: Optional[Path] = None) -> bool:
    if force or not path.exists():
        return True
    if source and source.exists():
        return path.stat().st_mtime < source.stat().st_mtime
    return False


def find_cloud_summary(device_name: str, cloud_batch: Optional[dict]) -> Optional[dict]:
    if not cloud_batch or not isinstance(cloud_batch, dict):
        return None
    for item in cloud_batch.get("results", []) or []:
        name = item.get("device_name") or item.get("device", {}).get("device_name")
        if name == device_name:
            summary = item.get("summary") or item.get("summary", {})
            if isinstance(summary, dict) and summary:
                return summary
    return None


def select_latest_diffs(diffs: List[Path], device: Optional[str] = None) -> List[Path]:
    latest: dict[str, Path] = {}
    for diff in diffs:
        device_name = diff.stem.split("_")[0]
        if device and device_name != device:
            continue
        current = latest.get(device_name)
        if current is None or diff.stat().st_mtime > current.stat().st_mtime:
            latest[device_name] = diff
    return sorted(latest.values(), key=lambda path: path.name)


def extract_added_removed_from_diff(diff_text: str) -> tuple[str, str]:
    added = []
    removed = []
    for line in diff_text.splitlines():
        if line.startswith("+++") or line.startswith("---") or line.startswith("@@"):
            continue
        if line.startswith("+"):
            added.append(line[1:].rstrip())
        elif line.startswith("-"):
            removed.append(line[1:].rstrip())
    return "\n".join(added).strip(), "\n".join(removed).strip()


def write_text_if_changed(path: Path, content: str) -> None:
    if path.exists():
        existing = path.read_text(encoding="utf-8")
        if existing == content:
            return
    path.write_text(content, encoding="utf-8")


def build_topology_context(device_name: str, topology: dict) -> str:
    device_info = topology.get("devices", {}).get(device_name, {})
    role = device_info.get("role", "unknown")
    neighbors = device_info.get("neighbors", [])

    neighbor_lines = []
    for n in neighbors:
        neighbor_lines.append(f'- {n.get("device")} via {n.get("local_interface")} ({n.get("relationship")})')

    context = f"Device role: {role}\nNeighbors:\n"
    context += "\n".join(neighbor_lines) if neighbor_lines else "- None"
    return context


def main():
    args = parse_args()
    settings = load_yaml("configs/settings.yaml")
    orchestrator_started_at = time.perf_counter()
    telemetry = {
        "ai_mode": args.ai_mode or "both",
        "polling_seconds": None,
        "cloud_seconds": None,
        "local_seconds": None,
        "orchestrator_total_seconds": None,
    }

    # 1) Run the Nornir-based poller (collects configs, writes diffs, and runs cloud AI)
    poller_script = Path("src/poller_nornir.py")
    if not poller_script.exists():
        print("Required Nornir poller not found: src/poller_nornir.py. Aborting.")
        return
    poller_cmd = [sys.executable, str(poller_script)]
    if args.dry_run:
        poller_cmd.append("--dry-run")
    poller_cmd.append("--skip-notifications")
    if args.ai_mode != "both":
        poller_cmd.extend(["--ai-mode", args.ai_mode])

    poller_started_at = time.perf_counter()
    poller_rc = run_cmd(poller_cmd, allow_failure=True)
    if poller_rc != 0:
        print(f"[!] Poller failed with exit code {poller_rc}; skipping cloud results and continuing.")
    telemetry["polling_seconds"] = round(time.perf_counter() - poller_started_at, 3)

    poller_metrics_path = Path("data/telemetry/poller_metrics.json")
    if poller_metrics_path.exists():
        poller_metrics = load_existing_metrics(poller_metrics_path)
        if poller_metrics.get("polling_seconds") is not None:
            telemetry["polling_seconds"] = poller_metrics["polling_seconds"]
        if poller_metrics.get("cloud_seconds") is not None:
            telemetry["cloud_seconds"] = poller_metrics["cloud_seconds"]

    # 2) Locate diff files produced by the poller
    diff_root = Path(settings["storage"]["diff_path"])
    topology = load_json("configs/topology.json")

    # Load hosts roles if available
    try:
        hosts = load_yaml("inventory/hosts.yaml")
    except Exception:
        hosts = {}

    # Load cloud batch output if present
    cloud_batch_path = Path("gemini_batch_output.json")
    cloud_batch = None
    if cloud_batch_path.exists():
        cloud_batch = json.loads(cloud_batch_path.read_text(encoding="utf-8"))

    # Iterate only the latest diff file per device
    diffs = list(diff_root.rglob("*.diff"))
    latest_diffs = select_latest_diffs(diffs, device=args.device)
    if not latest_diffs:
        print("No diff files found; nothing to do.")
        return

    for diff_file in latest_diffs:
        device_name = diff_file.stem.split("_")[0]
        if args.device and device_name != args.device:
            continue

        print(f"\n--- Processing device: {device_name} (diff: {diff_file})")

        diff_text = diff_file.read_text(encoding="utf-8")
        proposed_change, current_config = extract_added_removed_from_diff(diff_text)

        # Prepare file paths for intermediate outputs
        out_dir = Path("data") / "orchestrator" / device_name
        out_dir.mkdir(parents=True, exist_ok=True)
        rule_out = out_dir / f"{device_name}_rule_engine.json"
        local_out = out_dir / f"{device_name}_local_ai.json"
        cloud_out = out_dir / f"{device_name}_cloud_ai.json"
        final_out = out_dir / f"{device_name}_final_score.json"

        # 3) Rule engine: import and run evaluate_change
        try:
            from src.rule_engine_v3 import evaluate_change, save_result_to_json_file

            topology_context = build_topology_context(device_name, topology)
            role = hosts.get(device_name, {}).get("data", {}).get("role") if isinstance(hosts, dict) else None

            # Attempt to retrieve the full previous config as context for the rule engine.
            current_config_dir = Path(settings.get("storage", {}).get("current_config_path", "data/configs/current"))
            current_file = current_config_dir / f"{device_name}.cfg"

            prev_config = run_git_show(current_file)
            if not prev_config:
                # Fallback: try the archive directory and pick the most recent file for the device.
                archive_dir = Path(settings.get("storage", {}).get("archive_config_path", "data/configs/archive")) / device_name
                try:
                    archives = sorted(archive_dir.iterdir(), key=lambda p: p.stat().st_mtime, reverse=True)
                    if archives:
                        prev_config = archives[0].read_text(encoding="utf-8")
                except Exception:
                    prev_config = None

            rule_result = evaluate_change(
                proposed_change=proposed_change or diff_text,
                current_config=prev_config,
                topology_context=topology_context,
                device_role=role,
                proposed_full_config=False,
            )

            save_result_to_json_file(rule_result, str(rule_out))
            print(f"Rule-engine output saved to: {rule_out}")
        except Exception as exc:
            print(f"Rule engine failed for {device_name}: {exc}")
            continue

        should_run_cloud = args.ai_mode in {"both", "cloud"}
        should_run_local = args.ai_mode in {"both", "local"}

        # 4) Cloud AI: extract single-device summary from gemini batch output if available
        if should_run_cloud:
            cloud_summary = find_cloud_summary(device_name, cloud_batch)
            if cloud_summary is not None and should_run_output(cloud_out, args.force, source=diff_file):
                try:
                    cloud_out.write_text(json.dumps(cloud_summary, indent=2), encoding="utf-8")
                    print(f"Cloud AI output extracted to: {cloud_out}")
                except Exception as exc:
                    print(f"Failed to write cloud AI output for {device_name}: {exc}")
            elif cloud_summary is None:
                if cloud_batch_path.exists():
                    print(f"Cloud batch exists but no entry for {device_name} was found.")
                else:
                    print("No cloud batch output found (gemini_batch_output.json).")
            else:
                print(f"Skipping cloud extraction for {device_name}; {cloud_out} is up to date.")
        else:
            print(f"AI mode '{args.ai_mode}' skips cloud AI for {device_name}.")

        # 5) Local AI + Scoring: skip during dry-run to avoid heavy model loads
        if args.dry_run:
            print(f"Dry-run: skipping local AI and scoring for {device_name}.")
            continue

        if not should_run_local:
            print(f"AI mode '{args.ai_mode}' skips local AI for {device_name}; skipping scoring.")
            continue

        # 5a) Local AI only if needed
        cfg_path = out_dir / f"{device_name}_proposed.cfg"
        proposed_text = proposed_change or diff_text
        write_text_if_changed(cfg_path, proposed_text)

        if should_run_output(local_out, args.force, source=cfg_path):
            try:
                local_started_at = time.perf_counter()
                local_cmd = [
                    sys.executable,
                    "risk_qwen_v2.py",
                    "--config-file",
                    str(cfg_path),
                    "--output-file",
                    str(local_out),
                ]
                run_cmd(local_cmd)
                elapsed = round(time.perf_counter() - local_started_at, 3)
                current_local = telemetry.get("local_seconds") or 0.0
                telemetry["local_seconds"] = round(current_local + elapsed, 3)
                print(f"Local AI output saved to: {local_out} in {elapsed}s")
            except Exception as exc:
                print(f"Local AI failed for {device_name}: {exc}")
        else:
            print(f"Skipping local AI for {device_name}; {local_out} is up to date.")

        # 5b) Scoring only if local and rule results exist
        if not should_run_output(final_out, args.force, source=diff_file):
            print(f"Skipping scoring for {device_name}; {final_out} already exists and is up to date.")
            continue

        if not local_out.exists():
            print(f"Skipping scoring for {device_name}; local AI result missing.")
            continue

        if not rule_out.exists():
            print(f"Skipping scoring for {device_name}; rule engine result missing.")
            continue

        if not cloud_out.exists() and not args.force and should_run_cloud:
            print(f"Skipping scoring for {device_name}; cloud output missing and force not set.")
            continue

        try:
            scoring_cmd = [
                sys.executable,
                "scoring_engine.py",
                "--cloud",
                str(cloud_out) if cloud_out.exists() else str(cloud_batch_path),
                "--local",
                str(local_out),
                "--rules",
                str(rule_out),
                "--output",
                str(final_out),
            ]

            run_cmd(scoring_cmd)
            print(f"Final score output saved to: {final_out}")
        except Exception as exc:
            print(f"Scoring engine failed for {device_name}: {exc}")
            continue

        # 6) Email notification: use the combined summary from scoring output
        try:
            notification_data = json.loads(final_out.read_text(encoding="utf-8"))
            notification = notification_data.get("notification")
            if notification:
                subject = notification.get("title", f"Network change decision for {device_name}")
                body = notification.get("message", "No notification body available.")
                event = {
                    "device_name": device_name,
                    "device_role": hosts.get(device_name, {}).get("data", {}).get("role", "unknown"),
                    "platform": topology.get("devices", {}).get(device_name, {}).get("platform", "unknown"),
                    "timestamp": notification_data.get("generated_at", "unknown"),
                    "diff_file": str(diff_file),
                    "archive_file": "",
                }
                sent = send_combined_email_notifications(settings, event, subject, body)
                if sent:
                    print(f"Combined email notification sent for {device_name}")
                else:
                    print(f"Email notifications disabled or no recipients configured for {device_name}")
            else:
                print(f"No notification payload in final score output for {device_name}")
        except Exception as exc:
            print(f"Failed sending combined email notification for {device_name}: {exc}")

    telemetry["orchestrator_total_seconds"] = round(time.perf_counter() - orchestrator_started_at, 3)
    metrics_path = persist_metrics(telemetry, Path("data/telemetry"))
    print(f"Telemetry saved to: {metrics_path}")


if __name__ == "__main__":
    main()
