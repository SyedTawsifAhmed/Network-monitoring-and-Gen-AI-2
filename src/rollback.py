from datetime import datetime, timedelta
from pathlib import Path
import argparse

from netmiko import ConnectHandler

from utils import load_yaml, read_text


INVENTORY_PATH = "inventory/devices.yaml"
ARCHIVE_ROOT = Path("data/configs/archive")


def build_netmiko_device(device_data):
    return {
        "device_type": device_data["device_type"],
        "host": device_data["ip"],
        "username": device_data["username"],
        "password": device_data["password"],
    }


def load_inventory_devices():
    inventory = load_yaml(INVENTORY_PATH)
    return inventory["devices"]


def find_recent_archives(device_name, max_age_hours=24):
    archive_dir = ARCHIVE_ROOT / device_name
    if not archive_dir.exists():
        raise FileNotFoundError(f"No archive directory found for {device_name}")

    config_files = list(archive_dir.glob(f"{device_name}_*.cfg"))
    if not config_files:
        raise FileNotFoundError(f"No archived configs found for {device_name}")

    cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
    recent_files = [
        f for f in config_files
        if f.stat().st_mtime > cutoff_time.timestamp()
    ]

    return sorted(recent_files, key=lambda x: x.stat().st_mtime, reverse=True)


def find_latest_archive(device_name, max_age_hours=24):
    recent_files = find_recent_archives(device_name, max_age_hours=max_age_hours)
    if not recent_files:
        raise ValueError(
            f"No recent archived configs found for {device_name} "
            f"within the last {max_age_hours} hours"
        )
    return recent_files[0]


def list_rollback_candidates(device_name, max_age_hours=24):
    recent_files = find_recent_archives(device_name, max_age_hours=max_age_hours)

    if not recent_files:
        print(f"No recent archived configs found for {device_name}")
        return

    print(f"Recent rollback candidates for {device_name}:")
    for index, config_file in enumerate(recent_files[:10], start=1):
        modified_time = datetime.fromtimestamp(config_file.stat().st_mtime)
        print(f"{index}. {config_file.name}  ({modified_time})")


def rollback_device(device_data, config_file_path, dry_run=False):
    config_text = read_text(config_file_path)
    if not config_text:
        raise FileNotFoundError(f"Could not read rollback config: {config_file_path}")

    config_lines = [
        line for line in config_text.splitlines()
        if line.strip()
    ]

    if not config_lines:
        raise ValueError(f"Rollback config is empty: {config_file_path}")

    if dry_run:
        print(f"[DRY RUN] Would rollback {device_data['hostname']} using:")
        print(f"[DRY RUN] {config_file_path}")
        print(f"[DRY RUN] Total config lines: {len(config_lines)}")
        return "DRY RUN: rollback skipped"

    device = build_netmiko_device(device_data)

    print(f"[+] Connecting to {device_data['hostname']} ({device_data['ip']})")
    print(f"[+] Applying rollback config: {config_file_path}")

    with ConnectHandler(**device) as conn:
        output = conn.send_config_set(config_lines, read_timeout=120, cmd_verify=False)
        save_output = conn.save_config()

    print(f"[+] Rollback completed for {device_data['hostname']}")
    return f"{output}\n{save_output}"


def main():
    parser = argparse.ArgumentParser(
        description="Rollback a device to a recent archived configuration"
    )
    parser.add_argument("device_name", help="Device name, for example R1")
    parser.add_argument(
        "--list",
        action="store_true",
        help="List recent rollback candidates without applying one",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be rolled back without applying config",
    )
    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Maximum age in hours for rollback candidates (default: 24)",
    )

    args = parser.parse_args()

    devices = load_inventory_devices()

    if args.device_name not in devices:
        raise ValueError(f"Device not found in inventory: {args.device_name}")

    if args.list:
        list_rollback_candidates(args.device_name, max_age_hours=args.hours)
        return

    device_data = devices[args.device_name]
    target_config = find_latest_archive(args.device_name, max_age_hours=args.hours)

    rollback_device(
        device_data=device_data,
        config_file_path=target_config,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()