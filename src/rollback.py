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
        raise FileNotFoundError(
            f"No archive directory found for {device_name}"
        )

    config_files = list(archive_dir.glob(f"{device_name}_*.cfg"))

    if not config_files:
        raise FileNotFoundError(
            f"No archived configurations found for {device_name}"
        )

    cutoff_time = datetime.now() - timedelta(hours=max_age_hours)

    recent_files = [
        f
        for f in config_files
        if f.stat().st_mtime > cutoff_time.timestamp()
    ]

    return sorted(
        recent_files,
        key=lambda x: x.stat().st_mtime,
        reverse=True
    )


def find_latest_archive(device_name, max_age_hours=24):
    recent_files = find_recent_archives(
        device_name,
        max_age_hours=max_age_hours,
    )

    if not recent_files:
        raise ValueError(
            f"No archived configuration found within "
            f"{max_age_hours} hours."
        )

    return recent_files[0]


def list_rollback_candidates(device_name, max_age_hours=24):
    recent_files = find_recent_archives(
        device_name,
        max_age_hours=max_age_hours,
    )

    if not recent_files:
        print(f"No rollback candidates found for {device_name}")
        return

    print(f"\nRollback candidates for {device_name}")
    print("-" * 60)

    for index, config_file in enumerate(recent_files[:10], start=1):
        modified = datetime.fromtimestamp(config_file.stat().st_mtime)

        print(
            f"{index}. {config_file.name}"
            f" ({modified.strftime('%Y-%m-%d %H:%M:%S')})"
        )


def rollback_device(device_data, config_file_path, dry_run=False):

    config_text = read_text(config_file_path)

    if not config_text:
        raise FileNotFoundError(
            f"Unable to read rollback configuration:\n{config_file_path}"
        )

    config_lines = [
        line
        for line in config_text.splitlines()
        if line.strip()
    ]

    if not config_lines:
        raise ValueError("Rollback configuration is empty.")

    if dry_run:
        print("\n========== DRY RUN ==========")
        print(f"Device: {device_data['hostname']}")
        print(f"Configuration: {config_file_path}")
        print(f"Commands to apply: {len(config_lines)}")
        print("=============================\n")
        return "Dry run completed."

    print(f"[+] Connecting to {device_data['hostname']}...")

    device = build_netmiko_device(device_data)

    with ConnectHandler(**device) as conn:

        print("[+] Connection established")

        output = conn.send_config_set(
            config_lines,
            read_timeout=120,
            cmd_verify=False,
        )

        print("[+] Saving configuration...")

        save_output = conn.save_config()

    print(f"[+] Rollback successfully completed for {device_data['hostname']}")

    return f"{output}\n{save_output}"


def main():

    parser = argparse.ArgumentParser(
        description="Rollback a network device using a previously archived configuration."
    )

    parser.add_argument(
        "device_name",
        help="Device name (e.g. R1)"
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available rollback configurations"
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview rollback without applying configuration"
    )

    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Maximum archive age in hours (default: 24)"
    )

    args = parser.parse_args()

    devices = load_inventory_devices()

    if args.device_name not in devices:
        raise ValueError(
            f"{args.device_name} does not exist in the inventory."
        )

    if args.list:
        list_rollback_candidates(
            args.device_name,
            max_age_hours=args.hours,
        )
        return

    target_config = find_latest_archive(
        args.device_name,
        max_age_hours=args.hours,
    )

    rollback_device(
        device_data=devices[args.device_name],
        config_file_path=target_config,
        dry_run=args.dry_run,
    )


if __name__ == "__main__":
    main()
