from __future__ import annotations

import argparse
from pathlib import Path

from nornir import InitNornir
from nornir.core.task import Result, Task
from nornir_netmiko.tasks import netmiko_save_config, netmiko_send_config

REPO_ROOT = Path(__file__).resolve().parents[1]
HOST_FILE = REPO_ROOT / "inventory" / "hosts.yaml"
GROUP_FILE = REPO_ROOT / "inventory" / "groups.yaml"
DEFAULT_WORKERS = 10


def build_nornir(num_workers=DEFAULT_WORKERS):
    return InitNornir(
        runner={
            "plugin": "threaded",
            "options": {"num_workers": num_workers},
        },
        inventory={
            "plugin": "SimpleInventory",
            "options": {
                "host_file": str(HOST_FILE),
                "group_file": str(GROUP_FILE),
            },
        },
    )


def load_config_lines(config_file, config_text):
    if config_file:
        config_path = Path(config_file)
        if not config_path.exists():
            raise FileNotFoundError(f"Config file not found: {config_file}")
        content = config_path.read_text(encoding="utf-8")
    elif config_text is not None:
        content = config_text
    else:
        raise ValueError("Provide either --config-file or --config-text")

    return [line.rstrip() for line in content.splitlines() if line.strip()]


def push_config(task, config_lines, dry_run=False):
    lines = list(config_lines)
    if dry_run:
        return Result(
            host=task.host,
            result=f"[DRY RUN] Would push {len(lines)} config line(s) to {task.host.name}",
        )

    send_result = task.run(
        task=netmiko_send_config,
        config_commands=lines,
        enable=True,
        cmd_verify=False,
    )
    save_result = task.run(task=netmiko_save_config)

    output = f"Pushed {len(lines)} line(s) to {task.host.name}\n"
    output += f"{send_result.result}\n{save_result.result}".strip()
    return Result(host=task.host, result=output)


def main():
    parser = argparse.ArgumentParser(description="Push config to Cisco IOS-XE routers via Nornir + Netmiko")
    parser.add_argument("--config-file", help="Path to a text file containing the Cisco IOS config to apply")
    parser.add_argument("--config-text", help="Inline Cisco IOS config text to apply")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be pushed without applying it")
    parser.add_argument("--workers", type=int, default=DEFAULT_WORKERS, help="Number of worker threads")
    args = parser.parse_args()

    if not args.config_file and not args.config_text:
        parser.error("Provide either --config-file or --config-text")

    config_lines = load_config_lines(config_file=args.config_file, config_text=args.config_text)
    if not config_lines:
        raise ValueError("Configuration is empty")

    nr = build_nornir(num_workers=args.workers)
    results = nr.run(task=push_config, config_lines=config_lines, dry_run=args.dry_run)

    print(f"Processed {len(results)} device(s)")
    for host_name, host_result in results.items():
        if host_result.failed:
            print(f"[-] {host_name}: {host_result.exception}")
        else:
            print(f"[+] {host_name}")
            print(host_result.result)

    return 0 if not any(result.failed for result in results.values()) else 1


if __name__ == "__main__":
    main()

