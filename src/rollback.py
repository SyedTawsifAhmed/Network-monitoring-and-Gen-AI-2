from datetime import datetime, timedelta
from pathlib import Path
import argparse
import re

from nornir import InitNornir
from nornir.core.exceptions import NornirSubTaskError
from nornir_napalm.plugins.tasks import napalm_configure
from nornir_utils.plugins.functions import print_result

from utils import read_text


ARCHIVE_ROOT = Path("data/configs/archive")
DIFF_ROOT = Path("data/diffs")

HOSTS_FILE = "inventory/hosts.yaml"
GROUPS_FILE = "inventory/groups.yaml"
DEFAULTS_FILE = "inventory/defaults.yaml"

# Lines emitted by 'show running-config' that are not valid config commands.
# IOS 'configure replace' rejects them, causing an immediate auto-revert.
_SHOW_RUN_HEADER_RE = re.compile(
    r"^(Building configuration\.{3}|Current configuration\s*:.*bytes)\s*$",
    re.IGNORECASE,
)


def _strip_show_run_headers(config_text: str) -> str:
    """Remove show-running-config artifact lines before passing to configure replace.

    Archives are saved as raw 'show running-config' output, which begins with:
        Building configuration...
        Current configuration : XXXX bytes

    These are CLI output decorations, not IOS commands.  configure replace
    attempts to execute every line and fails immediately on the first one,
    triggering an automatic revert.  This function strips them.
    """
    cleaned = [
        line for line in config_text.splitlines()
        if not _SHOW_RUN_HEADER_RE.match(line)
    ]
    return "\n".join(cleaned)


def init_nornir(num_workers=10):
    return InitNornir(
        runner={
            "plugin": "threaded",
            "options": {"num_workers": num_workers},
        },
        inventory={
            "plugin": "SimpleInventory",
            "options": {
                "host_file": HOSTS_FILE,
                "group_file": GROUPS_FILE,
                "defaults_file": DEFAULTS_FILE,
            },
        },
    )


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

    cutoff = datetime.now() - timedelta(hours=max_age_hours)

    recent = [
        f for f in config_files
        if f.stat().st_mtime > cutoff.timestamp()
    ]

    return sorted(recent, key=lambda x: x.stat().st_mtime, reverse=True)


def find_previous_archive(device_name, max_age_hours=24):
    """Return the archive snapshot BEFORE the most recent change.

    The poller writes the *new* config to archive on each detected change,
    so recent_files[0] = current state and recent_files[1] = rollback target.
    """
    files = find_recent_archives(device_name, max_age_hours)

    if len(files) < 2:
        raise ValueError(
            f"Need at least 2 archives within {max_age_hours}h to roll back "
            f"{device_name}. Found: {len(files)}."
        )

    return files[1]


def find_latest_diff(device_name):
    """Return the most recent poller-generated diff file, or None."""
    diff_dir = DIFF_ROOT / device_name

    if not diff_dir.exists():
        return None

    diff_files = sorted(
        diff_dir.glob(f"{device_name}_*.diff"),
        key=lambda x: x.stat().st_mtime,
        reverse=True,
    )

    return diff_files[0] if diff_files else None


def list_rollback_candidates(device_name, max_age_hours=24):
    files = find_recent_archives(device_name, max_age_hours)

    if not files:
        print(f"No rollback candidates found for {device_name}")
        return

    print(f"\nRollback candidates for {device_name}")
    print("-" * 60)

    for i, f in enumerate(files[:10], start=1):
        modified = datetime.fromtimestamp(f.stat().st_mtime)
        ts = modified.strftime("%Y-%m-%d %H:%M:%S")

        if i == 1:
            label = "  (current state — not used)"
        elif i == 2:
            label = "  <-- ROLLBACK TARGET"
        else:
            label = ""

        print(f"  {i}. {f.name} ({ts}){label}")


# ---------------------------------------------------------------------------
# Nornir task
# ---------------------------------------------------------------------------

def rollback_task(task, rollback_configs, dry_run):
    """Nornir task: load the rollback config as a NAPALM replace candidate.

    NAPALM dispatches to the correct platform mechanism automatically:
      - Cisco IOS-XE : configure replace (via SCP — requires ip scp server enable)
      - Arista EOS   : configure session commit (For future support)
      - Juniper JunOS: load replace + commit (For future support)

    dry_run=True  → NAPALM loads candidate, computes diff, discards (no commit)
    dry_run=False → NAPALM loads candidate, computes diff, commits
    In both cases the diff text is returned as the task result.
    """
    config_text = rollback_configs[task.host.name]

    task.run(
        task=napalm_configure,
        configuration=config_text,
        replace=True,
        dry_run=dry_run,
        name="napalm_configure_rollback",
    )


# ---------------------------------------------------------------------------
# Orchestration helpers
# ---------------------------------------------------------------------------

def build_rollback_configs(device_names, hours):
    """Pre-flight: resolve the rollback archive for each device.

    Returns:
        rollback_configs: dict[device_name -> (archive_path, config_text)]
        skipped:          dict[device_name -> reason_string]
    """
    rollback_configs = {}
    skipped = {}

    for device_name in device_names:
        try:
            target = find_previous_archive(device_name, hours)
            config_text = read_text(target)
            config_text = _strip_show_run_headers(config_text)

            if not config_text:
                skipped[device_name] = f"Archive is empty: {target}"
                continue

            rollback_configs[device_name] = (target, config_text)

        except (FileNotFoundError, ValueError) as e:
            skipped[device_name] = str(e)

    return rollback_configs, skipped


def _print_detected_change(device_name):
    diff_file = find_latest_diff(device_name)

    if not diff_file:
        print(f"    (no diff file found)")
        return

    diff_text = read_text(diff_file)
    print(f"    Source: {diff_file.name}")
    print("    " + "-" * 56)

    for line in (diff_text or "    (empty diff)").splitlines():
        print(f"    {line}")


def rollback_devices(device_names, dry_run, hours):
    nr = init_nornir()
    all_hosts = list(nr.inventory.hosts.keys())
    targets = device_names if device_names else all_hosts

    unknown = [d for d in targets if d not in all_hosts]
    if unknown:
        raise ValueError(f"Device(s) not found in inventory: {', '.join(unknown)}")

    rollback_configs, skipped = build_rollback_configs(targets, hours)

    for device_name, reason in skipped.items():
        print(f"[!] Skipping {device_name}: {reason}")

    if not rollback_configs:
        print("[!] No devices available for rollback.")
        return {}, skipped

    if dry_run:
        print("\n========== DRY RUN ==========")
        for device_name, (archive_path, _) in rollback_configs.items():
            print(f"\n[{device_name}] Change being reverted (poller diff):")
            _print_detected_change(device_name)
            print(f"\n[{device_name}] Rollback target: {archive_path.name}")
        print("\n[*] Connecting to devices to compute NAPALM diff...\n")

    nr_filtered = nr.filter(
        filter_func=lambda h: h.name in rollback_configs
    )

    run_result = nr_filtered.run(
        task=rollback_task,
        rollback_configs={
            name: cfg for name, (_, cfg) in rollback_configs.items()
        },
        dry_run=dry_run,
        name="rollback",
    )

    successes = {}
    failures = dict(skipped)

    for host_name, multi_result in run_result.items():
        archive_path, _ = rollback_configs[host_name]

        if multi_result.failed:
            # Walk the sub-task results to find the deepest real exception.
            # NornirSubTaskError is just a wrapper — the NAPALM exception is
            # stored in the leaf sub-task result (e.g. napalm_configure_rollback).
            real_err = None
            for item in multi_result:
                if not item.failed or not item.exception:
                    continue
                exc = item.exception
                # Unwrap NornirSubTaskError chain to reach the root cause
                while isinstance(exc, NornirSubTaskError):
                    inner = getattr(exc, "result", None)
                    if inner and getattr(inner, "exception", None):
                        exc = inner.exception
                    else:
                        break
                real_err = exc
            err = real_err or multi_result.exception or multi_result.result
            failures[host_name] = str(err)
            err_msg = str(err)
            print(f"[!] FAILED {host_name}: {type(err).__name__}: {err_msg}")
            if "archive" in err_msg.lower() and "replace" in err_msg.lower():
                print(
                    f"    >>> Device pre-requisite missing on {host_name}.\n"
                    f"    >>> Configure the Cisco archive feature and retry:\n"
                    f"    >>>   archive\n"
                    f"    >>>    path flash:/archive\n"
                    f"    >>>    maximum 14\n"
                    f"    >>> This is required by 'configure replace' on IOS/IOS-XE."
                )
            else:
                print("    --- full task diagnostics ---")
                print_result(multi_result)
            continue

        napalm_diff = ""
        for item in multi_result:
            if item.name == "napalm_configure_rollback":
                napalm_diff = item.result or ""
                break

        successes[host_name] = napalm_diff

        if dry_run:
            print(f"[{host_name}] NAPALM diff (changes that would be applied):")
            if napalm_diff:
                for line in napalm_diff.splitlines():
                    print(f"  {line}")
            else:
                print("  (no diff — running config already matches rollback target)")
        else:
            status = f"→ {archive_path.name}"
            print(f"[+] Rollback completed for {host_name} {status}")
            if napalm_diff:
                print(f"    Applied diff:")
                for line in napalm_diff.splitlines():
                    print(f"      {line}")
            else:
                print(
                    f"    (configure replace applied — NAPALM compare_config "
                    f"returned no diff output, which is normal on some IOS-XE versions)"
                )

    if dry_run:
        print("\n========== END DRY RUN ==========\n")

    return successes, failures


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description=(
            "Manually roll back network devices to the configuration snapshot "
            "before the most recently detected change. Uses NAPALM via Nornir "
            "for vendor-agnostic, non-atomic config replace."
        )
    )

    parser.add_argument(
        "device_name",
        nargs="?",
        help="Target device name (e.g. R1).",
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Roll back all devices in the inventory in parallel.",
    )

    parser.add_argument(
        "--list",
        action="store_true",
        help="List available rollback archives without connecting to devices.",
    )

    parser.add_argument(
        "--dry-run",
        action="store_true",
        help=(
            "Show the detected change (poller diff) and the NAPALM candidate diff "
            "that would be applied, without committing anything."
        ),
    )

    parser.add_argument(
        "--hours",
        type=int,
        default=24,
        help="Maximum archive age in hours to search (default: 24).",
    )

    args = parser.parse_args()

    if not args.device_name and not args.all:
        parser.error("Specify a device name or use --all.")

    if args.device_name and args.all:
        parser.error("Use either a device name or --all, not both.")

    if args.all:
        nr = init_nornir()
        device_names = list(nr.inventory.hosts.keys())
    else:
        device_names = [args.device_name]

    if args.list:
        for device_name in device_names:
            try:
                list_rollback_candidates(device_name, max_age_hours=args.hours)
            except FileNotFoundError as e:
                print(f"[!] {e}")
        return

    rollback_devices(
        device_names=device_names,
        dry_run=args.dry_run,
        hours=args.hours,
    )


if __name__ == "__main__":
    main()
