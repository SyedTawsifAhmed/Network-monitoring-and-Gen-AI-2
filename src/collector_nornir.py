from nornir import InitNornir
from nornir_netmiko.tasks import netmiko_send_command


def init_nornir(
    hosts_file="inventory/hosts.yaml",
    groups_file="inventory/groups.yaml",
    defaults_file="inventory/defaults.yaml",
    num_workers=20,
):
    return InitNornir(
        runner={
            "plugin": "threaded",
            "options": {
                "num_workers": num_workers
            },
        },
        inventory={
            "plugin": "SimpleInventory",
            "options": {
                "host_file": hosts_file,
                "group_file": groups_file,
                "defaults_file": defaults_file,
            },
        },
    )


def collect_commands(task, config_cmd, logs_cmd):
    config_result = task.run(
        task=netmiko_send_command,
        command_string=config_cmd,
        enable=True,
        read_timeout=90,
        name="collect_running_config",
    )

    logs_result = task.run(
        task=netmiko_send_command,
        command_string=logs_cmd,
        enable=True,
        read_timeout=90,
        name="collect_logs",
    )

    return {
        "device_name": task.host.name,
        "role": task.host.get("role", "unknown"),
        "prompt": task.host.name,
        "running_config": config_result.result,
        "logs": logs_result.result,
    }


def collect_device_data_parallel(
    config_cmd,
    logs_cmd,
    hosts_file="inventory/hosts.yaml",
    groups_file="inventory/groups.yaml",
    defaults_file="inventory/defaults.yaml",
    num_workers=20,
):
    nr = init_nornir(
        hosts_file=hosts_file,
        groups_file=groups_file,
        defaults_file=defaults_file,
        num_workers=num_workers,
    )

    results = nr.run(
        task=collect_commands,
        config_cmd=config_cmd,
        logs_cmd=logs_cmd,
        name="collect_device_data",
    )

    collected = {}
    failures = {}

    for host_name, multi_result in results.items():
        if multi_result.failed:
            errors = []
            for item in multi_result:
                if item.failed:
                    errors.append(f"{item.name}: {item.exception or item.result}")
            failures[host_name] = errors
            continue

        payload = multi_result[0].result
        collected[host_name] = payload

    return collected, failures