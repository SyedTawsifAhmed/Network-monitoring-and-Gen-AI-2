from netmiko import ConnectHandler


def build_netmiko_device(device_data):
    return {
        "device_type": device_data["device_type"],
        "host": device_data["ip"],
        "username": device_data["username"],
        "password": device_data["password"],
    }


def collect_device_data(device_data, config_cmd, logs_cmd):
    device = build_netmiko_device(device_data)

    with ConnectHandler(**device) as conn:
        prompt = conn.find_prompt()
        running_config = conn.send_command(config_cmd)
        logs = conn.send_command(logs_cmd)

    return {
        "hostname": device_data["hostname"],
        "role": device_data.get("role", "unknown"),
        "platform": device_data.get(
            "platform",
            device_data.get("device_type", "unknown"),
        ),
        "prompt": prompt,
        "running_config": running_config,
        "logs": logs,
    }
