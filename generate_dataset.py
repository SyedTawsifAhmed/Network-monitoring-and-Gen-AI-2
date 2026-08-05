import json
import random
import csv
import zipfile
from pathlib import Path
from collections import Counter, defaultdict

# ============================================================
# Qwen Cisco IOS Network Configuration Risk Dataset Generator
# ============================================================

RANDOM_SEED = 8861
TOTAL_SAMPLES = 300
OUTPUT_DIR = Path("qwen_network_risk_dataset_300")

random.seed(RANDOM_SEED)

SYSTEM_PROMPT = (
    "You are a network configuration risk analysis assistant. "
    "Analyze the proposed Cisco IOS configuration change using the provided device role, topology context, "
    "and current configuration. Return JSON only with risk_score, risk_level, affected_areas, reason, "
    "and recommended_action."
)

RISK_ACTION = {
    "low": "approve",
    "medium": "warn",
    "medium-high": "manual_review_required",
    "high": "reject_or_senior_approval_required",
}

DEVICE_PROFILES = [
    {
        "device": "R1",
        "role": "core_router",
        "topology": "R1 is a core router connected to R2 and R3. GigabitEthernet{ifnum} is an uplink carrying OSPF area 0.",
    },
    {
        "device": "R2",
        "role": "distribution_router",
        "topology": "R2 aggregates access networks and has OSPF adjacencies to the core. GigabitEthernet{ifnum} connects to an access switch.",
    },
    {
        "device": "R3",
        "role": "edge_router",
        "topology": "R3 connects the internal network to an upstream provider and uses static routing, NAT, and BGP.",
    },
    {
        "device": "SW1",
        "role": "access_switch",
        "topology": "SW1 provides user access ports and trunks VLANs toward the distribution layer.",
    },
    {
        "device": "SW2",
        "role": "distribution_switch",
        "topology": "SW2 carries trunk links between access and distribution layers and provides VLAN segmentation.",
    },
    {
        "device": "FW1",
        "role": "firewall_edge",
        "topology": "FW1 controls traffic between internal and external networks and enforces access-control policy.",
    },
]


def ip(n: int) -> str:
    return f"10.{n % 250}.{(n * 3) % 250}.{(n * 7) % 250}"


def subnet(n: int) -> str:
    return f"10.{n % 250}.{(n * 2) % 250}.0"


def rand_iface() -> str:
    return f"GigabitEthernet{random.randint(0, 3)}/{random.randint(0, 3)}"


def sample_context():
    profile = random.choice(DEVICE_PROFILES)
    ifname = rand_iface()
    ifnum = ifname.split("GigabitEthernet")[-1]
    topology = profile["topology"].format(ifnum=ifnum)
    return profile["device"], profile["role"], topology, ifname


def assistant_output(score, level, areas, reason, action=None) -> str:
    if action is None:
        action = RISK_ACTION[level]

    return json.dumps(
        {
            "risk_score": score,
            "risk_level": level,
            "affected_areas": areas,
            "reason": reason,
            "recommended_action": action,
        },
        separators=(",", ":"),
    )


def make_chat(
    sample_id,
    category,
    level,
    score,
    device,
    role,
    topology,
    current_config,
    proposed_change,
    areas,
    reason,
    action=None,
):
    user = (
        f"Sample ID: {sample_id}\n"
        f"Category: {category}\n"
        f"Device: {device}\n"
        f"Role: {role}\n\n"
        f"Topology Context:\n{topology}\n\n"
        f"Current Configuration:\n{current_config.strip()}\n\n"
        f"Proposed Change:\n{proposed_change.strip()}"
    )

    return {
        "sample_id": sample_id,
        "category": category,
        "risk_level": level,
        "risk_score": score,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": user},
            {"role": "assistant", "content": assistant_output(score, level, areas, reason, action)},
        ],
    }


TEMPLATES = []


def add_template(category, level, score_range, areas, current_fn, proposed_fn, reason_fn, action=None):
    TEMPLATES.append(
        {
            "category": category,
            "level": level,
            "score_range": score_range,
            "areas": areas,
            "current_fn": current_fn,
            "proposed_fn": proposed_fn,
            "reason_fn": reason_fn,
            "action": action,
        }
    )


# ==================
# Low-risk templates
# ==================

add_template(
    "interface_description",
    "low",
    (5, 10),
    ["interface", "documentation"],
    lambda d, r, t, i, n: f"interface {i}\n description Existing link\n ip address {ip(n)} 255.255.255.252\n no shutdown",
    lambda d, r, t, i, n: f"interface {i}\ndescription Link to {random.choice(['R2', 'R3', 'SW1', 'Provider'])}",
    lambda d, r, t, i, n: "Changing an interface description updates documentation only and does not alter forwarding behavior.",
)

add_template(
    "logging_host",
    "low",
    (8, 15),
    ["management", "logging"],
    lambda d, r, t, i, n: "service timestamps log datetime\nlogging buffered 4096",
    lambda d, r, t, i, n: f"logging host 172.16.{random.randint(1, 254)}.{random.randint(1, 254)}",
    lambda d, r, t, i, n: "Adding a syslog host improves observability and should not affect routing or interface forwarding.",
)

add_template(
    "ntp_server",
    "low",
    (10, 20),
    ["management", "ntp"],
    lambda d, r, t, i, n: "clock timezone UTC 0\nntp server 172.16.1.10",
    lambda d, r, t, i, n: f"ntp server 172.16.{random.randint(1, 10)}.{random.randint(10, 250)}",
    lambda d, r, t, i, n: "Adding an NTP server affects time synchronization but does not normally impact packet forwarding.",
)

add_template(
    "banner_change",
    "low",
    (3, 8),
    ["management"],
    lambda d, r, t, i, n: f"hostname {d}",
    lambda d, r, t, i, n: "banner motd #Authorized access only#",
    lambda d, r, t, i, n: "Changing the login banner has no routing or connectivity impact.",
)

add_template(
    "add_loopback_not_advertised",
    "low",
    (10, 20),
    ["interface"],
    lambda d, r, t, i, n: "router ospf 1\n network 10.0.0.0 0.0.0.255 area 0",
    lambda d, r, t, i, n: f"interface Loopback{random.randint(10, 99)}\nip address {ip(n)} 255.255.255.255",
    lambda d, r, t, i, n: "Adding a loopback interface is low risk when it is not automatically advertised into routing.",
)


# =====================
# Medium-risk templates
# =====================

add_template(
    "static_route_add",
    "medium",
    (35, 50),
    ["routing", "static_route"],
    lambda d, r, t, i, n: "ip route 0.0.0.0 0.0.0.0 203.0.113.1",
    lambda d, r, t, i, n: f"ip route {subnet(n)} 255.255.255.0 10.{random.randint(0, 20)}.{random.randint(0, 20)}.1",
    lambda d, r, t, i, n: "Adding a static route changes forwarding for a specific prefix and should be reviewed for next-hop correctness.",
)

add_template(
    "ospf_network_add",
    "medium",
    (40, 55),
    ["ospf", "routing"],
    lambda d, r, t, i, n: "router ospf 1\n router-id 1.1.1.1\n network 10.0.0.0 0.0.0.255 area 0",
    lambda d, r, t, i, n: f"router ospf 1\nnetwork {subnet(n)} 0.0.0.255 area {random.choice([0, 1, 2])}",
    lambda d, r, t, i, n: "Adding an OSPF network can advertise new prefixes or form adjacencies, so it requires routing validation.",
)

add_template(
    "interface_ip_change",
    "medium",
    (45, 58),
    ["interface", "routing", "connectivity"],
    lambda d, r, t, i, n: f"interface {i}\n ip address {ip(n)} 255.255.255.252\n no shutdown",
    lambda d, r, t, i, n: f"interface {i}\nip address {ip(n + 1)} 255.255.255.252",
    lambda d, r, t, i, n: "Changing interface addressing can affect directly connected reachability and routing adjacencies.",
)

add_template(
    "vlan_add",
    "medium",
    (25, 40),
    ["vlan", "switching"],
    lambda d, r, t, i, n: "vlan 10\n name USERS",
    lambda d, r, t, i, n: f"vlan {random.randint(20, 399)}\nname {random.choice(['VOICE', 'GUEST', 'IOT', 'SERVERS'])}",
    lambda d, r, t, i, n: "Adding a VLAN is usually safe but should be checked against the source of truth and trunk policy.",
)

add_template(
    "snmp_community_change",
    "medium",
    (40, 55),
    ["management", "snmp", "security"],
    lambda d, r, t, i, n: "snmp-server community public RO",
    lambda d, r, t, i, n: f"snmp-server community netmon{random.randint(1, 99)} RO",
    lambda d, r, t, i, n: "SNMP community changes affect monitoring access and should be reviewed for security policy compliance.",
)

add_template(
    "bgp_network_add",
    "medium",
    (50, 60),
    ["bgp", "routing"],
    lambda d, r, t, i, n: "router bgp 65001\n neighbor 203.0.113.2 remote-as 65002",
    lambda d, r, t, i, n: f"router bgp 65001\nnetwork {subnet(n)} mask 255.255.255.0",
    lambda d, r, t, i, n: "Adding a BGP network statement can advertise a new prefix to peers and should be validated.",
)

add_template(
    "nat_add",
    "medium",
    (45, 58),
    ["nat", "connectivity"],
    lambda d, r, t, i, n: "interface GigabitEthernet0/0\n ip nat outside\ninterface GigabitEthernet0/1\n ip nat inside",
    lambda d, r, t, i, n: f"ip nat inside source list {random.randint(10, 99)} interface GigabitEthernet0/0 overload",
    lambda d, r, t, i, n: "NAT policy changes can affect internal-to-external reachability and should be reviewed.",
)

add_template(
    "qos_service_policy",
    "medium",
    (40, 55),
    ["qos", "performance"],
    lambda d, r, t, i, n: f"interface {i}\n no shutdown",
    lambda d, r, t, i, n: f"interface {i}\nservice-policy output WAN-QOS",
    lambda d, r, t, i, n: "Applying a QoS service policy can affect traffic treatment and performance under congestion.",
)


# ==========================
# Medium-high risk templates
# ==========================

add_template(
    "ospf_cost_change",
    "medium-high",
    (61, 72),
    ["ospf", "routing", "traffic_engineering"],
    lambda d, r, t, i, n: f"interface {i}\n ip ospf cost 10\n no shutdown",
    lambda d, r, t, i, n: f"interface {i}\nip ospf cost {random.choice([50, 100, 200])}",
    lambda d, r, t, i, n: "Changing OSPF cost may shift traffic to different paths and should be validated against expected routing behavior.",
)

add_template(
    "trunk_allowed_vlan_change",
    "medium-high",
    (63, 75),
    ["vlan", "trunk", "switching"],
    lambda d, r, t, i, n: f"interface {i}\n switchport mode trunk\n switchport trunk allowed vlan 10,20,30",
    lambda d, r, t, i, n: f"interface {i}\nswitchport trunk allowed vlan {random.choice(['10', '10,20', '20,30'])}",
    lambda d, r, t, i, n: "Changing the allowed VLAN list on a trunk can disconnect VLANs across the uplink.",
)

add_template(
    "acl_apply_outbound",
    "medium-high",
    (60, 72),
    ["acl", "interface", "connectivity"],
    lambda d, r, t, i, n: f"interface {i}\n ip address {ip(n)} 255.255.255.252\n no shutdown",
    lambda d, r, t, i, n: f"interface {i}\nip access-group {random.randint(100, 199)} out",
    lambda d, r, t, i, n: "Applying an outbound ACL can block forwarded traffic and should be reviewed before deployment.",
)

add_template(
    "permit_any_any",
    "medium-high",
    (65, 78),
    ["acl", "security"],
    lambda d, r, t, i, n: "ip access-list extended FILTER-IN\n deny ip any 192.0.2.0 0.0.0.255",
    lambda d, r, t, i, n: "ip access-list extended FILTER-IN\npermit ip any any",
    lambda d, r, t, i, n: "A permit any-any ACL rule may violate least-privilege security policy and broaden access unexpectedly.",
)

add_template(
    "vty_access_change",
    "medium-high",
    (65, 78),
    ["management", "ssh", "remote_access"],
    lambda d, r, t, i, n: "line vty 0 4\n transport input ssh",
    lambda d, r, t, i, n: f"line vty 0 4\naccess-class {random.randint(10, 99)} in",
    lambda d, r, t, i, n: "Changing VTY access controls can affect administrative reachability and should be carefully reviewed.",
)

add_template(
    "remove_vlan",
    "medium-high",
    (70, 80),
    ["vlan", "switching", "connectivity"],
    lambda d, r, t, i, n: "vlan 20\n name VOICE\nvlan 30\n name GUEST",
    lambda d, r, t, i, n: f"no vlan {random.choice([20, 30, 40, 100])}",
    lambda d, r, t, i, n: "Removing a VLAN can disconnect endpoints or services assigned to that VLAN.",
)

add_template(
    "passive_interface_change",
    "medium-high",
    (60, 72),
    ["ospf", "adjacency", "routing"],
    lambda d, r, t, i, n: "router ospf 1\n passive-interface default",
    lambda d, r, t, i, n: f"router ospf 1\nno passive-interface {i}",
    lambda d, r, t, i, n: "Changing passive-interface behavior can create or remove OSPF adjacencies.",
)

add_template(
    "bgp_neighbor_add",
    "medium-high",
    (60, 75),
    ["bgp", "routing"],
    lambda d, r, t, i, n: "router bgp 65001\n network 10.0.0.0 mask 255.255.255.0",
    lambda d, r, t, i, n: f"router bgp 65001\nneighbor 203.0.113.{random.randint(2, 250)} remote-as {random.randint(65002, 65100)}",
    lambda d, r, t, i, n: "Adding a BGP neighbor can introduce new route exchange and requires peer validation.",
)


# ===================
# High-risk templates
# ===================

add_template(
    "interface_shutdown_critical",
    "high",
    (85, 98),
    ["interface", "connectivity", "routing"],
    lambda d, r, t, i, n: f"interface {i}\n ip address {ip(n)} 255.255.255.252\n no shutdown",
    lambda d, r, t, i, n: f"interface {i}\nshutdown",
    lambda d, r, t, i, n: "Shutting down this interface may break an uplink or routing adjacency based on the topology context.",
)

add_template(
    "remove_interface_ip",
    "high",
    (82, 90),
    ["interface", "routing", "connectivity"],
    lambda d, r, t, i, n: f"interface {i}\n ip address {ip(n)} 255.255.255.252\n no shutdown",
    lambda d, r, t, i, n: f"interface {i}\nno ip address",
    lambda d, r, t, i, n: "Removing the interface IP address can break directly connected reachability and routing adjacency.",
)

add_template(
    "remove_ospf_process",
    "high",
    (95, 100),
    ["ospf", "routing", "connectivity"],
    lambda d, r, t, i, n: "router ospf 1\n router-id 1.1.1.1\n network 10.0.0.0 0.0.0.255 area 0",
    lambda d, r, t, i, n: "no router ospf 1",
    lambda d, r, t, i, n: "Removing the OSPF process can remove adjacencies and all OSPF-learned routes.",
)

add_template(
    "acl_deny_any_inbound",
    "high",
    (95, 100),
    ["acl", "interface", "connectivity"],
    lambda d, r, t, i, n: f"interface {i}\n ip address {ip(n)} 255.255.255.252\n no shutdown",
    lambda d, r, t, i, n: f"access-list {random.randint(10, 99)} deny any\ninterface {i}\nip access-group {random.randint(10, 99)} in",
    lambda d, r, t, i, n: "Applying a deny-any ACL inbound can block all traffic entering the interface.",
)

add_template(
    "remove_default_route",
    "high",
    (90, 98),
    ["routing", "default_route", "internet_connectivity"],
    lambda d, r, t, i, n: "ip route 0.0.0.0 0.0.0.0 203.0.113.1",
    lambda d, r, t, i, n: "no ip route 0.0.0.0 0.0.0.0 203.0.113.1",
    lambda d, r, t, i, n: "Removing the default route can break reachability to external or unknown destinations.",
)

add_template(
    "remove_bgp_neighbor",
    "high",
    (90, 98),
    ["bgp", "routing", "wan"],
    lambda d, r, t, i, n: "router bgp 65001\n neighbor 203.0.113.2 remote-as 65002",
    lambda d, r, t, i, n: "router bgp 65001\nno neighbor 203.0.113.2",
    lambda d, r, t, i, n: "Removing a BGP neighbor can terminate route exchange and affect WAN or Internet reachability.",
)

add_template(
    "write_erase",
    "high",
    (100, 100),
    ["device", "configuration", "availability"],
    lambda d, r, t, i, n: f"hostname {d}\ninterface {i}\n no shutdown",
    lambda d, r, t, i, n: "write erase",
    lambda d, r, t, i, n: "Erasing startup configuration is destructive and may prevent recovery after reload.",
)

add_template(
    "reload",
    "high",
    (95, 100),
    ["device", "availability"],
    lambda d, r, t, i, n: f"hostname {d}\ninterface {i}\n no shutdown",
    lambda d, r, t, i, n: "reload",
    lambda d, r, t, i, n: "Reloading the device can cause an immediate outage.",
)

add_template(
    "remove_nat_overload",
    "high",
    (85, 95),
    ["nat", "internet_connectivity"],
    lambda d, r, t, i, n: "ip nat inside source list 10 interface GigabitEthernet0/0 overload",
    lambda d, r, t, i, n: "no ip nat inside source list 10 interface GigabitEthernet0/0 overload",
    lambda d, r, t, i, n: "Removing NAT overload can prevent internal hosts from reaching external networks.",
)

add_template(
    "management_lockout",
    "high",
    (90, 100),
    ["management", "ssh", "remote_access", "acl"],
    lambda d, r, t, i, n: "line vty 0 4\n transport input ssh\n access-class 10 in\naccess-list 10 permit 172.16.190.0 0.0.0.255",
    lambda d, r, t, i, n: "line vty 0 4\naccess-class 10 in\naccess-list 10 deny any",
    lambda d, r, t, i, n: "A deny-any ACL applied to VTY access can lock administrators out of the device.",
)


def generate_sample(sample_index: int, target_level: str = None):
    templates = [t for t in TEMPLATES if t["level"] == target_level] if target_level else TEMPLATES
    template = random.choice(templates)

    device, role, topology, ifname = sample_context()
    n = sample_index + random.randint(1, 500)

    score = random.randint(*template["score_range"])
    current_config = template["current_fn"](device, role, topology, ifname, n)
    proposed_change = template["proposed_fn"](device, role, topology, ifname, n)
    reason = template["reason_fn"](device, role, topology, ifname, n)

    sample_id = f"{template['level'].upper().replace('-', '_')}_{sample_index:04d}"

    return make_chat(
        sample_id=sample_id,
        category=template["category"],
        level=template["level"],
        score=score,
        device=device,
        role=role,
        topology=topology,
        current_config=current_config,
        proposed_change=proposed_change,
        areas=template["areas"],
        reason=reason,
        action=template["action"],
    )


def chat_only(sample: dict) -> dict:
    return {"messages": sample["messages"]}


def write_jsonl(path: Path, rows: list[dict]) -> None:
    with path.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(chat_only(row), ensure_ascii=False) + "\n")

def build_dataset(total_samples: int = TOTAL_SAMPLES) -> list[dict]:
    if total_samples % 4 != 0:
        raise ValueError("TOTAL_SAMPLES should be divisible by 4 for balanced risk labels.")

    samples_per_level = total_samples // 4
    samples = []

    for level in ["low", "medium", "medium-high", "high"]:
        for _ in range(samples_per_level):
            samples.append(generate_sample(len(samples) + 1, level))

    random.shuffle(samples)
    return samples

def write_metadata(output_dir: Path, samples: list[dict]) -> None:
    with (output_dir / "metadata.csv").open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=["sample_id", "category", "risk_level", "risk_score"],
        )
        writer.writeheader()

        for sample in samples:
            writer.writerow(
                {
                    "sample_id": sample["sample_id"],
                    "category": sample["category"],
                    "risk_level": sample["risk_level"],
                    "risk_score": sample["risk_score"],
                }
            )

def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    samples = build_dataset(TOTAL_SAMPLES)

    with (OUTPUT_DIR / "all_samples_with_metadata.jsonl").open("w", encoding="utf-8") as f:
        for sample in samples:
            f.write(json.dumps(sample, ensure_ascii=False) + "\n")

    write_metadata(OUTPUT_DIR, samples)

    # Copy this script into the output folder for reproducibility.
    script_path = Path(__file__)
    if script_path.exists():
        (OUTPUT_DIR / "generate_dataset.py").write_text(script_path.read_text(encoding="utf-8"), encoding="utf-8")

    zip_path = zip_dataset(OUTPUT_DIR)

    print(f"Created dataset in: {OUTPUT_DIR}")
    print(f"Total: {len(samples)}")
    print(Counter(sample["risk_level"] for sample in samples))


if __name__ == "__main__":
    main()
