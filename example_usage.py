from src.rule_engine import evaluate_change
import json

examples = [
    {
        "name": "Low risk description change",
        "proposed": """
interface GigabitEthernet2
description Link to R2
""",
        "topology": "GigabitEthernet2 connects R1 to R2.",
        "role": "core_router",
    },
    {
        "name": "High risk OSPF uplink shutdown",
        "proposed": """
interface GigabitEthernet2
shutdown
""",
        "topology": "GigabitEthernet2 connects R1 to R2 and carries OSPF adjacency.",
        "role": "core_router",
    },
    {
        "name": "Critical ACL deny any inbound",
        "proposed": """
access-list 20 deny any
interface GigabitEthernet2
ip access-group 20 in
""",
        "topology": "GigabitEthernet2 connects R1 to R2.",
        "role": "distribution_router",
    },
    {
        "name": "Critical routing process removal",
        "proposed": """
no router ospf 1
""",
        "topology": "R1 participates in OSPF area 0 with R2 and R3.",
        "role": "core_router",
    },
]

for example in examples:
    print("=" * 80)
    print(example["name"])
    print("=" * 80)

    result = evaluate_change(
        proposed_change=example["proposed"],
        topology_context=example["topology"],
        device_role=example["role"],
    )

    print(json.dumps(result.to_dict(), indent=2))
    print()
