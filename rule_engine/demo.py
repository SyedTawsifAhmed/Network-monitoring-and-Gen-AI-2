from src.rule_engine import evaluate_change
import json

print("Context-Aware Cisco IOS Rule Engine Demo")
print("---------------------------------------")
print("Paste Cisco IOS proposed commands.")
print("Press ENTER twice when done.\n")

lines = []
while True:
    line = input()
    if line == "":
        break
    lines.append(line)

proposed_change = "\n".join(lines)

result = evaluate_change(
    proposed_change=proposed_change,
    current_config="",
    topology_context="R1 connects to R2 using GigabitEthernet2 and carries OSPF Area 0.",
    device_role="core_router",
)

print("\nRule Engine Result:\n")
print(json.dumps(result.to_dict(), indent=2))
