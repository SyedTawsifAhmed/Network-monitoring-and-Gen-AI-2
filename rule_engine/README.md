# Context-Aware Cisco IOS Rule Engine
1. Parses Cisco IOS hierarchy.
2. Knows whether a command is under `interface`, `router ospf`, `router bgp`, `line vty`, ACL, VLAN, etc.
3. Uses topology and device role to adjust risk.
4. Detects dangerous command combinations.
5. Can compare a current config to a full proposed config and detect removed lines.
6. Returns structured JSON output for Qwen/Gemini and the consensus scoring engine.

## Run the example

```bash
cd context_aware_rule_engine
python3 example_usage.py
```

## Run the interactive demo

```bash
python3 demo.py
```

Paste a Cisco IOS command block such as:

```cisco
interface GigabitEthernet2
 shutdown
```

Press ENTER twice.

## Use in another Python file

```python
from src.context_aware_rule_engine import evaluate_change

result = evaluate_change(
    proposed_change="interface GigabitEthernet2\n shutdown",
    current_config="interface GigabitEthernet2\n ip address 10.0.12.1 255.255.255.252\n no shutdown",
    topology_context="GigabitEthernet2 connects R1 to R2 and carries OSPF adjacency.",
    device_role="core_router",
)

print(result.to_json())
```

## Output fields

```json
{
  "rule_score": 95,
  "risk_level": "high",
  "decision_hint": "reject_or_senior_approval_required",
  "hard_stop_triggered": true,
  "findings": [],
  "affected_areas": [],
  "configuration_diff": [],
  "summary": "Triggered deterministic rule(s): INTERFACE_SHUTDOWN"
}
```

## Risk scoring

- 0–30: low
- 31–60: medium
- 61–80: medium-high
- 81–100: high

## Decision hints

- approve
- warn
- manual_review_required
- reject_or_senior_approval_required

## Recommended capstone use

This rule engine should run first. Its output should be included in the prompt sent to Qwen3 and Gemini.

Pipeline:

```text
Proposed Cisco IOS Change
        ↓
Context-Aware Rule Engine
        ↓
Qwen3 Local Model
        ↓
Gemini Cloud Model
        ↓
Consensus Scoring Engine
        ↓
Approve / Warn / Manual Review / Reject
```
