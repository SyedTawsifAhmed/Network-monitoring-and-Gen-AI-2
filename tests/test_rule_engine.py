from src.rule_engine import evaluate_change, parse_ios_config

def test_parser_context_interface():
    parsed = parse_ios_config("""
interface GigabitEthernet2
description Link to R2
shutdown
router ospf 1
network 10.0.0.0 0.0.0.255 area 0
""")
    shutdown = [cmd for cmd in parsed if cmd.command == "shutdown"][0]
    assert shutdown.context_type == "interface"
    assert shutdown.context_name == "GigabitEthernet2"

def test_low_risk_description():
    result = evaluate_change("""
interface GigabitEthernet2
description Link to R2
""")
    assert result.rule_score == 5
    assert result.risk_level == "low"

def test_context_critical_shutdown():
    result = evaluate_change(
        proposed_change="""
interface GigabitEthernet2
shutdown
""",
        topology_context="GigabitEthernet2 carries OSPF adjacency to R2.",
        device_role="core_router",
    )
    assert result.rule_score == 95
    assert result.hard_stop_triggered is True

def test_acl_deny_any_inbound_combination():
    result = evaluate_change("""
access-list 20 deny any
interface GigabitEthernet2
ip access-group 20 in
""")
    assert result.rule_score == 100
    assert result.hard_stop_triggered is True
    assert any(f.rule_id == "ACL_DENY_ANY_APPLIED_INBOUND" for f in result.findings)

def test_remove_ospf_process():
    result = evaluate_change("no router ospf 1")
    assert result.rule_score == 100
    assert result.hard_stop_triggered is True

def test_full_config_diff_removed_ospf_network():
    current = """
router ospf 1
network 10.0.12.0 0.0.0.3 area 0
network 10.0.23.0 0.0.0.3 area 0
"""
    proposed = """
router ospf 1
network 10.0.12.0 0.0.0.3 area 0
"""
    result = evaluate_change(
        proposed_change=proposed,
        current_config=current,
        proposed_full_config=True,
    )
    assert result.rule_score >= 75
    assert any(f.rule_id == "REMOVED_OSPF_NETWORK_FROM_DIFF" for f in result.findings)
