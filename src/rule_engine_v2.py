"""
Cisco IOS-style configuration modifications using a context-aware deterministic rule engine.

1. Contextualizing the IOS configuration hierarchy.
2. Being aware of the locations of instructions such interface, router ospf, router bgp, line vty, ACL, and VLAN.
3. When both are available, comparing the suggested configuration or modification with the existing one.
4. Using device-role context and topology.
5. Identifying potentially harmful command combinations.
6. Providing organized results for Qwen/Gemini and a consensus scoring engine later on.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any, Tuple
import re
import difflib
import json
import argparse
from pathlib import Path


# -----------------------------
# Data classes
# -----------------------------

@dataclass
class ParsedCommand:
    context_type: str
    context_name: str
    command: str
    raw_line: str
    line_number: int


@dataclass
class RuleFinding:
    rule_id: str
    description: str
    score: int
    severity: str
    affected_areas: List[str]
    context_type: str
    context_name: str
    matched_command: str
    hard_stop: bool = False
    reason: str = ""


@dataclass
class RuleEngineResult:
    rule_score: int
    risk_level: str
    decision_hint: str
    hard_stop_triggered: bool
    findings: List[RuleFinding]
    affected_areas: List[str]
    configuration_diff: List[str]
    summary: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_score": self.rule_score,
            "risk_level": self.risk_level,
            "decision_hint": self.decision_hint,
            "hard_stop_triggered": self.hard_stop_triggered,
            "findings": [asdict(f) for f in self.findings],
            "affected_areas": self.affected_areas,
            "configuration_diff": self.configuration_diff,
            "summary": self.summary,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)


# -----------------------------
# Utility functions
# -----------------------------

def normalize_config(config: Optional[str]) -> str:
    if not config:
        return ""
    config = config.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in config.splitlines()).strip()


def is_parent_context(line: str) -> bool:
    stripped = line.strip().lower()
    if not stripped:
        return False

    # CML/Netmiko/Nornir command captures often remove indentation and may
    # use IOS abbreviations such as "int g0/1" instead of "interface g0/1".
    # The parser therefore treats these parent commands as configuration-mode
    # changes regardless of indentation.
    parent_prefixes = (
        "interface ",
        "int ",
        "router ospf",
        "router bgp",
        "router eigrp",
        "ip access-list ",
        "ipv6 access-list ",
        "line vty",
        "line console",
        "vlan ",
        "policy-map ",
        "class-map ",
        "route-map ",
        "ip prefix-list ",
        "ip nat ",
    )

    return any(stripped.startswith(prefix) for prefix in parent_prefixes)


def is_context_exit(line: str) -> bool:
    stripped = line.strip().lower()
    return stripped in {"exit", "end", "!", "do end"}


def get_context(line: str) -> Tuple[str, str]:
    stripped = line.strip()
    lower = stripped.lower()

    if lower.startswith("interface ") or lower.startswith("int "):
        return "interface", stripped.split(None, 1)[1]

    if lower.startswith("router ospf"):
        return "router_ospf", stripped

    if lower.startswith("router bgp"):
        return "router_bgp", stripped

    if lower.startswith("router eigrp"):
        return "router_eigrp", stripped

    if lower.startswith("ip access-list"):
        return "acl", stripped

    if lower.startswith("ipv6 access-list"):
        return "acl", stripped

    if lower.startswith("line vty"):
        return "line_vty", stripped

    if lower.startswith("line console"):
        return "line_console", stripped

    if lower.startswith("vlan "):
        return "vlan", stripped

    if lower.startswith("policy-map "):
        return "policy_map", stripped

    if lower.startswith("class-map "):
        return "class_map", stripped

    if lower.startswith("route-map "):
        return "route_map", stripped

    if lower.startswith("ip prefix-list "):
        return "prefix_list", stripped

    if lower.startswith("ip nat "):
        return "nat", "global"

    return "global", "global"


def parse_ios_config(config: str) -> List[ParsedCommand]:
    """
    This parser purposefully doesn't use indentation. IOS commands 
    are frequently represented as single, unindented lines in CML, 
    Netmiko, Nornir, terminal grabs, and AI-generated command blocks. 
    For instance:

    int g0/1 
    shutdown

    The parser functions more like the iOS CLI:
    The current configuration context is altered by a parent command 
    like "interface", "router ospf", or "line vty".
    Until another parent context is entered or an explicit "exit" or 
    "end" is observed, all further commands belong to that context.
    """
    config = normalize_config(config)
    if not config:
        return []

    parsed: List[ParsedCommand] = []
    current_type = "global"
    current_name = "global"

    for index, raw_line in enumerate(config.splitlines(), start=1):
        line = raw_line.rstrip()
        stripped = line.strip()

        if not stripped or stripped.startswith("!"):
            continue

        if is_context_exit(stripped):
            parsed.append(
                ParsedCommand(
                    context_type=current_type,
                    context_name=current_name,
                    command=stripped,
                    raw_line=line,
                    line_number=index,
                )
            )
            current_type, current_name = "global", "global"
            continue

        if is_parent_context(stripped):
            current_type, current_name = get_context(stripped)
            parsed.append(
                ParsedCommand(
                    context_type=current_type,
                    context_name=current_name,
                    command=stripped,
                    raw_line=line,
                    line_number=index,
                )
            )
            continue

        parsed.append(
            ParsedCommand(
                context_type=current_type,
                context_name=current_name,
                command=stripped,
                raw_line=line,
                line_number=index,
            )
        )

    return parsed


def make_diff(current_config: str, proposed_config: str) -> List[str]:
    current_lines = normalize_config(current_config).splitlines()
    proposed_lines = normalize_config(proposed_config).splitlines()
    return list(difflib.unified_diff(
        current_lines,
        proposed_lines,
        fromfile="current",
        tofile="proposed",
        lineterm=""
    ))


def risk_level_from_score(score: int) -> str:
    if score >= 81:
        return "high"
    if score >= 61:
        return "medium-high"
    if score >= 31:
        return "medium"
    return "low"


def decision_from_score(score: int, hard_stop: bool) -> str:
    if hard_stop:
        return "reject_or_senior_approval_required"
    if score >= 81:
        return "manual_review_required"
    if score >= 61:
        return "manual_review_required"
    if score >= 31:
        return "warn"
    return "approve"


def add_finding(
    findings: List[RuleFinding],
    rule_id: str,
    description: str,
    score: int,
    severity: str,
    affected_areas: List[str],
    cmd: ParsedCommand,
    hard_stop: bool = False,
    reason: str = "",
) -> None:
    findings.append(
        RuleFinding(
            rule_id=rule_id,
            description=description,
            score=score,
            severity=severity,
            affected_areas=affected_areas,
            context_type=cmd.context_type,
            context_name=cmd.context_name,
            matched_command=cmd.command,
            hard_stop=hard_stop,
            reason=reason,
        )
    )


def context_keywords(text: str) -> List[str]:
    lower = text.lower()
    keys = []
    for kw in [
        "core", "distribution", "access", "edge", "wan", "uplink", "ospf", "bgp",
        "management", "ssh", "internet", "provider", "default route", "trunk",
        "voice", "nat", "firewall"
    ]:
        if kw in lower:
            keys.append(kw)
    return keys


# -----------------------------
# Core rule engine
# -----------------------------

class CiscoIOSRuleEngine:
    def evaluate(
        self,
        proposed_change: str,
        current_config: Optional[str] = None,
        topology_context: Optional[str] = None,
        device_role: Optional[str] = None,
        proposed_full_config: bool = False,
    ) -> RuleEngineResult:
        """
        Evaluate a proposed Cisco IOS change.

        Args:
            proposed_change:
                Either the proposed change block or the full proposed config.
            current_config:
                Optional current config or current relevant snippet.
            topology_context:
                Optional topology context, such as "Gi2 connects to R2 and carries OSPF".
            device_role:
                Optional role, such as core_router, access_switch, edge_router.
            proposed_full_config:
                Set True if proposed_change is a complete proposed config rather than just a change block.

        Returns:
            RuleEngineResult
        """
        current_config = normalize_config(current_config)
        proposed_change = normalize_config(proposed_change)
        topology_context = topology_context or ""
        device_role = device_role or ""

        if proposed_full_config and current_config:
            diff = make_diff(current_config, proposed_change)
            parsed_commands = parse_ios_config(proposed_change)
            removed_lines = self._removed_lines_from_diff(diff)
        else:
            diff = make_diff(current_config, proposed_change) if current_config else []
            parsed_commands = parse_ios_config(proposed_change)
            removed_lines = []

        findings: List[RuleFinding] = []

        for cmd in parsed_commands:
            self._evaluate_command(cmd, findings, topology_context, device_role)

        self._evaluate_combinations(parsed_commands, findings, topology_context, device_role)
        self._evaluate_removed_lines(removed_lines, findings, topology_context, device_role)

        if not findings:
            score = 0
            hard_stop = False
            summary = "No deterministic high-risk IOS patterns were detected. This does not guarantee the change is safe."
        else:
            score = max(f.score for f in findings)
            hard_stop = any(f.hard_stop for f in findings)
            rules = sorted({f.rule_id for f in findings})
            summary = "Triggered deterministic rule(s): " + ", ".join(rules)

        areas = sorted({area for f in findings for area in f.affected_areas})

        return RuleEngineResult(
            rule_score=score,
            risk_level=risk_level_from_score(score),
            decision_hint=decision_from_score(score, hard_stop),
            hard_stop_triggered=hard_stop,
            findings=findings,
            affected_areas=areas,
            configuration_diff=diff[:80],  # Limit output size for API/demo readability.
            summary=summary,
        )

    def _evaluate_command(
        self,
        cmd: ParsedCommand,
        findings: List[RuleFinding],
        topology_context: str,
        device_role: str,
    ) -> None:
        c = cmd.command.strip()
        lower = c.lower()
        context_text = f"{topology_context} {device_role} {cmd.context_name}".lower()
        keywords = context_keywords(context_text)

        # Destructive global commands.
        if re.fullmatch(r"reload", lower):
            add_finding(
                findings, "RELOAD_DEVICE", "Reloads the device.", 100, "critical",
                ["device", "availability"], cmd, True,
                "Reload may cause an immediate outage."
            )

        if re.search(r"\bwrite\s+erase\b|\berase\s+startup-config\b", lower):
            add_finding(
                findings, "WRITE_ERASE", "Erases startup configuration.", 100, "critical",
                ["device", "configuration", "availability"], cmd, True,
                "Erasing startup configuration is destructive."
            )

        # Interface context.
        if cmd.context_type == "interface":
            if lower == "shutdown":
                score = 80
                hard_stop = False
                reason = "Interface shutdown can remove connectivity."

                if any(k in keywords for k in ["core", "uplink", "wan", "ospf", "bgp", "provider", "default route", "management"]):
                    score = 95
                    hard_stop = True
                    reason = "Interface appears critical based on role/topology context."

                add_finding(
                    findings, "INTERFACE_SHUTDOWN", "Shuts down an interface.", score,
                    "critical" if hard_stop else "high",
                    ["interface", "connectivity"], cmd, hard_stop, reason
                )

            if lower.startswith("no ip address"):
                add_finding(
                    findings, "REMOVE_INTERFACE_IP", "Removes an interface IP address.", 85, "high",
                    ["interface", "routing", "connectivity"], cmd, False,
                    "Removing an IP address can break routing adjacencies and directly connected reachability."
                )

            if re.match(r"ip address \d{1,3}(?:\.\d{1,3}){3} \d{1,3}(?:\.\d{1,3}){3}", lower):
                add_finding(
                    findings, "INTERFACE_IP_CHANGE", "Adds or changes interface IP address.", 50, "medium",
                    ["interface", "routing", "connectivity"], cmd, False,
                    "Changing interface addressing can affect reachability and routing."
                )

            if lower.startswith("description "):
                add_finding(
                    findings, "INTERFACE_DESCRIPTION_CHANGE", "Changes interface description.", 5, "low",
                    ["interface", "documentation"], cmd, False,
                    "Description changes do not affect traffic forwarding."
                )

            if re.match(r"ip access-group \S+ in", lower):
                add_finding(
                    findings, "ACL_APPLIED_INBOUND", "Applies ACL inbound on interface.", 70, "high",
                    ["acl", "interface", "connectivity"], cmd, False,
                    "Inbound ACLs can block traffic before routing decisions."
                )

            if re.match(r"ip access-group \S+ out", lower):
                add_finding(
                    findings, "ACL_APPLIED_OUTBOUND", "Applies ACL outbound on interface.", 60, "medium-high",
                    ["acl", "interface", "connectivity"], cmd, False,
                    "Outbound ACLs can block forwarded traffic."
                )

            if re.match(r"ip ospf cost \d+", lower):
                add_finding(
                    findings, "OSPF_COST_CHANGE", "Changes OSPF interface cost.", 55, "medium",
                    ["ospf", "routing", "traffic_engineering"], cmd, False,
                    "Changing OSPF cost can shift traffic paths."
                )

            if lower.startswith("switchport trunk allowed vlan"):
                add_finding(
                    findings, "TRUNK_ALLOWED_VLAN_CHANGE", "Changes trunk allowed VLAN list.", 65, "medium-high",
                    ["vlan", "trunk", "switching"], cmd, False,
                    "Changing allowed VLANs can disconnect VLANs across trunks."
                )

            if re.match(r"switchport access vlan \d+", lower):
                add_finding(
                    findings, "ACCESS_VLAN_CHANGE", "Changes access VLAN.", 40, "medium",
                    ["vlan", "switching", "endpoint_connectivity"], cmd, False,
                    "Changing access VLAN can move endpoints to another segment."
                )

            if re.match(r"(no )?service-policy (input|output)", lower):
                add_finding(
                    findings, "SERVICE_POLICY_CHANGE", "Applies or removes service policy.", 45, "medium",
                    ["qos", "performance"], cmd, False,
                    "QoS policy changes can affect traffic treatment."
                )

        # OSPF context/global removal.
        if lower.startswith("no router ospf"):
            add_finding(
                findings, "REMOVE_OSPF_PROCESS", "Removes OSPF process.", 100, "critical",
                ["ospf", "routing", "connectivity"], cmd, True,
                "Removing OSPF can remove adjacencies and learned routes."
            )

        if cmd.context_type == "router_ospf":
            if re.match(r"network \d{1,3}(?:\.\d{1,3}){3} \d{1,3}(?:\.\d{1,3}){3} area \S+", lower):
                add_finding(
                    findings, "OSPF_NETWORK_CHANGE", "Adds or changes OSPF network statement.", 45, "medium",
                    ["ospf", "routing"], cmd, False,
                    "OSPF network statements may advertise new prefixes or form new adjacencies."
                )
            if lower.startswith("no network "):
                add_finding(
                    findings, "OSPF_NETWORK_REMOVED", "Removes OSPF network statement.", 75, "high",
                    ["ospf", "routing", "connectivity"], cmd, False,
                    "Removing OSPF network statements may remove route advertisements or adjacencies."
                )
            if lower.startswith("passive-interface") or lower.startswith("no passive-interface"):
                add_finding(
                    findings, "OSPF_PASSIVE_INTERFACE_CHANGE", "Changes OSPF passive-interface behavior.", 60, "medium-high",
                    ["ospf", "adjacency", "routing"], cmd, False,
                    "Passive-interface changes can create or remove OSPF adjacencies."
                )

        # BGP.
        if lower.startswith("no router bgp"):
            add_finding(
                findings, "REMOVE_BGP_PROCESS", "Removes BGP process.", 100, "critical",
                ["bgp", "routing", "wan"], cmd, True,
                "Removing BGP can terminate external or internal route exchange."
            )

        if cmd.context_type == "router_bgp":
            if re.match(r"no neighbor \S+", lower):
                add_finding(
                    findings, "BGP_NEIGHBOR_REMOVED", "Removes BGP neighbor.", 95, "critical",
                    ["bgp", "routing", "wan"], cmd, True,
                    "Removing a BGP neighbor can terminate route exchange."
                )
            if re.match(r"neighbor \S+ remote-as \d+", lower):
                add_finding(
                    findings, "BGP_NEIGHBOR_ADDED_OR_CHANGED", "Adds or changes BGP neighbor.", 60, "medium-high",
                    ["bgp", "routing"], cmd, False,
                    "BGP neighbor changes can affect route exchange."
                )
            if lower.startswith("network "):
                add_finding(
                    findings, "BGP_NETWORK_CHANGE", "Changes BGP network advertisement.", 55, "medium",
                    ["bgp", "routing"], cmd, False,
                    "BGP network statements affect advertised prefixes."
                )

        # Static routes.
        if re.match(r"no ip route 0\.0\.0\.0 0\.0\.0\.0", lower):
            add_finding(
                findings, "REMOVE_DEFAULT_ROUTE", "Removes default route.", 95, "critical",
                ["routing", "default_route", "internet_connectivity"], cmd, True,
                "Removing the default route can break external reachability."
            )
        elif lower.startswith("no ip route "):
            add_finding(
                findings, "REMOVE_STATIC_ROUTE", "Removes static route.", 85, "high",
                ["routing", "static_route"], cmd, False,
                "Removing a static route can break reachability to a prefix."
            )
        elif re.match(r"ip route \d{1,3}(?:\.\d{1,3}){3} \d{1,3}(?:\.\d{1,3}){3} \S+", lower):
            add_finding(
                findings, "ADD_STATIC_ROUTE", "Adds static route.", 45, "medium",
                ["routing", "static_route"], cmd, False,
                "Static routes change forwarding for destination prefixes."
            )

        # ACL contexts and global numbered ACLs.
        if cmd.context_type == "acl" or lower.startswith("access-list "):
            if re.search(r"\bdeny\s+(ip\s+)?any(\s+any)?\b", lower):
                add_finding(
                    findings, "ACL_DENY_ANY", "ACL denies broad any traffic.", 95, "critical",
                    ["acl", "security", "connectivity"], cmd, True,
                    "Deny-any ACL entries may block broad traffic."
                )
            if re.search(r"\bpermit\s+(ip\s+)?any\s+any\b", lower):
                add_finding(
                    findings, "ACL_PERMIT_ANY_ANY", "ACL permits any-any traffic.", 65, "medium-high",
                    ["acl", "security"], cmd, False,
                    "Permit any-any may violate least-privilege security policy."
                )

        # VLAN context/global.
        if re.match(r"no vlan \d+", lower):
            add_finding(
                findings, "REMOVE_VLAN", "Removes VLAN.", 75, "high",
                ["vlan", "switching", "connectivity"], cmd, False,
                "Removing a VLAN can disconnect hosts in that segment."
            )

        # NAT.
        if re.match(r"no ip nat inside source .*overload", lower):
            add_finding(
                findings, "REMOVE_NAT_OVERLOAD", "Removes NAT overload/PAT.", 90, "high",
                ["nat", "internet_connectivity"], cmd, False,
                "Removing NAT overload can break outbound access for inside hosts."
            )
        elif lower.startswith("ip nat inside source"):
            add_finding(
                findings, "NAT_CHANGE", "Adds or changes NAT source translation.", 55, "medium",
                ["nat", "connectivity"], cmd, False,
                "NAT changes can affect internal-to-external reachability."
            )

        # Management and security.
        if cmd.context_type == "line_vty":
            if lower.startswith("transport input") or lower.startswith("access-class"):
                add_finding(
                    findings, "VTY_ACCESS_CHANGE", "Changes remote management access.", 70, "high",
                    ["management", "ssh", "remote_access"], cmd, False,
                    "VTY access changes can affect administrative reachability."
                )

        if re.match(r"username \S+ .*(secret|password)", lower):
            add_finding(
                findings, "USERNAME_SECRET_CHANGE", "Adds or changes local credentials.", 55, "medium",
                ["management", "authentication", "security"], cmd, False,
                "Credential changes affect management security."
            )

        if re.match(r"enable (secret|password)", lower):
            add_finding(
                findings, "ENABLE_SECRET_CHANGE", "Changes enable secret/password.", 65, "medium-high",
                ["management", "authentication", "security"], cmd, False,
                "Enable credential changes affect privileged access."
            )

        if lower.startswith("snmp-server community") or lower.startswith("no snmp-server community"):
            add_finding(
                findings, "SNMP_COMMUNITY_CHANGE", "Changes SNMP community.", 45, "medium",
                ["management", "snmp", "security"], cmd, False,
                "SNMP community changes affect monitoring and security exposure."
            )

        if lower.startswith("logging host"):
            add_finding(
                findings, "LOGGING_HOST_CHANGE", "Adds or changes syslog host.", 10, "low",
                ["management", "logging"], cmd, False,
                "Syslog destination changes generally improve or modify observability."
            )

        if lower.startswith("ntp server") or lower.startswith("no ntp server"):
            add_finding(
                findings, "NTP_SERVER_CHANGE", "Adds or removes NTP server.", 20, "low",
                ["management", "ntp"], cmd, False,
                "NTP changes affect time synchronization but generally not forwarding."
            )

        # QoS.
        if re.match(r"priority( percent)? \d+", lower):
            add_finding(
                findings, "QOS_PRIORITY_CHANGE", "Changes QoS priority behavior.", 50, "medium",
                ["qos", "voice", "performance"], cmd, False,
                "Priority queue changes can affect latency-sensitive traffic."
            )

    def _evaluate_combinations(
        self,
        parsed_commands: List[ParsedCommand],
        findings: List[RuleFinding],
        topology_context: str,
        device_role: str,
    ) -> None:
        rule_ids = {f.rule_id for f in findings}

        if "ACL_DENY_ANY" in rule_ids and "ACL_APPLIED_INBOUND" in rule_ids:
            pseudo = ParsedCommand(
                context_type="combination",
                context_name="acl_inbound",
                command="deny any + ip access-group in",
                raw_line="deny any + ip access-group in",
                line_number=0,
            )
            add_finding(
                findings,
                "ACL_DENY_ANY_APPLIED_INBOUND",
                "Deny-any ACL is applied inbound.",
                100,
                "critical",
                ["acl", "interface", "connectivity"],
                pseudo,
                True,
                "This combination can block all inbound traffic on the interface."
            )

        if "VTY_ACCESS_CHANGE" in rule_ids and "ACL_DENY_ANY" in rule_ids:
            pseudo = ParsedCommand(
                context_type="combination",
                context_name="management_acl",
                command="vty access change + deny any",
                raw_line="vty access change + deny any",
                line_number=0,
            )
            add_finding(
                findings,
                "MANAGEMENT_LOCKOUT_RISK",
                "Management ACL or VTY change may lock out administrators.",
                100,
                "critical",
                ["management", "ssh", "remote_access"],
                pseudo,
                True,
                "A deny-any ACL combined with management access changes can block administrative access."
            )

    def _removed_lines_from_diff(self, diff: List[str]) -> List[str]:
        removed = []
        for line in diff:
            if line.startswith("---"):
                continue
            if line.startswith("-"):
                removed.append(line[1:].strip())
        return removed

    def _evaluate_removed_lines(
        self,
        removed_lines: List[str],
        findings: List[RuleFinding],
        topology_context: str,
        device_role: str,
    ) -> None:
        """
        Detect risk from full-config diff removals.
        Useful when proposed_change is a full desired config.
        """
        for i, line in enumerate(removed_lines):
            lower = line.lower()
            pseudo = ParsedCommand(
                context_type="diff_removed",
                context_name="removed_config",
                command=line,
                raw_line=line,
                line_number=i + 1,
            )

            if lower.startswith("network ") and "area" in lower:
                add_finding(
                    findings,
                    "REMOVED_OSPF_NETWORK_FROM_DIFF",
                    "OSPF network statement removed in proposed config.",
                    75,
                    "high",
                    ["ospf", "routing", "connectivity"],
                    pseudo,
                    False,
                    "Removing an OSPF network can remove route advertisements or adjacencies."
                )

            if lower.startswith("neighbor ") and "remote-as" in lower:
                add_finding(
                    findings,
                    "REMOVED_BGP_NEIGHBOR_FROM_DIFF",
                    "BGP neighbor removed in proposed config.",
                    95,
                    "critical",
                    ["bgp", "routing", "wan"],
                    pseudo,
                    True,
                    "Removing a BGP neighbor can terminate route exchange."
                )

            if lower.startswith("ip route 0.0.0.0 0.0.0.0"):
                add_finding(
                    findings,
                    "REMOVED_DEFAULT_ROUTE_FROM_DIFF",
                    "Default route removed in proposed config.",
                    95,
                    "critical",
                    ["routing", "default_route", "internet_connectivity"],
                    pseudo,
                    True,
                    "Removing the default route can break external reachability."
                )


def evaluate_change(
    proposed_change: str,
    current_config: Optional[str] = None,
    topology_context: Optional[str] = None,
    device_role: Optional[str] = None,
    proposed_full_config: bool = False,
) -> RuleEngineResult:
    """Provide a simple public function for running the rule engine."""

    # Create the engine here so callers do not need to instantiate the class.
    engine = CiscoIOSRuleEngine()

    # Return the complete structured result to the calling application.
    return engine.evaluate(
        proposed_change=proposed_change,
        current_config=current_config,
        topology_context=topology_context,
        device_role=device_role,
        proposed_full_config=proposed_full_config,
    )


def save_result_to_json_file(
    result: RuleEngineResult,
    output_file: str = "rule_engine_output.json",
) -> Path:
    """Save the rule-engine result as a formatted JSON file.

    Args:
        result: The completed rule-engine evaluation result.
        output_file: Name or path of the JSON file to create.

    Returns:
        The Path of the saved JSON file.
    """

    output_path = Path(output_file)

    # Write the dictionary through json.dump so the generated file is valid,
    # human-readable JSON that can be consumed by other applications.
    with output_path.open("w", encoding="utf-8") as file:
        json.dump(result.to_dict(), file, indent=2, ensure_ascii=False)
        file.write("\n")

    return output_path


def read_multiline_input(prompt: str, required: bool = False) -> str:
    """Read a multiline value from the terminal until the user enters END.

    This is useful for configuration blocks because network changes normally
    contain several IOS commands. Blank optional sections are allowed by
    entering END immediately.
    """

    while True:
        print(f"\n{prompt}")
        print("Enter one command per line. Type END on a line by itself when finished.")

        lines: List[str] = []

        while True:
            try:
                line = input()
            except EOFError:
                # EOF also finishes the current block, which makes redirected
                # terminal input easier to use in scripts and test pipelines.
                break

            if line.strip().upper() == "END":
                break

            lines.append(line)

        value = "\n".join(lines).strip()

        if value or not required:
            return value

        print("A proposed configuration change is required. Please try again.")


def collect_interactive_input() -> Dict[str, Any]:
    """Collect rule-engine inputs from a person using the command line."""

    print("Cisco IOS Rule Engine")
    print("Provide the configuration information to evaluate.")

    proposed_change = read_multiline_input(
        "Proposed configuration commands:",
        required=True,
    )

    current_config = read_multiline_input(
        "Current configuration context (optional):"
    )

    topology_context = input(
        "\nTopology context (optional, press Enter to skip): "
    ).strip()

    device_role = input(
        "Device role (optional, for example core_router): "
    ).strip()

    full_config_answer = input(
        "Is the proposed input a complete desired configuration? [y/N]: "
    ).strip().lower()

    return {
        "proposed_change": proposed_change,
        "current_config": current_config,
        "topology_context": topology_context,
        "device_role": device_role,
        "proposed_full_config": full_config_answer in {"y", "yes"},
    }


def load_input_payload(input_file: str) -> Dict[str, Any]:
    """Load rule-engine input from a JSON file for automated integrations.

    Expected JSON fields:
        proposed_change: Required string containing the commands to evaluate.
        current_config: Optional current configuration or relevant snippet.
        topology_context: Optional topology description.
        device_role: Optional device role.
        proposed_full_config: Optional boolean indicating whether the proposed
            input is a complete desired configuration.
    """

    input_path = Path(input_file)

    with input_path.open("r", encoding="utf-8") as file:
        payload = json.load(file)

    if not isinstance(payload, dict):
        raise ValueError("The input JSON must contain a JSON object.")

    proposed_change = payload.get("proposed_change")

    if not isinstance(proposed_change, str) or not proposed_change.strip():
        raise ValueError(
            "The input JSON must contain a non-empty 'proposed_change' string."
        )

    proposed_full_config = payload.get("proposed_full_config", False)

    if not isinstance(proposed_full_config, bool):
        raise ValueError("'proposed_full_config' must be true or false.")

    return {
        "proposed_change": proposed_change,
        "current_config": payload.get("current_config") or "",
        "topology_context": payload.get("topology_context") or "",
        "device_role": payload.get("device_role") or "",
        "proposed_full_config": proposed_full_config,
    }


def build_argument_parser() -> argparse.ArgumentParser:
    """Create command-line options for manual and automated execution."""

    parser = argparse.ArgumentParser(
        description=(
            "Evaluate Cisco IOS configuration commands using the deterministic "
            "rule engine. Without --input-json, the program prompts for input."
        )
    )

    parser.add_argument(
        "--input-json",
        help=(
            "Optional JSON file containing proposed_change and related context. "
            "Use this option when another application invokes the rule engine."
        ),
    )

    parser.add_argument(
        "--output",
        default="rule_engine_output.json",
        help="JSON result file. Default: rule_engine_output.json",
    )

    return parser


def main() -> None:
    """Run the rule engine using either interactive or JSON-file input."""

    parser = build_argument_parser()
    args = parser.parse_args()

    try:
        # JSON input supports the future automated scoring and notification
        # pipeline. Interactive input remains convenient for manual testing.
        if args.input_json:
            payload = load_input_payload(args.input_json)
        else:
            payload = collect_interactive_input()

        result = evaluate_change(
            proposed_change=payload["proposed_change"],
            current_config=payload.get("current_config"),
            topology_context=payload.get("topology_context"),
            device_role=payload.get("device_role"),
            proposed_full_config=payload.get("proposed_full_config", False),
        )

        # Print the structured result for terminal users and calling processes.
        print("\nRule-engine result:\n")
        print(result.to_json())

        # Save the same validated structure to a standalone JSON file so the
        # scoring, reporting, and notification components can consume it.
        saved_path = save_result_to_json_file(result, args.output)
        print(f"\nRule-engine output saved to: {saved_path.resolve()}")

    except (OSError, json.JSONDecodeError, ValueError) as error:
        parser.exit(status=1, message=f"Error: {error}\n")


if __name__ == "__main__":
    main()
