# Labeling Guide

## Risk levels

- `low`
  Minimal operational impact. Examples: interface description, banner, logging host, NTP server.

- `medium`
  May affect routing, monitoring, or connectivity for a limited scope. Examples: static route addition, OSPF network addition, interface IP change, SNMP community change.

- `medium-high`
  Could significantly affect connectivity, segmentation, routing behavior, or management access. Examples: trunk VLAN changes, OSPF cost changes, VTY access changes, BGP neighbor additions.

- `high`
  May cause outage, loss of routing, management lockout, broad traffic block, or destructive device state. Examples: interface shutdown on critical link, no router ospf, no BGP neighbor, deny-any ACL inbound, reload, write erase.

## Recommended actions

- `approve`: low-risk change can proceed with normal logging.
- `warn`: medium-risk change should be confirmed by the operator.
- `manual_review_required`: medium-high change should be reviewed by a network engineer.
- `reject_or_senior_approval_required`: high-risk or hard-stop change should be rejected unless approved by a senior engineer with rollback.
