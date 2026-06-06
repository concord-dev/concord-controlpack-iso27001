package concord.iso27001.a_8_20

import rego.v1

# ISO 27001:2022 A.8.20 — Networks security.
# Adapted from: Prowler `vpc_flow_logs_enabled`.

deny contains msg if {
    not input.vpc_flow_logs
    msg := "no VPC flow-logs evidence collected"
}

deny contains msg if {
    some vpc in input.vpc_flow_logs.vpcs
    not vpc.flow_logs_enabled
    msg := sprintf("VPC %q in region %q has flow logs disabled", [vpc.id, vpc.region])
}
