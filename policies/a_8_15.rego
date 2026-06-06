package concord.iso27001.a_8_15

import rego.v1

# ISO 27001:2022 A.8.15 — Logging.

min_retention_days := 365

deny contains msg if {
    not input.cloudwatch_logs
    msg := "no CloudWatch Logs evidence collected"
}

deny contains msg if {
    some group in input.cloudwatch_logs.log_groups
    group.is_production
    not group.retention_in_days >= min_retention_days
    msg := sprintf("production log group %q retention is %d days (min %d)", [group.name, group.retention_in_days, min_retention_days])
}

deny contains msg if {
    some group in input.cloudwatch_logs.log_groups
    group.is_production
    not group.kms_key_id
    msg := sprintf("production log group %q is not KMS-encrypted", [group.name])
}
