package concord.iso27001.a_5_30

import rego.v1

# ISO 27001:2022 A.5.30 — ICT readiness, backups.

min_retention_days := 35

deny contains msg if {
    not input.prod_backups
    msg := "no backup evidence collected"
}

deny contains msg if {
    some rds in input.prod_backups.rds_instances
    is_prod(rds)
    rds.backup_retention_period < min_retention_days
    msg := sprintf("production RDS %q backup retention %d days < %d", [rds.identifier, rds.backup_retention_period, min_retention_days])
}

deny contains msg if {
    some table in input.prod_backups.dynamodb_tables
    is_prod(table)
    not table.point_in_time_recovery_enabled
    msg := sprintf("production DynamoDB table %q has point-in-time recovery disabled", [table.name])
}

deny contains msg if {
    some vault in input.prod_backups.backup_vaults
    vault.holds_prod
    not vault.locked
    msg := sprintf("backup vault %q holds production data but is not vault-locked", [vault.name])
}

is_prod(resource) if {
    resource.tags.production == "true"
}

# doc 31 §4 — no fail-open tag gates: a resource with no 'production' tag is neither confirmed in-scope
# nor out-of-scope, so every deny above skips it and it would pass silently.
# Warn on the unclassified resource instead of ignoring it.

warn contains msg if {
    some resource in input.prod_backups.rds_instances
    not classified(resource)
    msg := sprintf("RDS instance %q has no production tag, so this control's checks did not apply to it — tag production=true to bring it into production scope or production=false to confirm it is out of scope", [resource.identifier])
}

warn contains msg if {
    some resource in input.prod_backups.dynamodb_tables
    not classified(resource)
    msg := sprintf("DynamoDB table %q has no production tag, so this control's checks did not apply to it — tag production=true to bring it into production scope or production=false to confirm it is out of scope", [resource.name])
}

classified(resource) if resource.tags.production == "true"

classified(resource) if resource.tags.production == "false"
