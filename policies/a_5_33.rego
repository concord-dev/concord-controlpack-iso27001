package concord.iso27001.a_5_33

import rego.v1

# ISO 27001:2022 A.5.33 — Protection of records (CloudTrail integrity).
# Adapted from: Prowler `cloudtrail_log_file_validation_enabled`.

deny contains msg if {
    not input.cloudtrail
    msg := "no CloudTrail evidence collected"
}

deny contains msg if {
    count(input.cloudtrail.trails) == 0
    msg := "no CloudTrail trails configured"
}

deny contains msg if {
    some trail in input.cloudtrail.trails
    trail.is_logging
    not trail.log_file_validation_enabled
    msg := sprintf("trail %q has log-file validation disabled", [trail.name])
}
