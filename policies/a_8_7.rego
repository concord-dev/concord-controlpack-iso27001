package concord.iso27001.a_8_7

import rego.v1

# ISO 27001:2022 A.8.7 — Protection against malware.

deny contains msg if {
    not input.anti_malware
    msg := "no anti-malware evidence collected"
}

deny contains msg if {
    some region in input.anti_malware.active_regions
    not has_guardduty(region)
    msg := sprintf("GuardDuty disabled in active region %q", [region])
}

deny contains msg if {
    not input.anti_malware.inspector_account_enabled
    msg := "AWS Inspector is not enabled at the account level"
}

deny contains msg if {
    some scan_type in {"EC2", "ECR"}
    not scan_type in input.anti_malware.inspector_resource_scans
    msg := sprintf("Inspector is enabled but does not include %s resource scanning", [scan_type])
}

has_guardduty(region) if {
    some detector in input.anti_malware.guardduty_detectors
    detector.region == region
    detector.status == "ENABLED"
}
