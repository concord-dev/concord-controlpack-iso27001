package concord.iso27001.a_5_7

import rego.v1

# ISO/IEC 27001:2022 A.5.7 — Threat Intelligence.
# Adapted from: Prowler `guardduty_is_enabled`,
# `guardduty_no_high_severity_findings`.

max_finding_age_days := 30

deny contains msg if {
    not input.guardduty
    msg := "no GuardDuty evidence collected"
}

deny contains msg if {
    some region in input.guardduty.regions_with_workloads
    not has_enabled_detector(region)
    msg := sprintf("GuardDuty disabled in region %q which carries production workloads", [region])
}

deny contains msg if {
    some finding in input.guardduty.high_severity_findings
    finding.age_days > max_finding_age_days
    msg := sprintf("HIGH-severity GuardDuty finding %q is %d days old — A.5.7 requires the threat-intel loop to close", [finding.id, finding.age_days])
}

warn contains msg if {
    some finding in input.guardduty.high_severity_findings
    finding.age_days <= max_finding_age_days
    msg := sprintf("active HIGH-severity GuardDuty finding %q (%d days old) in region %q", [finding.id, finding.age_days, finding.region])
}

has_enabled_detector(region) if {
    some detector in input.guardduty.detectors
    detector.region == region
    detector.status == "ENABLED"
}
