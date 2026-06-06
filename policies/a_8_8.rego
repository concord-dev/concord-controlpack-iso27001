package concord.iso27001.a_8_8

import rego.v1

# ISO 27001:2022 A.8.8 — Management of technical vulnerabilities.

critical_sla_days := 7
high_sla_days := 30

deny contains msg if {
    not input.vuln_scan
    msg := "no vulnerability-scan evidence collected"
}

deny contains msg if {
    some issue in input.vuln_scan.issues
    issue.severity == "critical"
    issue.age_days > critical_sla_days
    msg := sprintf("CRITICAL vuln %q is %d days old (SLA %d) — %s", [issue.id, issue.age_days, critical_sla_days, issue.title])
}

deny contains msg if {
    some issue in input.vuln_scan.issues
    issue.severity == "high"
    issue.age_days > high_sla_days
    msg := sprintf("HIGH vuln %q is %d days old (SLA %d) — %s", [issue.id, issue.age_days, high_sla_days, issue.title])
}

warn contains msg if {
    some issue in input.vuln_scan.issues
    issue.severity == "high"
    issue.age_days <= high_sla_days
    issue.age_days > 14
    msg := sprintf("HIGH vuln %q approaching SLA (%d/%d days) — %s", [issue.id, issue.age_days, high_sla_days, issue.title])
}
