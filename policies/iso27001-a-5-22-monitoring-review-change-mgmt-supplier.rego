package concord.iso27001.a_5_22_monitoring_review_change_mgmt_supplier

import rego.v1

# ISO/IEC 27001:2022 A.5.22 — Suppliers are monitored, reviewed, and managed for compliance
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"monitoring_cadence", "review_criteria", "change_management", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no supplier_monitoring attestation collected"
}

deny contains msg if {
	input.attestation.kind != "supplier_monitoring"
	msg := sprintf("attestation kind is %q, expected \"supplier_monitoring\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("supplier_monitoring attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("supplier_monitoring review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("supplier_monitoring review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
