package concord.iso27001.a_8_34_protection_of_information_systems_during_audit

import rego.v1

# ISO/IEC 27001:2022 A.8.34 — Audit testing of operational systems is planned to minimise disruption
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"audit_planning_process", "access_scoping", "disruption_minimisation", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no audit_protection attestation collected"
}

deny contains msg if {
	input.attestation.kind != "audit_protection"
	msg := sprintf("attestation kind is %q, expected \"audit_protection\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("audit_protection attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("audit_protection review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("audit_protection review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
