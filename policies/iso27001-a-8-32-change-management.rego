package concord.iso27001.a_8_32_change_management

import rego.v1

# ISO/IEC 27001:2022 A.8.32 — Changes are subject to change management procedures
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"change_process", "approval_gates", "rollback_procedure", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no change_management attestation collected"
}

deny contains msg if {
	input.attestation.kind != "change_management"
	msg := sprintf("attestation kind is %q, expected \"change_management\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("change_management attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("change_management review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("change_management review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
