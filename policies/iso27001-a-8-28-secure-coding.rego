package concord.iso27001.a_8_28_secure_coding

import rego.v1

# ISO/IEC 27001:2022 A.8.28 — Secure coding principles are applied during development
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"coding_standards", "sast_tooling", "developer_training", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no secure_coding attestation collected"
}

deny contains msg if {
	input.attestation.kind != "secure_coding"
	msg := sprintf("attestation kind is %q, expected \"secure_coding\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("secure_coding attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("secure_coding review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("secure_coding review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
