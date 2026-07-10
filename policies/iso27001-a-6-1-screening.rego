package concord.iso27001.a_6_1_screening

import rego.v1

# ISO/IEC 27001:2022 A.6.1 — Background screening is done on candidates per legal requirements
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"screening_process", "roles_in_scope", "legal_compliance", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no background_screening attestation collected"
}

deny contains msg if {
	input.attestation.kind != "background_screening"
	msg := sprintf("attestation kind is %q, expected \"background_screening\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("background_screening attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("background_screening review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("background_screening review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
