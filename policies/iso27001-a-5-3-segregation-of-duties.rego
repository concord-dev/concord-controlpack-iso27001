package concord.iso27001.a_5_3_segregation_of_duties

import rego.v1

# ISO/IEC 27001:2022 A.5.3 — Conflicting duties are segregated to reduce fraud and error
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"conflicting_duties_matrix", "separation_controls", "review_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no segregation_of_duties attestation collected"
}

deny contains msg if {
	input.attestation.kind != "segregation_of_duties"
	msg := sprintf("attestation kind is %q, expected \"segregation_of_duties\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("segregation_of_duties attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("segregation_of_duties review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("segregation_of_duties review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
