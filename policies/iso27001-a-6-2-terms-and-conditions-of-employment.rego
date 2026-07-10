package concord.iso27001.a_6_2_terms_and_conditions_of_employment

import rego.v1

# ISO/IEC 27001:2022 A.6.2 — Employment contracts state information security responsibilities
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"security_responsibilities_clause", "contract_coverage", "acknowledgement_tracking", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no employment_terms attestation collected"
}

deny contains msg if {
	input.attestation.kind != "employment_terms"
	msg := sprintf("attestation kind is %q, expected \"employment_terms\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("employment_terms attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("employment_terms review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("employment_terms review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
