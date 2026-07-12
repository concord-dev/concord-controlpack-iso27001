package concord.iso27001.a_5_10_acceptable_use_of_information

import rego.v1

# ISO/IEC 27001:2022 A.5.10 — Acceptable use rules for information and assets are defined
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"acceptable_use_rules", "prohibited_activities", "acknowledgement_tracking", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no acceptable_use attestation collected"
}

deny contains msg if {
	input.attestation.kind != "acceptable_use"
	msg := sprintf("attestation kind is %q, expected \"acceptable_use\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("acceptable_use attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("acceptable_use review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("acceptable_use review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
