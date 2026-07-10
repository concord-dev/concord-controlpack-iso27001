package concord.iso27001.a_5_12_classification_of_information

import rego.v1

# ISO/IEC 27001:2022 A.5.12 — Information is classified according to legal, business, and security needs
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"classification_scheme", "criteria", "handling_rules", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no information_classification attestation collected"
}

deny contains msg if {
	input.attestation.kind != "information_classification"
	msg := sprintf("attestation kind is %q, expected \"information_classification\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("information_classification attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("information_classification review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("information_classification review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
