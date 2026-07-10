package concord.iso27001.a_5_13_labelling_of_information

import rego.v1

# ISO/IEC 27001:2022 A.5.13 — Information labelling is consistent with the classification scheme
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"labelling_procedure", "label_types", "tooling", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no information_labelling attestation collected"
}

deny contains msg if {
	input.attestation.kind != "information_labelling"
	msg := sprintf("attestation kind is %q, expected \"information_labelling\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("information_labelling attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("information_labelling review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("information_labelling review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
