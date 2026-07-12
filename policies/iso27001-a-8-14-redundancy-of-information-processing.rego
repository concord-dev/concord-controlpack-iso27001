package concord.iso27001.a_8_14_redundancy_of_information_processing

import rego.v1

# ISO/IEC 27001:2022 A.8.14 — Availability is maintained via redundancy in critical components
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"redundant_components", "availability_targets", "failover_testing", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no redundancy attestation collected"
}

deny contains msg if {
	input.attestation.kind != "redundancy"
	msg := sprintf("attestation kind is %q, expected \"redundancy\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("redundancy attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("redundancy review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("redundancy review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
