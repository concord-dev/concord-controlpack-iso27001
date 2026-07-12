package concord.iso27001.a_8_10_information_deletion

import rego.v1

# ISO/IEC 27001:2022 A.8.10 — Information is deleted when no longer required
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"deletion_policy", "methods", "retention_alignment", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no information_deletion attestation collected"
}

deny contains msg if {
	input.attestation.kind != "information_deletion"
	msg := sprintf("attestation kind is %q, expected \"information_deletion\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("information_deletion attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("information_deletion review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("information_deletion review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
