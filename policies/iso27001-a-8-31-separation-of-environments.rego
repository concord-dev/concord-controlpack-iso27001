package concord.iso27001.a_8_31_separation_of_environments

import rego.v1

# ISO/IEC 27001:2022 A.8.31 — Development, test, and production environments are separated
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"separation_method", "environments", "access_controls", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no environment_separation attestation collected"
}

deny contains msg if {
	input.attestation.kind != "environment_separation"
	msg := sprintf("attestation kind is %q, expected \"environment_separation\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("environment_separation attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("environment_separation review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("environment_separation review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
