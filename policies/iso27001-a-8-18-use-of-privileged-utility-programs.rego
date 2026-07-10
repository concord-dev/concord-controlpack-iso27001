package concord.iso27001.a_8_18_use_of_privileged_utility_programs

import rego.v1

# ISO/IEC 27001:2022 A.8.18 — Privileged utility programs are restricted and tightly controlled
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"restricted_utilities", "authorization_process", "monitoring", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no privileged_utilities attestation collected"
}

deny contains msg if {
	input.attestation.kind != "privileged_utilities"
	msg := sprintf("attestation kind is %q, expected \"privileged_utilities\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("privileged_utilities attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("privileged_utilities review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("privileged_utilities review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
