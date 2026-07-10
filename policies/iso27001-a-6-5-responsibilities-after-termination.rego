package concord.iso27001.a_6_5_responsibilities_after_termination

import rego.v1

# ISO/IEC 27001:2022 A.6.5 — Responsibilities remaining after termination are defined
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"continuing_obligations", "enforcement", "communication_at_exit", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no post_termination_responsibilities attestation collected"
}

deny contains msg if {
	input.attestation.kind != "post_termination_responsibilities"
	msg := sprintf("attestation kind is %q, expected \"post_termination_responsibilities\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("post_termination_responsibilities attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("post_termination_responsibilities review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("post_termination_responsibilities review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
