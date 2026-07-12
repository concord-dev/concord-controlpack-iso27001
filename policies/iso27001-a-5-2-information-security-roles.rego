package concord.iso27001.a_5_2_information_security_roles

import rego.v1

# ISO/IEC 27001:2022 A.5.2 — Information security roles and responsibilities are formally assigned
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"defined_roles", "responsibilities", "authority_assignment", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no security_roles attestation collected"
}

deny contains msg if {
	input.attestation.kind != "security_roles"
	msg := sprintf("attestation kind is %q, expected \"security_roles\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("security_roles attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("security_roles review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("security_roles review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
