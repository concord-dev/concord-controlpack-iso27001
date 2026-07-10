package concord.iso27001.a_8_29_security_testing_in_development

import rego.v1

# ISO/IEC 27001:2022 A.8.29 — Security testing is integrated into the development process
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"testing_types", "integration_points", "gating_criteria", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no security_testing attestation collected"
}

deny contains msg if {
	input.attestation.kind != "security_testing"
	msg := sprintf("attestation kind is %q, expected \"security_testing\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("security_testing attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("security_testing review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("security_testing review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
