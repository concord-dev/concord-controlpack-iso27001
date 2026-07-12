package concord.iso27001.a_8_3_information_access_restriction

import rego.v1

# ISO/IEC 27001:2022 A.8.3 — Access to information is restricted per the access control policy
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"access_control_policy", "restriction_mechanisms", "review_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no access_restriction attestation collected"
}

deny contains msg if {
	input.attestation.kind != "access_restriction"
	msg := sprintf("attestation kind is %q, expected \"access_restriction\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("access_restriction attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("access_restriction review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("access_restriction review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
