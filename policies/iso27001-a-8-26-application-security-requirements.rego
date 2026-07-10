package concord.iso27001.a_8_26_application_security_requirements

import rego.v1

# ISO/IEC 27001:2022 A.8.26 — Application security requirements are defined and tested
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"requirement_categories", "definition_process", "testing_verification", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no appsec_requirements attestation collected"
}

deny contains msg if {
	input.attestation.kind != "appsec_requirements"
	msg := sprintf("attestation kind is %q, expected \"appsec_requirements\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("appsec_requirements attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("appsec_requirements review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("appsec_requirements review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
