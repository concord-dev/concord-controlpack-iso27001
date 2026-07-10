package concord.iso27001.a_5_25_assessment_of_information_security_events

import rego.v1

# ISO/IEC 27001:2022 A.5.25 — Information security events are assessed and classified
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"assessment_criteria", "classification_scheme", "escalation_thresholds", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no event_assessment attestation collected"
}

deny contains msg if {
	input.attestation.kind != "event_assessment"
	msg := sprintf("attestation kind is %q, expected \"event_assessment\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("event_assessment attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("event_assessment review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("event_assessment review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
