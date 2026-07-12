package concord.iso27001.a_5_27_learning_from_incidents

import rego.v1

# ISO/IEC 27001:2022 A.5.27 — Knowledge from incidents is used to improve controls
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"lessons_learned_process", "control_improvements", "tracking", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no incident_learning attestation collected"
}

deny contains msg if {
	input.attestation.kind != "incident_learning"
	msg := sprintf("attestation kind is %q, expected \"incident_learning\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident_learning attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("incident_learning review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("incident_learning review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
