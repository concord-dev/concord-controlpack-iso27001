package concord.iso27001.a_5_24_incident_management_planning

import rego.v1

# ISO/IEC 27001:2022 A.5.24 — Information security incident response is planned and prepared
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"roles_responsibilities", "procedures", "preparation_activities", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no incident_planning attestation collected"
}

deny contains msg if {
	input.attestation.kind != "incident_planning"
	msg := sprintf("attestation kind is %q, expected \"incident_planning\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident_planning attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("incident_planning review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("incident_planning review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
