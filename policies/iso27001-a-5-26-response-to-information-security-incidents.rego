package concord.iso27001.a_5_26_response_to_information_security_incidents

import rego.v1

# ISO/IEC 27001:2022 A.5.26 — Response to incidents follows documented procedures
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"response_procedures", "roles", "communication_plan", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no incident_response attestation collected"
}

deny contains msg if {
	input.attestation.kind != "incident_response"
	msg := sprintf("attestation kind is %q, expected \"incident_response\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("incident_response attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("incident_response review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("incident_response review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
