package concord.iso27001.a_5_5_contact_with_authorities

import rego.v1

# ISO/IEC 27001:2022 A.5.5 — Appropriate contacts with relevant authorities are maintained
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"authorities_identified", "contact_process", "escalation_triggers", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no authority_contacts attestation collected"
}

deny contains msg if {
	input.attestation.kind != "authority_contacts"
	msg := sprintf("attestation kind is %q, expected \"authority_contacts\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("authority_contacts attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("authority_contacts review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("authority_contacts review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
