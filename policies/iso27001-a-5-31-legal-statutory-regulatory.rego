package concord.iso27001.a_5_31_legal_statutory_regulatory

import rego.v1

# ISO/IEC 27001:2022 A.5.31 — Legal, statutory, and regulatory requirements are identified and met
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"applicable_requirements", "identification_process", "compliance_tracking", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no legal_requirements attestation collected"
}

deny contains msg if {
	input.attestation.kind != "legal_requirements"
	msg := sprintf("attestation kind is %q, expected \"legal_requirements\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("legal_requirements attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("legal_requirements review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("legal_requirements review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
