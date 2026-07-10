package concord.iso27001.a_8_30_outsourced_development

import rego.v1

# ISO/IEC 27001:2022 A.8.30 — Outsourced development is supervised and monitored
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"supervision_process", "security_requirements", "monitoring", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no outsourced_development attestation collected"
}

deny contains msg if {
	input.attestation.kind != "outsourced_development"
	msg := sprintf("attestation kind is %q, expected \"outsourced_development\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("outsourced_development attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("outsourced_development review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("outsourced_development review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
