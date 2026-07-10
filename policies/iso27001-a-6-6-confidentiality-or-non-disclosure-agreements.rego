package concord.iso27001.a_6_6_confidentiality_or_non_disclosure_agreements

import rego.v1

# ISO/IEC 27001:2022 A.6.6 — Confidentiality / NDA agreements are signed where required
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"nda_requirements", "coverage", "review_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no nda_management attestation collected"
}

deny contains msg if {
	input.attestation.kind != "nda_management"
	msg := sprintf("attestation kind is %q, expected \"nda_management\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("nda_management attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("nda_management review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("nda_management review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
