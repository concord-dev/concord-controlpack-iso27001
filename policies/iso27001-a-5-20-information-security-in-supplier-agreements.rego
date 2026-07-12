package concord.iso27001.a_5_20_information_security_in_supplier_agreements

import rego.v1

# ISO/IEC 27001:2022 A.5.20 — Information security requirements are agreed with each supplier
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"security_clauses", "agreement_coverage", "review_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no supplier_agreements attestation collected"
}

deny contains msg if {
	input.attestation.kind != "supplier_agreements"
	msg := sprintf("attestation kind is %q, expected \"supplier_agreements\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("supplier_agreements attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("supplier_agreements review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("supplier_agreements review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
