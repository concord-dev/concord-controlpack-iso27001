package concord.iso27001.a_8_4_access_to_source_code

import rego.v1

# ISO/IEC 27001:2022 A.8.4 — Access to source code is restricted to authorised personnel
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"access_restrictions", "repository_controls", "review_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no source_code_access attestation collected"
}

deny contains msg if {
	input.attestation.kind != "source_code_access"
	msg := sprintf("attestation kind is %q, expected \"source_code_access\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("source_code_access attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("source_code_access review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("source_code_access review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
