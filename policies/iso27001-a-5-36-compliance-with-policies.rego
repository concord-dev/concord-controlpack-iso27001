package concord.iso27001.a_5_36_compliance_with_policies

import rego.v1

# ISO/IEC 27001:2022 A.5.36 — Compliance with information security policies is reviewed
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"review_process", "coverage", "exceptions_tracked", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no policy_compliance_review attestation collected"
}

deny contains msg if {
	input.attestation.kind != "policy_compliance_review"
	msg := sprintf("attestation kind is %q, expected \"policy_compliance_review\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("policy_compliance_review attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("policy_compliance_review review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("policy_compliance_review review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
