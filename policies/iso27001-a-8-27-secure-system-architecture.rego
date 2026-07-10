package concord.iso27001.a_8_27_secure_system_architecture

import rego.v1

# ISO/IEC 27001:2022 A.8.27 — Secure architecture principles are applied to system design
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"architecture_principles", "review_process", "patterns_library", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no secure_architecture attestation collected"
}

deny contains msg if {
	input.attestation.kind != "secure_architecture"
	msg := sprintf("attestation kind is %q, expected \"secure_architecture\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("secure_architecture attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("secure_architecture review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("secure_architecture review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
