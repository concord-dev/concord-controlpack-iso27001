package concord.iso27001.a_5_8_information_security_in_project_management

import rego.v1

# ISO/IEC 27001:2022 A.5.8 — Information security is integrated into project management
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"project_risk_assessment", "security_gates", "integration_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no project_security attestation collected"
}

deny contains msg if {
	input.attestation.kind != "project_security"
	msg := sprintf("attestation kind is %q, expected \"project_security\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("project_security attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("project_security review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("project_security review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
