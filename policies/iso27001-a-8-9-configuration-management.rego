package concord.iso27001.a_8_9_configuration_management

import rego.v1

# ISO/IEC 27001:2022 A.8.9 — Configuration baselines exist and drift is detected
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"baseline_definition", "drift_detection", "enforcement", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no configuration_management attestation collected"
}

deny contains msg if {
	input.attestation.kind != "configuration_management"
	msg := sprintf("attestation kind is %q, expected \"configuration_management\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("configuration_management attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("configuration_management review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("configuration_management review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
