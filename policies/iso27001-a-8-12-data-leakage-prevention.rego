package concord.iso27001.a_8_12_data_leakage_prevention

import rego.v1

# ISO/IEC 27001:2022 A.8.12 — DLP controls are deployed on systems handling sensitive information
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"dlp_controls", "monitored_channels", "coverage", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no data_leakage_prevention attestation collected"
}

deny contains msg if {
	input.attestation.kind != "data_leakage_prevention"
	msg := sprintf("attestation kind is %q, expected \"data_leakage_prevention\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("data_leakage_prevention attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("data_leakage_prevention review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("data_leakage_prevention review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
