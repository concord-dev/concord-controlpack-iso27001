package concord.iso27001.a_6_8_information_security_event_reporting

import rego.v1

# ISO/IEC 27001:2022 A.6.8 — Reporting channel for information security events is documented
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"reporting_channel", "reporting_timeframes", "awareness_communication", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no event_reporting attestation collected"
}

deny contains msg if {
	input.attestation.kind != "event_reporting"
	msg := sprintf("attestation kind is %q, expected \"event_reporting\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("event_reporting attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("event_reporting review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("event_reporting review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
