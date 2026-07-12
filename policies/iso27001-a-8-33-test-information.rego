package concord.iso27001.a_8_33_test_information

import rego.v1

# ISO/IEC 27001:2022 A.8.33 — Test information is selected, protected, and managed
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"selection_criteria", "protection_controls", "access_restrictions", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no test_information_protection attestation collected"
}

deny contains msg if {
	input.attestation.kind != "test_information_protection"
	msg := sprintf("attestation kind is %q, expected \"test_information_protection\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("test_information_protection attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("test_information_protection review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("test_information_protection review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
