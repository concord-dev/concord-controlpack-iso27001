package concord.iso27001.a_5_34_privacy_and_pii

import rego.v1

# ISO/IEC 27001:2022 A.5.34 — Privacy and protection of PII is ensured per regulations
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"pii_inventory", "legal_basis", "data_subject_rights_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no privacy_pii attestation collected"
}

deny contains msg if {
	input.attestation.kind != "privacy_pii"
	msg := sprintf("attestation kind is %q, expected \"privacy_pii\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("privacy_pii attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("privacy_pii review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("privacy_pii review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
