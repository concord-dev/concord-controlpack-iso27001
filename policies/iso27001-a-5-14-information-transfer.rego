package concord.iso27001.a_5_14_information_transfer

import rego.v1

# ISO/IEC 27001:2022 A.5.14 — Transfer of information is protected by transfer rules and agreements
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"transfer_rules", "agreements", "protection_mechanisms", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no information_transfer attestation collected"
}

deny contains msg if {
	input.attestation.kind != "information_transfer"
	msg := sprintf("attestation kind is %q, expected \"information_transfer\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("information_transfer attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("information_transfer review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("information_transfer review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
