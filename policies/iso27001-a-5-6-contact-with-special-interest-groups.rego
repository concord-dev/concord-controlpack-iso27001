package concord.iso27001.a_5_6_contact_with_special_interest_groups

import rego.v1

# ISO/IEC 27001:2022 A.5.6 — Appropriate contacts with special interest groups are maintained
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"groups_identified", "participation", "intel_sharing_process", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no special_interest_groups attestation collected"
}

deny contains msg if {
	input.attestation.kind != "special_interest_groups"
	msg := sprintf("attestation kind is %q, expected \"special_interest_groups\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("special_interest_groups attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("special_interest_groups review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("special_interest_groups review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
