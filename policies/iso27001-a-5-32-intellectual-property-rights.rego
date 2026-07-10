package concord.iso27001.a_5_32_intellectual_property_rights

import rego.v1

# ISO/IEC 27001:2022 A.5.32 — Intellectual property rights are protected
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"ip_protection_measures", "license_compliance_process", "monitoring", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no ip_rights attestation collected"
}

deny contains msg if {
	input.attestation.kind != "ip_rights"
	msg := sprintf("attestation kind is %q, expected \"ip_rights\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("ip_rights attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("ip_rights review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("ip_rights review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
