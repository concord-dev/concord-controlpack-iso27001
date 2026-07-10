package concord.iso27001.a_8_19_installation_of_software_on_operational_systems

import rego.v1

# ISO/IEC 27001:2022 A.8.19 — Software installation on operational systems is controlled
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"installation_policy", "approval_process", "enforcement_mechanism", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no software_installation_control attestation collected"
}

deny contains msg if {
	input.attestation.kind != "software_installation_control"
	msg := sprintf("attestation kind is %q, expected \"software_installation_control\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("software_installation_control attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("software_installation_control review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("software_installation_control review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
