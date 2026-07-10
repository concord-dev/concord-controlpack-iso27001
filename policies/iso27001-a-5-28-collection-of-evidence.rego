package concord.iso27001.a_5_28_collection_of_evidence

import rego.v1

# ISO/IEC 27001:2022 A.5.28 — Evidence collection during incidents follows forensics procedures
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"forensic_procedures", "chain_of_custody", "tooling", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no evidence_collection attestation collected"
}

deny contains msg if {
	input.attestation.kind != "evidence_collection"
	msg := sprintf("attestation kind is %q, expected \"evidence_collection\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("evidence_collection attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("evidence_collection review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= time.now_ns()
	msg := sprintf("evidence_collection review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
