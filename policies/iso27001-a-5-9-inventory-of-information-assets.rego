package concord.iso27001.a_5_9_inventory_of_information_assets

import rego.v1

# ISO/IEC 27001:2022 A.5.9 — Inventory of information assets is maintained and up to date
# Structured attestation (source: attestation / policy_attestation).

required_fields := {"inventory_scope", "owner_assignment", "review_cadence", "last_reviewed_at", "next_review_due"}

deny contains msg if {
	not input.attestation
	msg := "no asset_inventory attestation collected"
}

deny contains msg if {
	input.attestation.kind != "asset_inventory"
	msg := sprintf("attestation kind is %q, expected \"asset_inventory\"", [input.attestation.kind])
}

deny contains msg if {
	some f in required_fields
	not input.attestation.attested_fields[f]
	msg := sprintf("asset_inventory attestation missing required field: %s", [f])
}

deny contains msg if {
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < time.now_ns()
	msg := sprintf("asset_inventory review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
	now_ns := time.now_ns()
	review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
	review_due < (now_ns + 30 * 24 * 3600 * 1000 * 1000 * 1000)
	review_due >= now_ns
	msg := sprintf("asset_inventory review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
