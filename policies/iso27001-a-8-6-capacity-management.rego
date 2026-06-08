package concord.iso27001.iso27001_a_8_6_capacity_management

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_6_capacity_management")
	msg := "ISO27001-A.8.6-capacity-management: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_6_capacity_management)
	msg := sprintf("ISO27001-A.8.6-capacity-management: attestation expired (expires_at=%s)", [input.iso27001_a_8_6_capacity_management.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_6_capacity_management, 365)
	msg := sprintf("ISO27001-A.8.6-capacity-management: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_6_capacity_management.last_review_at])
}
