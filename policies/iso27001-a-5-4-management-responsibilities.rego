package concord.iso27001.iso27001_a_5_4_management_responsibilities

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_4_management_responsibilities")
	msg := "ISO27001-A.5.4-management-responsibilities: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_4_management_responsibilities)
	msg := sprintf("ISO27001-A.5.4-management-responsibilities: attestation expired (expires_at=%s)", [input.iso27001_a_5_4_management_responsibilities.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_4_management_responsibilities, 365)
	msg := sprintf("ISO27001-A.5.4-management-responsibilities: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_4_management_responsibilities.last_review_at])
}
