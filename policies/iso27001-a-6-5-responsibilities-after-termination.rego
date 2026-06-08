package concord.iso27001.iso27001_a_6_5_responsibilities_after_termination

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_6_5_responsibilities_after_termination")
	msg := "ISO27001-A.6.5-responsibilities-after-termination: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_6_5_responsibilities_after_termination)
	msg := sprintf("ISO27001-A.6.5-responsibilities-after-termination: attestation expired (expires_at=%s)", [input.iso27001_a_6_5_responsibilities_after_termination.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_6_5_responsibilities_after_termination, 365)
	msg := sprintf("ISO27001-A.6.5-responsibilities-after-termination: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_6_5_responsibilities_after_termination.last_review_at])
}
