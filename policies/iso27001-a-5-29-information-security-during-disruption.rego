package concord.iso27001.iso27001_a_5_29_information_security_during_disruption

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_29_information_security_during_disruption")
	msg := "ISO27001-A.5.29-information-security-during-disruption: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_29_information_security_during_disruption)
	msg := sprintf("ISO27001-A.5.29-information-security-during-disruption: attestation expired (expires_at=%s)", [input.iso27001_a_5_29_information_security_during_disruption.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_29_information_security_during_disruption, 365)
	msg := sprintf("ISO27001-A.5.29-information-security-during-disruption: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_29_information_security_during_disruption.last_review_at])
}
