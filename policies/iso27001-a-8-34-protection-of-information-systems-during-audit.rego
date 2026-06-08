package concord.iso27001.iso27001_a_8_34_protection_of_information_systems_during_audit

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_34_protection_of_information_systems_during_audit")
	msg := "ISO27001-A.8.34-protection-of-information-systems-during-audit: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_34_protection_of_information_systems_during_audit)
	msg := sprintf("ISO27001-A.8.34-protection-of-information-systems-during-audit: attestation expired (expires_at=%s)", [input.iso27001_a_8_34_protection_of_information_systems_during_audit.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_34_protection_of_information_systems_during_audit, 365)
	msg := sprintf("ISO27001-A.8.34-protection-of-information-systems-during-audit: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_34_protection_of_information_systems_during_audit.last_review_at])
}
