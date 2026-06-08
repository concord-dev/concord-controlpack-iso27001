package concord.iso27001.iso27001_a_5_8_information_security_in_project_management

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_8_information_security_in_project_management")
	msg := "ISO27001-A.5.8-information-security-in-project-management: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_8_information_security_in_project_management)
	msg := sprintf("ISO27001-A.5.8-information-security-in-project-management: attestation expired (expires_at=%s)", [input.iso27001_a_5_8_information_security_in_project_management.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_8_information_security_in_project_management, 365)
	msg := sprintf("ISO27001-A.5.8-information-security-in-project-management: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_8_information_security_in_project_management.last_review_at])
}
