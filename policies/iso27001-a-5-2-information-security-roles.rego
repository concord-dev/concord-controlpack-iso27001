package concord.iso27001.iso27001_a_5_2_information_security_roles

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_2_information_security_roles")
	msg := "ISO27001-A.5.2-information-security-roles: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_2_information_security_roles)
	msg := sprintf("ISO27001-A.5.2-information-security-roles: attestation expired (expires_at=%s)", [input.iso27001_a_5_2_information_security_roles.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_2_information_security_roles, 365)
	msg := sprintf("ISO27001-A.5.2-information-security-roles: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_2_information_security_roles.last_review_at])
}
