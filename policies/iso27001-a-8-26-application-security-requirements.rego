package concord.iso27001.iso27001_a_8_26_application_security_requirements

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_26_application_security_requirements")
	msg := "ISO27001-A.8.26-application-security-requirements: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_26_application_security_requirements)
	msg := sprintf("ISO27001-A.8.26-application-security-requirements: attestation expired (expires_at=%s)", [input.iso27001_a_8_26_application_security_requirements.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_26_application_security_requirements, 365)
	msg := sprintf("ISO27001-A.8.26-application-security-requirements: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_26_application_security_requirements.last_review_at])
}
