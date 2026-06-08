package concord.iso27001.iso27001_a_5_26_response_to_information_security_incidents

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_26_response_to_information_security_incidents")
	msg := "ISO27001-A.5.26-response-to-information-security-incidents: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_26_response_to_information_security_incidents)
	msg := sprintf("ISO27001-A.5.26-response-to-information-security-incidents: attestation expired (expires_at=%s)", [input.iso27001_a_5_26_response_to_information_security_incidents.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_26_response_to_information_security_incidents, 365)
	msg := sprintf("ISO27001-A.5.26-response-to-information-security-incidents: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_26_response_to_information_security_incidents.last_review_at])
}
