package concord.iso27001.iso27001_a_5_25_assessment_of_information_security_events

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_25_assessment_of_information_security_events")
	msg := "ISO27001-A.5.25-assessment-of-information-security-events: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_25_assessment_of_information_security_events)
	msg := sprintf("ISO27001-A.5.25-assessment-of-information-security-events: attestation expired (expires_at=%s)", [input.iso27001_a_5_25_assessment_of_information_security_events.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_25_assessment_of_information_security_events, 365)
	msg := sprintf("ISO27001-A.5.25-assessment-of-information-security-events: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_25_assessment_of_information_security_events.last_review_at])
}
