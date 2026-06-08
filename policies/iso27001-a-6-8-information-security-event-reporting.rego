package concord.iso27001.iso27001_a_6_8_information_security_event_reporting

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_6_8_information_security_event_reporting")
	msg := "ISO27001-A.6.8-information-security-event-reporting: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_6_8_information_security_event_reporting)
	msg := sprintf("ISO27001-A.6.8-information-security-event-reporting: attestation expired (expires_at=%s)", [input.iso27001_a_6_8_information_security_event_reporting.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_6_8_information_security_event_reporting, 365)
	msg := sprintf("ISO27001-A.6.8-information-security-event-reporting: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_6_8_information_security_event_reporting.last_review_at])
}
