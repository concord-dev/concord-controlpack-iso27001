package concord.iso27001.iso27001_a_5_3_segregation_of_duties

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_3_segregation_of_duties")
	msg := "ISO27001-A.5.3-segregation-of-duties: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_3_segregation_of_duties)
	msg := sprintf("ISO27001-A.5.3-segregation-of-duties: attestation expired (expires_at=%s)", [input.iso27001_a_5_3_segregation_of_duties.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_3_segregation_of_duties, 365)
	msg := sprintf("ISO27001-A.5.3-segregation-of-duties: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_3_segregation_of_duties.last_review_at])
}
