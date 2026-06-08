package concord.iso27001.iso27001_a_6_1_screening

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_6_1_screening")
	msg := "ISO27001-A.6.1-screening: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_6_1_screening)
	msg := sprintf("ISO27001-A.6.1-screening: attestation expired (expires_at=%s)", [input.iso27001_a_6_1_screening.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_6_1_screening, 365)
	msg := sprintf("ISO27001-A.6.1-screening: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_6_1_screening.last_review_at])
}
