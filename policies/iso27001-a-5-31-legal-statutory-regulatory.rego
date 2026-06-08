package concord.iso27001.iso27001_a_5_31_legal_statutory_regulatory

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_31_legal_statutory_regulatory")
	msg := "ISO27001-A.5.31-legal-statutory-regulatory: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_31_legal_statutory_regulatory)
	msg := sprintf("ISO27001-A.5.31-legal-statutory-regulatory: attestation expired (expires_at=%s)", [input.iso27001_a_5_31_legal_statutory_regulatory.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_31_legal_statutory_regulatory, 365)
	msg := sprintf("ISO27001-A.5.31-legal-statutory-regulatory: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_31_legal_statutory_regulatory.last_review_at])
}
