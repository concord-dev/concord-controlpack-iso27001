package concord.iso27001.iso27001_a_6_6_confidentiality_or_non_disclosure_agreements

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_6_6_confidentiality_or_non_disclosure_agreements")
	msg := "ISO27001-A.6.6-confidentiality-or-non-disclosure-agreements: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_6_6_confidentiality_or_non_disclosure_agreements)
	msg := sprintf("ISO27001-A.6.6-confidentiality-or-non-disclosure-agreements: attestation expired (expires_at=%s)", [input.iso27001_a_6_6_confidentiality_or_non_disclosure_agreements.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_6_6_confidentiality_or_non_disclosure_agreements, 365)
	msg := sprintf("ISO27001-A.6.6-confidentiality-or-non-disclosure-agreements: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_6_6_confidentiality_or_non_disclosure_agreements.last_review_at])
}
