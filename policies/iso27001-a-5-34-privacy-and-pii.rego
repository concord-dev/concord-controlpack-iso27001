package concord.iso27001.iso27001_a_5_34_privacy_and_pii

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_34_privacy_and_pii")
	msg := "ISO27001-A.5.34-privacy-and-pii: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_34_privacy_and_pii)
	msg := sprintf("ISO27001-A.5.34-privacy-and-pii: attestation expired (expires_at=%s)", [input.iso27001_a_5_34_privacy_and_pii.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_34_privacy_and_pii, 365)
	msg := sprintf("ISO27001-A.5.34-privacy-and-pii: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_34_privacy_and_pii.last_review_at])
}
