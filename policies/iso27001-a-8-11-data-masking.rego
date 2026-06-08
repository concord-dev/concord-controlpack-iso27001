package concord.iso27001.iso27001_a_8_11_data_masking

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_11_data_masking")
	msg := "ISO27001-A.8.11-data-masking: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_11_data_masking)
	msg := sprintf("ISO27001-A.8.11-data-masking: attestation expired (expires_at=%s)", [input.iso27001_a_8_11_data_masking.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_11_data_masking, 365)
	msg := sprintf("ISO27001-A.8.11-data-masking: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_11_data_masking.last_review_at])
}
