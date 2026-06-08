package concord.iso27001.iso27001_a_8_10_information_deletion

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_10_information_deletion")
	msg := "ISO27001-A.8.10-information-deletion: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_10_information_deletion)
	msg := sprintf("ISO27001-A.8.10-information-deletion: attestation expired (expires_at=%s)", [input.iso27001_a_8_10_information_deletion.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_10_information_deletion, 365)
	msg := sprintf("ISO27001-A.8.10-information-deletion: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_10_information_deletion.last_review_at])
}
