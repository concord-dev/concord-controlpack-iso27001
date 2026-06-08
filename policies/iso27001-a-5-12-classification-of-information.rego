package concord.iso27001.iso27001_a_5_12_classification_of_information

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_12_classification_of_information")
	msg := "ISO27001-A.5.12-classification-of-information: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_12_classification_of_information)
	msg := sprintf("ISO27001-A.5.12-classification-of-information: attestation expired (expires_at=%s)", [input.iso27001_a_5_12_classification_of_information.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_12_classification_of_information, 365)
	msg := sprintf("ISO27001-A.5.12-classification-of-information: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_12_classification_of_information.last_review_at])
}
