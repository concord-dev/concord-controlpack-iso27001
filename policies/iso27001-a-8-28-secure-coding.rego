package concord.iso27001.iso27001_a_8_28_secure_coding

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_28_secure_coding")
	msg := "ISO27001-A.8.28-secure-coding: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_28_secure_coding)
	msg := sprintf("ISO27001-A.8.28-secure-coding: attestation expired (expires_at=%s)", [input.iso27001_a_8_28_secure_coding.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_28_secure_coding, 365)
	msg := sprintf("ISO27001-A.8.28-secure-coding: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_28_secure_coding.last_review_at])
}
