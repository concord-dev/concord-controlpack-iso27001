package concord.iso27001.iso27001_a_6_4_disciplinary_process

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_6_4_disciplinary_process")
	msg := "ISO27001-A.6.4-disciplinary-process: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_6_4_disciplinary_process)
	msg := sprintf("ISO27001-A.6.4-disciplinary-process: attestation expired (expires_at=%s)", [input.iso27001_a_6_4_disciplinary_process.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_6_4_disciplinary_process, 365)
	msg := sprintf("ISO27001-A.6.4-disciplinary-process: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_6_4_disciplinary_process.last_review_at])
}
