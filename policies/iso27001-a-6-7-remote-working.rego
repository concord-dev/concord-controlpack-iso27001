package concord.iso27001.iso27001_a_6_7_remote_working

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_6_7_remote_working")
	msg := "ISO27001-A.6.7-remote-working: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_6_7_remote_working)
	msg := sprintf("ISO27001-A.6.7-remote-working: attestation expired (expires_at=%s)", [input.iso27001_a_6_7_remote_working.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_6_7_remote_working, 365)
	msg := sprintf("ISO27001-A.6.7-remote-working: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_6_7_remote_working.last_review_at])
}
