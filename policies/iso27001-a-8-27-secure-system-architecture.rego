package concord.iso27001.iso27001_a_8_27_secure_system_architecture

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_27_secure_system_architecture")
	msg := "ISO27001-A.8.27-secure-system-architecture: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_27_secure_system_architecture)
	msg := sprintf("ISO27001-A.8.27-secure-system-architecture: attestation expired (expires_at=%s)", [input.iso27001_a_8_27_secure_system_architecture.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_27_secure_system_architecture, 365)
	msg := sprintf("ISO27001-A.8.27-secure-system-architecture: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_27_secure_system_architecture.last_review_at])
}
