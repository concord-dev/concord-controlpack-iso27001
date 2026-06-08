package concord.iso27001.iso27001_a_8_25_secure_development_life_cycle

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_25_secure_development_life_cycle")
	msg := "ISO27001-A.8.25-secure-development-life-cycle: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_25_secure_development_life_cycle)
	msg := sprintf("ISO27001-A.8.25-secure-development-life-cycle: attestation expired (expires_at=%s)", [input.iso27001_a_8_25_secure_development_life_cycle.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_25_secure_development_life_cycle, 365)
	msg := sprintf("ISO27001-A.8.25-secure-development-life-cycle: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_25_secure_development_life_cycle.last_review_at])
}
