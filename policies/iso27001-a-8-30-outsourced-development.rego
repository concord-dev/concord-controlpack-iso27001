package concord.iso27001.iso27001_a_8_30_outsourced_development

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_30_outsourced_development")
	msg := "ISO27001-A.8.30-outsourced-development: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_30_outsourced_development)
	msg := sprintf("ISO27001-A.8.30-outsourced-development: attestation expired (expires_at=%s)", [input.iso27001_a_8_30_outsourced_development.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_30_outsourced_development, 365)
	msg := sprintf("ISO27001-A.8.30-outsourced-development: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_30_outsourced_development.last_review_at])
}
