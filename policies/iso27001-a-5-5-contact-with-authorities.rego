package concord.iso27001.iso27001_a_5_5_contact_with_authorities

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_5_contact_with_authorities")
	msg := "ISO27001-A.5.5-contact-with-authorities: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_5_contact_with_authorities)
	msg := sprintf("ISO27001-A.5.5-contact-with-authorities: attestation expired (expires_at=%s)", [input.iso27001_a_5_5_contact_with_authorities.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_5_contact_with_authorities, 365)
	msg := sprintf("ISO27001-A.5.5-contact-with-authorities: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_5_contact_with_authorities.last_review_at])
}
