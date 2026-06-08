package concord.iso27001.iso27001_a_5_11_return_of_assets

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_11_return_of_assets")
	msg := "ISO27001-A.5.11-return-of-assets: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_11_return_of_assets)
	msg := sprintf("ISO27001-A.5.11-return-of-assets: attestation expired (expires_at=%s)", [input.iso27001_a_5_11_return_of_assets.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_11_return_of_assets, 365)
	msg := sprintf("ISO27001-A.5.11-return-of-assets: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_11_return_of_assets.last_review_at])
}
