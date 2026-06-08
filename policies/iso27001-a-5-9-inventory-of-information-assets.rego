package concord.iso27001.iso27001_a_5_9_inventory_of_information_assets

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_9_inventory_of_information_assets")
	msg := "ISO27001-A.5.9-inventory-of-information-assets: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_9_inventory_of_information_assets)
	msg := sprintf("ISO27001-A.5.9-inventory-of-information-assets: attestation expired (expires_at=%s)", [input.iso27001_a_5_9_inventory_of_information_assets.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_9_inventory_of_information_assets, 365)
	msg := sprintf("ISO27001-A.5.9-inventory-of-information-assets: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_9_inventory_of_information_assets.last_review_at])
}
