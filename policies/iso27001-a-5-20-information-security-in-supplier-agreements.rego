package concord.iso27001.iso27001_a_5_20_information_security_in_supplier_agreements

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_20_information_security_in_supplier_agreements")
	msg := "ISO27001-A.5.20-information-security-in-supplier-agreements: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_20_information_security_in_supplier_agreements)
	msg := sprintf("ISO27001-A.5.20-information-security-in-supplier-agreements: attestation expired (expires_at=%s)", [input.iso27001_a_5_20_information_security_in_supplier_agreements.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_20_information_security_in_supplier_agreements, 365)
	msg := sprintf("ISO27001-A.5.20-information-security-in-supplier-agreements: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_20_information_security_in_supplier_agreements.last_review_at])
}
