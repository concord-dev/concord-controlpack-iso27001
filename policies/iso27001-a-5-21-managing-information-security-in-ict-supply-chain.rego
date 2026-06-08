package concord.iso27001.iso27001_a_5_21_managing_information_security_in_ict_supply_chain

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_21_managing_information_security_in_ict_supply_chain")
	msg := "ISO27001-A.5.21-managing-information-security-in-ict-supply-chain: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_21_managing_information_security_in_ict_supply_chain)
	msg := sprintf("ISO27001-A.5.21-managing-information-security-in-ict-supply-chain: attestation expired (expires_at=%s)", [input.iso27001_a_5_21_managing_information_security_in_ict_supply_chain.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_21_managing_information_security_in_ict_supply_chain, 365)
	msg := sprintf("ISO27001-A.5.21-managing-information-security-in-ict-supply-chain: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_21_managing_information_security_in_ict_supply_chain.last_review_at])
}
