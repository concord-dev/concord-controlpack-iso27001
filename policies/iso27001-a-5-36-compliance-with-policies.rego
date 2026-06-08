package concord.iso27001.iso27001_a_5_36_compliance_with_policies

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_36_compliance_with_policies")
	msg := "ISO27001-A.5.36-compliance-with-policies: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_36_compliance_with_policies)
	msg := sprintf("ISO27001-A.5.36-compliance-with-policies: attestation expired (expires_at=%s)", [input.iso27001_a_5_36_compliance_with_policies.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_36_compliance_with_policies, 365)
	msg := sprintf("ISO27001-A.5.36-compliance-with-policies: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_36_compliance_with_policies.last_review_at])
}
