package concord.iso27001.iso27001_a_5_28_collection_of_evidence

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_28_collection_of_evidence")
	msg := "ISO27001-A.5.28-collection-of-evidence: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_28_collection_of_evidence)
	msg := sprintf("ISO27001-A.5.28-collection-of-evidence: attestation expired (expires_at=%s)", [input.iso27001_a_5_28_collection_of_evidence.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_28_collection_of_evidence, 365)
	msg := sprintf("ISO27001-A.5.28-collection-of-evidence: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_28_collection_of_evidence.last_review_at])
}
