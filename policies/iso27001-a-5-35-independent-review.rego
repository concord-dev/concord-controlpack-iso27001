package concord.iso27001.iso27001_a_5_35_independent_review

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_5_35_independent_review")
	msg := "ISO27001-A.5.35-independent-review: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_5_35_independent_review)
	msg := sprintf("ISO27001-A.5.35-independent-review: attestation expired (expires_at=%s)", [input.iso27001_a_5_35_independent_review.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_5_35_independent_review, 365)
	msg := sprintf("ISO27001-A.5.35-independent-review: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_5_35_independent_review.last_review_at])
}
