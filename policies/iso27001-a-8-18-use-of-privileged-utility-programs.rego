package concord.iso27001.iso27001_a_8_18_use_of_privileged_utility_programs

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_18_use_of_privileged_utility_programs")
	msg := "ISO27001-A.8.18-use-of-privileged-utility-programs: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_18_use_of_privileged_utility_programs)
	msg := sprintf("ISO27001-A.8.18-use-of-privileged-utility-programs: attestation expired (expires_at=%s)", [input.iso27001_a_8_18_use_of_privileged_utility_programs.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_18_use_of_privileged_utility_programs, 365)
	msg := sprintf("ISO27001-A.8.18-use-of-privileged-utility-programs: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_18_use_of_privileged_utility_programs.last_review_at])
}
