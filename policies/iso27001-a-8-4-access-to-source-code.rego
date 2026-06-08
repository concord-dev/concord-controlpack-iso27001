package concord.iso27001.iso27001_a_8_4_access_to_source_code

import rego.v1
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_4_access_to_source_code")
	msg := "ISO27001-A.8.4-access-to-source-code: github evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_4_access_to_source_code.repos
	not r.protected_default_branch
	msg := sprintf("ISO27001-A.8.4-access-to-source-code: %q default branch has no protection rule", [r.full_name])
}
