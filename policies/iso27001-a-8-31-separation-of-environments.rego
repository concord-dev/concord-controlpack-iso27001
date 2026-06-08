package concord.iso27001.iso27001_a_8_31_separation_of_environments

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_31_separation_of_environments")
	msg := "ISO27001-A.8.31-separation-of-environments: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_31_separation_of_environments.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.31-separation-of-environments: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
