package concord.iso27001.iso27001_a_8_22_segregation_of_networks

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_22_segregation_of_networks")
	msg := "ISO27001-A.8.22-segregation-of-networks: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_22_segregation_of_networks.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.22-segregation-of-networks: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
