package concord.iso27001.iso27001_a_8_14_redundancy_of_information_processing

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_14_redundancy_of_information_processing")
	msg := "ISO27001-A.8.14-redundancy-of-information-processing: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_14_redundancy_of_information_processing.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.14-redundancy-of-information-processing: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
