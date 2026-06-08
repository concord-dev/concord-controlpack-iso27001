package concord.iso27001.iso27001_a_8_12_data_leakage_prevention

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_12_data_leakage_prevention")
	msg := "ISO27001-A.8.12-data-leakage-prevention: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_12_data_leakage_prevention.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.12-data-leakage-prevention: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
