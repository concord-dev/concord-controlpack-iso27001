package concord.iso27001.iso27001_a_8_17_clock_synchronisation

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_17_clock_synchronisation")
	msg := "ISO27001-A.8.17-clock-synchronisation: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_17_clock_synchronisation.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.17-clock-synchronisation: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
