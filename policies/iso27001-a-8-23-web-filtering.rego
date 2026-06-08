package concord.iso27001.iso27001_a_8_23_web_filtering

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_23_web_filtering")
	msg := "ISO27001-A.8.23-web-filtering: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_23_web_filtering.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.23-web-filtering: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
