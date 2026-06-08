package concord.iso27001.iso27001_a_8_1_user_endpoint_devices

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_1_user_endpoint_devices")
	msg := "ISO27001-A.8.1-user-endpoint-devices: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_1_user_endpoint_devices.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.1-user-endpoint-devices: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
