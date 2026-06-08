package concord.iso27001.iso27001_a_8_21_security_of_network_services

import rego.v1
import data.concord.lib.collection
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_21_security_of_network_services")
	msg := "ISO27001-A.8.21-security-of-network-services: aws evidence missing"
}

deny contains msg if {
	some r in input.iso27001_a_8_21_security_of_network_services.resources
	not r.compliant
	msg := sprintf("ISO27001-A.8.21-security-of-network-services: resource %q is non-compliant (reason: %s)", [r.arn, r.reason])
}
