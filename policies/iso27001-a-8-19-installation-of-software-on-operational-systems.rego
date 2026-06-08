package concord.iso27001.iso27001_a_8_19_installation_of_software_on_operational_systems

import rego.v1
import data.concord.lib.attestation
import data.concord.lib.evidence

deny contains msg if {
	not evidence.present(input, "iso27001_a_8_19_installation_of_software_on_operational_systems")
	msg := "ISO27001-A.8.19-installation-of-software-on-operational-systems: no signed attestation submitted"
}

deny contains msg if {
	not attestation.not_expired(input.iso27001_a_8_19_installation_of_software_on_operational_systems)
	msg := sprintf("ISO27001-A.8.19-installation-of-software-on-operational-systems: attestation expired (expires_at=%s)", [input.iso27001_a_8_19_installation_of_software_on_operational_systems.expires_at])
}

deny contains msg if {
	not attestation.fresh(input.iso27001_a_8_19_installation_of_software_on_operational_systems, 365)
	msg := sprintf("ISO27001-A.8.19-installation-of-software-on-operational-systems: attestation not reviewed in 365 days (last_review_at=%s)", [input.iso27001_a_8_19_installation_of_software_on_operational_systems.last_review_at])
}
