package concord.iso27001.a_8_1_user_endpoint_devices

import rego.v1

# ISO/IEC 27001:2022 A.8.1 — User endpoint devices. Information stored on,
# processed by, or accessible via user endpoint devices must be protected.
# Concord verifies this technically by reading the managed-device inventory from
# the identity/MDM provider (input.managed_devices.devices[]) and requiring every
# endpoint to be MDM-enrolled and full-disk encrypted. Fail-closed: no inventory
# is a denial, and a missing encryption/enrollment attribute is treated as
# non-compliant rather than compliant.

deny contains msg if {
	not input.managed_devices
	msg := "no managed-device inventory evidence collected"
}

deny contains msg if {
	some device in input.managed_devices.devices
	not device.disk_encryption == true
	msg := sprintf("endpoint %q does not have full-disk encryption enabled — ISO 27001 A.8.1", [device.id])
}

deny contains msg if {
	some device in input.managed_devices.devices
	not device.mdm_enrolled == true
	msg := sprintf("endpoint %q is not MDM-enrolled — ISO 27001 A.8.1", [device.id])
}
