package concord.iso27001.a_8_9_configuration_management

import rego.v1

# ISO/IEC 27001:2022 A.8.9 — Configuration management. Configurations, including
# security configurations, of hardware, software, services and networks must be
# established, documented, implemented, monitored and reviewed. In AWS this is
# demonstrated by the Config recorder being enabled and recording in every
# active region, so the configuration of all resources is continuously captured
# and drift is detectable. Evidence: AWS Config recorder status
# (input.config_recorders). Fail-closed: absent evidence, no active regions, or
# a non-recording region denies. Adapted from the FedRAMP CM-2 / PCI 2.2.1
# baseline-configuration pattern.

deny contains msg if {
	not input.config_recorders
	msg := "no AWS Config recorder evidence collected — configuration management cannot be demonstrated (ISO 27001 A.8.9)"
}

deny contains msg if {
	input.config_recorders
	count(object.get(input.config_recorders, "active_regions", [])) == 0
	msg := "no active regions reported — configuration recording cannot be demonstrated (ISO 27001 A.8.9)"
}

deny contains msg if {
	some region in input.config_recorders.active_regions
	not has_recording_in_region(region)
	msg := sprintf("AWS Config recorder is not recording in active region %q — resource configuration is not captured there (ISO 27001 A.8.9)", [region])
}

has_recording_in_region(region) if {
	some recorder in input.config_recorders.recorders
	recorder.region == region
	recorder.recording == true
}
