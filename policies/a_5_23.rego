package concord.iso27001.a_5_23

import rego.v1

# ISO 27001:2022 A.5.23 — Cloud services configuration recording.
# Adapted from: Prowler `config_recorder_all_regions_enabled`.

deny contains msg if {
    not input.config_recorder
    msg := "no AWS Config evidence collected"
}

deny contains msg if {
    some region in input.config_recorder.active_regions
    not has_recording_in_region(region)
    msg := sprintf("AWS Config recorder disabled in active region %q", [region])
}

deny contains msg if {
    some recorder in input.config_recorder.recorders
    recorder.recording
    not recorder.all_supported
    msg := sprintf("Config recorder %q in region %q is not recording all resource types", [recorder.name, recorder.region])
}

has_recording_in_region(region) if {
    some recorder in input.config_recorder.recorders
    recorder.region == region
    recorder.recording
}
