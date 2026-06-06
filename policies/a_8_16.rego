package concord.iso27001.a_8_16

import rego.v1

# ISO 27001:2022 A.8.16 — Monitoring activities (CloudTrail coverage).

deny contains msg if {
    not input.cloudtrail
    msg := "no CloudTrail evidence collected"
}

deny contains msg if {
    not has_multi_region_trail
    msg := "no multi-region CloudTrail trail is logging — A.8.16 requires monitoring coverage across every region"
}

deny contains msg if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region_trail
    trail.is_logging
    not records_management_events(trail)
    msg := sprintf("trail %q does not record management events", [trail.name])
}

has_multi_region_trail if {
    some trail in input.cloudtrail.trails
    trail.is_multi_region_trail
    trail.is_logging
}

records_management_events(trail) if {
    some selector in trail.event_selectors
    selector.include_management_events
}
