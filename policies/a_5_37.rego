package concord.iso27001.a_5_37

import rego.v1

# ISO 27001:2022 A.5.37 — Documented operating procedures.

required_runbooks := {
    "incident_response",
    "access_provisioning",
    "access_revocation",
    "backup_restore",
    "vulnerability_patching",
}

deny contains msg if {
    not input.attestation
    msg := "no runbook-catalogue attestation collected"
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "runbook-catalogue attestation cosign signature did not verify"
}

deny contains msg if {
    some required in required_runbooks
    not has_runbook(required)
    msg := sprintf("required runbook %q is missing from the catalogue", [required])
}

deny contains msg if {
    some runbook in input.attestation.attested_fields.runbooks
    runbook.review_age_days > 365
    msg := sprintf("runbook %q last reviewed %d days ago", [runbook.id, runbook.review_age_days])
}

has_runbook(id) if {
    some runbook in input.attestation.attested_fields.runbooks
    runbook.id == id
}
