package concord.iso27001.a_5_18

import rego.v1

# ISO 27001:2022 A.5.18 — Access rights, reviewed quarterly.

max_cycle_age_days := 100

required_fields := {"cycle_id", "completed_at", "reviewers",
                    "decisions_total", "subjects_total"}

deny contains msg if {
    not input.attestation
    msg := "no access-review attestation collected"
}

deny contains msg if {
    input.attestation.kind != "access_review"
    msg := sprintf("attestation kind is %q, expected \"access_review\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("access-review attestation missing field: %s", [f])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "access-review attestation cosign signature did not verify"
}

deny contains msg if {
    input.attestation.attested_fields.cycle_age_days > max_cycle_age_days
    msg := sprintf("last access-review cycle completed %d days ago — A.5.18 requires quarterly cadence", [input.attestation.attested_fields.cycle_age_days])
}

deny contains msg if {
    input.attestation.attested_fields.decisions_total < input.attestation.attested_fields.subjects_total
    msg := sprintf("%d subjects in scope but only %d decisions recorded — review is incomplete",
        [input.attestation.attested_fields.subjects_total, input.attestation.attested_fields.decisions_total])
}
