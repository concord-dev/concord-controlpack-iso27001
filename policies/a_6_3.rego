package concord.iso27001.a_6_3

import rego.v1

# ISO 27001:2022 A.6.3 — Security awareness training, annual.

max_completion_age_days := 365

deny contains msg if {
    not input.attestation
    msg := "no training-register attestation collected"
}

deny contains msg if {
    input.attestation.kind != "training_register"
    msg := sprintf("attestation kind is %q, expected \"training_register\"", [input.attestation.kind])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "training-register attestation cosign signature did not verify"
}

deny contains msg if {
    some person in input.attestation.attested_fields.active_people
    not person_completed_in_window(person)
    msg := sprintf("active employee %q has no security-awareness completion in the last %d days", [person.email, max_completion_age_days])
}

person_completed_in_window(person) if {
    person.last_completion_days_ago <= max_completion_age_days
}
