package concord.iso27001.a_5_15

import rego.v1

# ISO/IEC 27001:2022 A.5.15 — Access-control policy attestation.

required_fields := {"approval_date", "approving_authority",
                    "last_reviewed_at", "next_review_due", "scope"}

deny contains msg if {
    not input.attestation
    msg := "no access-control-policy attestation collected"
}

deny contains msg if {
    input.attestation.kind != "access_control_policy"
    msg := sprintf("attestation kind is %q, expected \"access_control_policy\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("attestation missing required field: %s", [f])
}

deny contains msg if {
    review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
    review_due < time.now_ns()
    msg := sprintf("policy review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

deny contains msg if {
    not input.attestation.signature_verified
    msg := "attestation cosign signature did not verify"
}
