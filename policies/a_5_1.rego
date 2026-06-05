package concord.iso27001.a_5_1

import rego.v1

# ISO/IEC 27001:2022 A.5.1 — information security policies attested
# annually by an approving authority.

required_fields := {"approval_date", "approving_authority",
                    "last_reviewed_at", "next_review_due"}

deny contains msg if {
    not input.attestation
    msg := "no information-security-policy attestation collected"
}

deny contains msg if {
    input.attestation.kind != "information_security_policy"
    msg := sprintf("attestation kind is %q, expected \"information_security_policy\"", [input.attestation.kind])
}

deny contains msg if {
    some f in required_fields
    not input.attestation.attested_fields[f]
    msg := sprintf("policy attestation missing required field: %s", [f])
}

deny contains msg if {
    review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
    review_due < time.now_ns()
    msg := sprintf("policy review is overdue (next_review_due=%s)", [input.attestation.attested_fields.next_review_due])
}

warn contains msg if {
    review_due := time.parse_rfc3339_ns(input.attestation.attested_fields.next_review_due)
    review_due < (time.now_ns() + 30 * 24 * 3600 * 1000 * 1000 * 1000)
    review_due >= time.now_ns()
    msg := sprintf("policy review due within 30 days (%s)", [input.attestation.attested_fields.next_review_due])
}
