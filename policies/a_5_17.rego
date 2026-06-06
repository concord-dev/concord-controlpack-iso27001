package concord.iso27001.a_5_17

import rego.v1

# ISO 27001:2022 A.5.17 — Authentication information.
# Adapted from: Prowler `iam_password_policy_*` family.

min_length := 12
max_age_days := 90
min_reuse_prevention := 12

deny contains msg if {
    not input.iam_password_policy
    msg := "no IAM password policy evidence collected"
}

deny contains msg if {
    input.iam_password_policy.minimum_password_length < min_length
    msg := sprintf("password policy length %d is below ISO-equivalent floor of %d", [input.iam_password_policy.minimum_password_length, min_length])
}

deny contains msg if {
    not input.iam_password_policy.require_lowercase_characters
    msg := "password policy does not require lowercase characters"
}

deny contains msg if {
    not input.iam_password_policy.require_uppercase_characters
    msg := "password policy does not require uppercase characters"
}

deny contains msg if {
    not input.iam_password_policy.require_numbers
    msg := "password policy does not require numbers"
}

deny contains msg if {
    not input.iam_password_policy.require_symbols
    msg := "password policy does not require symbols"
}

deny contains msg if {
    not input.iam_password_policy.password_reuse_prevention >= min_reuse_prevention
    msg := sprintf("password policy reuse prevention is below %d", [min_reuse_prevention])
}

deny contains msg if {
    not input.iam_password_policy.max_password_age <= max_age_days
    msg := sprintf("password max-age must be <= %d days", [max_age_days])
}
