package concord.iso27001.a_5_16

import rego.v1

# ISO 27001:2022 A.5.16 — Identity management.
# Adapted from: Prowler `iam_no_root_access_key`, `iam_avoid_root_usage`,
# `iam_user_no_setup_initial_access_key`.

max_root_idle_days := 90

deny contains msg if {
    not input.iam_identity
    msg := "no IAM evidence collected"
}

deny contains msg if {
    input.iam_identity.account_access_keys_present > 0
    msg := "root account has access keys — identities must be uniquely attributable"
}

deny contains msg if {
    input.iam_identity.root_last_used_days_ago < max_root_idle_days
    msg := sprintf("root account used %d days ago — investigate", [input.iam_identity.root_last_used_days_ago])
}

deny contains msg if {
    some user in input.iam_identity.shared_credentials
    msg := sprintf("IAM principal %q shares credentials with %d users", [user.username, user.shared_count])
}

deny contains msg if {
    some user in input.iam_identity.users
    user.is_service_account
    user.has_console_login
    msg := sprintf("service account %q has console login enabled", [user.username])
}
