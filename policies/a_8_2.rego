package concord.iso27001.a_8_2

import rego.v1

# ISO 27001:2022 A.8.2 — Privileged access rights.
# Adapted from: Prowler `iam_administrator_access_with_mfa`,
# `iam_no_administrator_access_with_access_key`,
# `iam_user_with_administrator_access_mfa_enabled`.

max_admin_count := 5

deny contains msg if {
    not input.iam_admins
    msg := "no IAM privileged-principals evidence collected"
}

deny contains msg if {
    count(input.iam_admins.administrators) > max_admin_count
    msg := sprintf("%d IAM principals carry AdministratorAccess — A.8.2 says privileged access must be restricted (target ≤ %d)", [count(input.iam_admins.administrators), max_admin_count])
}

deny contains msg if {
    some admin in input.iam_admins.administrators
    admin.has_access_key
    msg := sprintf("administrator %q holds a long-lived access key — admin access must be assumable, not static", [admin.username])
}

deny contains msg if {
    some admin in input.iam_admins.administrators
    not admin.mfa_enabled
    msg := sprintf("administrator %q is not MFA-enrolled", [admin.username])
}
