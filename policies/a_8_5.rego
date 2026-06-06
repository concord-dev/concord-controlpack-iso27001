package concord.iso27001.a_8_5

import rego.v1

# ISO 27001:2022 A.8.5 — Secure authentication.
# Adapted from: SOC 2 CC6.1 pattern (concord-controlpack-soc2/cc6_1.rego).

weak_factor_types := {"sms", "call", "email", "security_question"}

deny contains msg if {
    not input.okta_users
    msg := "no Okta evidence collected"
}

deny contains msg if {
    some user in input.okta_users.users
    user.status == "ACTIVE"
    not user.has_strong_mfa
    msg := sprintf("active user %q has no strong MFA factor enrolled", [user.email])
}

warn contains msg if {
    some user in input.okta_users.users
    user.status == "ACTIVE"
    user.has_strong_mfa
    has_weak_factor(user)
    msg := sprintf("user %q still has weak factors (SMS/call/email) enrolled — remove to prevent phishing-fallback", [user.email])
}

has_weak_factor(user) if {
    some f in user.factors
    f.status == "ACTIVE"
    f.type in weak_factor_types
}
