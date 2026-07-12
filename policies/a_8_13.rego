package concord.iso27001.a_8_13

import rego.v1

# ISO 27001:2022 A.8.13 — Information backup with verified restoration.

max_test_age_days := 90

deny contains msg if {
    not input.restore_tests
    msg := "no restore-test evidence collected"
}

deny contains msg if {
    count(input.restore_tests.tests) == 0
    msg := "no restore tests have ever been executed"
}

deny contains msg if {
    every test in input.restore_tests.tests {
        test.status != "succeeded"
    }
    msg := "no restore tests have ever succeeded"
}

deny contains msg if {
    latest := latest_test
    latest.age_days > max_test_age_days
    msg := sprintf("most recent restore test was %d days ago (max %d)", [latest.age_days, max_test_age_days])
}

deny contains msg if {
    latest := latest_test
    latest.status != "succeeded"
    msg := sprintf("most recent restore test (%s) failed: %s", [latest.id, latest.failure_reason])
}

latest_test := test if {
    sorted := [t |
        some t in input.restore_tests.tests
    ]
    sorted_by_age := [t |
        some t in sorted
        not has_younger(t, sorted)
    ]
    test := sorted_by_age[0]
}

has_younger(t, items) if {
    some other in items
    other.age_days < t.age_days
}
