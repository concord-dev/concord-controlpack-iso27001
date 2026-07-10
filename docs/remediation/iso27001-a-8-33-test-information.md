# Test information is selected, protected, and managed

`ISO27001-A.8.33-test-information` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.33 requires test information to be appropriately selected, protected, and managed. Concord verifies a cosigned attestation of the selection criteria (avoiding real PII where possible), the protection controls, and access restrictions.

## Why it matters

Production data copied into test environments is a frequent, avoidable exposure of real sensitive data.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no test_information_protection attestation collected
- attestation kind is <value>, expected "test_information_protection"
- test_information_protection attestation missing required field: <value>
- test_information_protection review is overdue (next_review_due=<value>)
- test_information_protection review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.33-test-information
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.33"
  nist_800_53:
  - "SA-15"
  - "SC-28"
```
