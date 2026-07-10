# Data masking is applied when protecting sensitive information

`ISO27001-A.8.11-data-masking` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.11 requires data masking to be used in accordance with the access control and business requirements. Concord verifies a cosigned attestation of the masking techniques, the scope of application, and the tooling.

## Why it matters

Masking limits exposure of sensitive fields to users and lower environments that do not need the clear values.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no data_masking attestation collected
- attestation kind is <value>, expected "data_masking"
- data_masking attestation missing required field: <value>
- data_masking review is overdue (next_review_due=<value>)
- data_masking review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.11-data-masking
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.11"
  nist_800_53:
  - "SC-28"
  - "AC-4"
```
