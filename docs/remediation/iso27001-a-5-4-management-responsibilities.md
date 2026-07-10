# Management mandates adherence to information security policy

`ISO27001-A.5.4-management-responsibilities` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.4 requires management to require all personnel to apply information security per established policies. Concord verifies a cosigned attestation of the management directive, its enforcement mechanism, and how it is communicated.

## Why it matters

Visible management mandate is what auditors treat as evidence of tone-from-the-top and drives policy adherence.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no management_responsibilities attestation collected
- attestation kind is <value>, expected "management_responsibilities"
- management_responsibilities attestation missing required field: <value>
- management_responsibilities review is overdue (next_review_due=<value>)
- management_responsibilities review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.4-management-responsibilities
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.4"
  nist_800_53:
  - "PM-1"
  - "PL-4"
```
