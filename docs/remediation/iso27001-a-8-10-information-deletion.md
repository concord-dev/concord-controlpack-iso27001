# Information is deleted when no longer required

`ISO27001-A.8.10-information-deletion` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.10 requires information stored in systems, devices, or any other storage media to be deleted when no longer required. Concord verifies a cosigned attestation of the deletion policy, the deletion methods, and alignment with retention schedules.

## Why it matters

Over-retained data expands breach blast radius and violates data-minimisation obligations.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no information_deletion attestation collected
- attestation kind is <value>, expected "information_deletion"
- information_deletion attestation missing required field: <value>
- information_deletion review is overdue (next_review_due=<value>)
- information_deletion review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.10-information-deletion
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.10"
  nist_800_53:
  - "SI-12"
  - "MP-6"
```
