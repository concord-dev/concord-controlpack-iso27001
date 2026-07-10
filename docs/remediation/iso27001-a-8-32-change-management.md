# Changes are subject to change management procedures

`ISO27001-A.8.32-change-management` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.32 requires changes to information processing facilities and systems to be subject to change management procedures. Concord verifies a cosigned attestation of the change process, the approval gates, and the rollback procedure.

## Why it matters

Unmanaged changes are a top cause of both outages and security regressions; change control is the guardrail.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no change_management attestation collected
- attestation kind is <value>, expected "change_management"
- change_management attestation missing required field: <value>
- change_management review is overdue (next_review_due=<value>)
- change_management review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.32-change-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.32"
  nist_800_53:
  - "CM-3"
```
