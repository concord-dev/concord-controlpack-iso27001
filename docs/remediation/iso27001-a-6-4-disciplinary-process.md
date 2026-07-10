# Formal disciplinary process for policy violations is documented

`ISO27001-A.6.4-disciplinary-process` · framework **iso27001** · severity **medium** · People Controls

## What this control checks

ISO/IEC 27001:2022 A.6.4 requires a formalized and communicated disciplinary process for information security policy violations. Concord verifies a cosigned attestation of the process steps, the violation categories, and how the process is communicated.

## Why it matters

A consistent, communicated disciplinary process is what makes policy enforcement credible and deters violations.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no disciplinary_process attestation collected
- attestation kind is <value>, expected "disciplinary_process"
- disciplinary_process attestation missing required field: <value>
- disciplinary_process review is overdue (next_review_due=<value>)
- disciplinary_process review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.6.4-disciplinary-process
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.6.4"
  nist_800_53:
  - "PS-8"
```
