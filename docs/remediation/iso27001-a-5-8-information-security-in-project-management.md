# Information security is integrated into project management

`ISO27001-A.5.8-information-security-in-project-management` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.8 requires information security to be integrated into project management. Concord verifies a cosigned attestation of the per-project risk assessment, the security gates, and how security is integrated across the project lifecycle.

## Why it matters

Security bolted on after delivery is costlier and weaker; A.5.8 ensures risks are addressed at project inception.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no project_security attestation collected
- attestation kind is <value>, expected "project_security"
- project_security attestation missing required field: <value>
- project_security review is overdue (next_review_due=<value>)
- project_security review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.8-information-security-in-project-management
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.8"
  nist_800_53:
  - "SA-3"
  - "PL-2"
```
