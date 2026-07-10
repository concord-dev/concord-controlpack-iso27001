# Secure architecture principles are applied to system design

`ISO27001-A.8.27-secure-system-architecture` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.27 requires principles for engineering secure systems to be established, documented, and applied. Concord verifies a cosigned attestation of the architecture principles, the design review process, and the secure-patterns library.

## Why it matters

Architectural flaws are the costliest to fix later; applying secure-design principles prevents whole vulnerability classes.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no secure_architecture attestation collected
- attestation kind is <value>, expected "secure_architecture"
- secure_architecture attestation missing required field: <value>
- secure_architecture review is overdue (next_review_due=<value>)
- secure_architecture review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.27-secure-system-architecture
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.27"
  nist_800_53:
  - "SA-8"
  - "PL-8"
```
