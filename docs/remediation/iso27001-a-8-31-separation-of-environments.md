# Development, test, and production environments are separated

`ISO27001-A.8.31-separation-of-environments` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.31 requires development, testing, and production environments to be separated and secured. Concord verifies a cosigned attestation of the separation method, the environments in scope, and the per-environment access controls.

## Why it matters

Mixing environments lets test mistakes and lower-trust access reach production data and systems.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no environment_separation attestation collected
- attestation kind is <value>, expected "environment_separation"
- environment_separation attestation missing required field: <value>
- environment_separation review is overdue (next_review_due=<value>)
- environment_separation review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.31-separation-of-environments
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.31"
  nist_800_53:
  - "CM-4"
  - "SC-7"
```
