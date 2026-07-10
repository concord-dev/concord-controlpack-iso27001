# Secure coding principles are applied during development

`ISO27001-A.8.28-secure-coding` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.28 requires secure coding principles to be applied to software development. Concord verifies a cosigned attestation of the coding standards, the SAST tooling, and developer secure-coding training.

## Why it matters

Most application vulnerabilities originate in code; enforced secure-coding standards and SAST catch them early.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no secure_coding attestation collected
- attestation kind is <value>, expected "secure_coding"
- secure_coding attestation missing required field: <value>
- secure_coding review is overdue (next_review_due=<value>)
- secure_coding review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.28-secure-coding
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.28"
  nist_800_53:
  - "SA-15"
  - "SA-11"
```
