# Security testing is integrated into the development process

`ISO27001-A.8.29-security-testing-in-development` · framework **iso27001** · severity **high** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.29 requires security testing processes to be defined and implemented in the development lifecycle. Concord verifies a cosigned attestation of the testing types (SAST/DAST/SCA), the integration points, and the gating criteria.

## Why it matters

Security testing gates are what stop known-vulnerable builds from reaching production.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security_testing attestation collected
- attestation kind is <value>, expected "security_testing"
- security_testing attestation missing required field: <value>
- security_testing review is overdue (next_review_due=<value>)
- security_testing review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.29-security-testing-in-development
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.29"
  nist_800_53:
  - "SA-11"
```
