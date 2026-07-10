# Outsourced development is supervised and monitored

`ISO27001-A.8.30-outsourced-development` · framework **iso27001** · severity **medium** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.30 requires the organization to direct, monitor, and review outsourced system development activities. Concord verifies a cosigned attestation of the supervision process, the security requirements imposed on the supplier, and monitoring.

## Why it matters

Outsourced code inherits the vendor's security posture; supervision and requirements are how you govern that risk.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no outsourced_development attestation collected
- attestation kind is <value>, expected "outsourced_development"
- outsourced_development attestation missing required field: <value>
- outsourced_development review is overdue (next_review_due=<value>)
- outsourced_development review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.30-outsourced-development
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.30"
  nist_800_53:
  - "SA-4"
  - "SA-9"
```
