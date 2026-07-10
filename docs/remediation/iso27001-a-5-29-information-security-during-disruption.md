# Information security is maintained during business disruption

`ISO27001-A.5.29-information-security-during-disruption` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.29 requires information security to be maintained during disruption. Concord verifies a cosigned attestation of the continuity controls, the security posture in degraded mode, and the security-aware recovery priorities.

## Why it matters

Disruptions are exactly when controls are most likely to be bypassed 'to restore service' — A.5.29 guards against that.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security_during_disruption attestation collected
- attestation kind is <value>, expected "security_during_disruption"
- security_during_disruption attestation missing required field: <value>
- security_during_disruption review is overdue (next_review_due=<value>)
- security_during_disruption review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.29-information-security-during-disruption
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.29"
  nist_800_53:
  - "CP-2"
```
