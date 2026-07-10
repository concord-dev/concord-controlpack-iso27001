# Information security events are assessed and classified

`ISO27001-A.5.25-assessment-of-information-security-events` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.25 requires assessing information security events and deciding if they are incidents. Concord verifies a cosigned attestation of the assessment criteria, the event classification scheme, and the escalation thresholds.

## Why it matters

Consistent triage criteria prevent both alert fatigue and missed incidents.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no event_assessment attestation collected
- attestation kind is <value>, expected "event_assessment"
- event_assessment attestation missing required field: <value>
- event_assessment review is overdue (next_review_due=<value>)
- event_assessment review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.25-assessment-of-information-security-events
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.25"
  nist_800_53:
  - "IR-4"
  - "AU-6"
```
