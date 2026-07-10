# Knowledge from incidents is used to improve controls

`ISO27001-A.5.27-learning-from-incidents` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.27 requires knowledge gained from incidents to reduce the likelihood or impact of future incidents. Concord verifies a cosigned attestation of the lessons-learned process, the resulting control improvements, and how they are tracked to closure.

## Why it matters

Incidents that do not feed back into control improvements are destined to recur.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident_learning attestation collected
- attestation kind is <value>, expected "incident_learning"
- incident_learning attestation missing required field: <value>
- incident_learning review is overdue (next_review_due=<value>)
- incident_learning review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.27-learning-from-incidents
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.27"
  nist_800_53:
  - "IR-4"
```
