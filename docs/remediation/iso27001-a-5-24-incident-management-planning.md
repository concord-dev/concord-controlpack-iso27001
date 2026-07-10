# Information security incident response is planned and prepared

`ISO27001-A.5.24-incident-management-planning` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.24 requires planning and preparation for managing information security incidents. Concord verifies a cosigned attestation of the incident roles and responsibilities, the response procedures, and the preparation activities (tooling, training).

## Why it matters

An unplanned incident response is slow and error-prone; A.5.24 is the readiness foundation the rest of A.5.25-28 builds on.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident_planning attestation collected
- attestation kind is <value>, expected "incident_planning"
- incident_planning attestation missing required field: <value>
- incident_planning review is overdue (next_review_due=<value>)
- incident_planning review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.24-incident-management-planning
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.24"
  nist_800_53:
  - "IR-1"
  - "IR-8"
```
