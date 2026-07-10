# Response to incidents follows documented procedures

`ISO27001-A.5.26-response-to-information-security-incidents` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.26 requires incidents to be responded to per documented procedures. Concord verifies a cosigned attestation of the response procedures, the responder roles, and the incident communication plan.

## Why it matters

Documented, rehearsed response procedures are what keep containment fast and evidence intact under pressure.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no incident_response attestation collected
- attestation kind is <value>, expected "incident_response"
- incident_response attestation missing required field: <value>
- incident_response review is overdue (next_review_due=<value>)
- incident_response review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.26-response-to-information-security-incidents
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.26"
  nist_800_53:
  - "IR-4"
```
