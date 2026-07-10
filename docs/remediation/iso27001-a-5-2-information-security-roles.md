# Information security roles and responsibilities are formally assigned

`ISO27001-A.5.2-information-security-roles` · framework **iso27001** · severity **high** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.2 requires information security roles and responsibilities to be defined and allocated according to organizational needs. Concord verifies a cosigned attestation naming the defined roles, their responsibilities, and how authority is assigned, kept current by review.

## Why it matters

Unassigned or ambiguous security roles are a common root cause of unremediated findings; auditors expect named, accountable owners.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no security_roles attestation collected
- attestation kind is <value>, expected "security_roles"
- security_roles attestation missing required field: <value>
- security_roles review is overdue (next_review_due=<value>)
- security_roles review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.2-information-security-roles
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.2"
  nist_800_53:
  - "PM-2"
  - "PS-9"
```
