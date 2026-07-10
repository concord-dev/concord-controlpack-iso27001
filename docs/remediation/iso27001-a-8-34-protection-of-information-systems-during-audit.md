# Audit testing of operational systems is planned to minimise disruption

`ISO27001-A.8.34-protection-of-information-systems-during-audit` · framework **iso27001** · severity **low** · Technological Controls

## What this control checks

ISO/IEC 27001:2022 A.8.34 requires audit tests and other assurance activities involving operational systems to be planned and agreed to minimise disruption. Concord verifies a cosigned attestation of the audit planning process, the access scoping, and disruption-minimisation measures.

## Why it matters

Uncoordinated audit testing on production can itself cause outages or expose data; A.8.34 governs it.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no audit_protection attestation collected
- attestation kind is <value>, expected "audit_protection"
- audit_protection attestation missing required field: <value>
- audit_protection review is overdue (next_review_due=<value>)
- audit_protection review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.8.34-protection-of-information-systems-during-audit
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.8.34"
  nist_800_53:
  - "AU-5"
  - "CA-2"
```
