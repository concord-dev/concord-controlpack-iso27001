# Compliance with information security policies is reviewed

`ISO27001-A.5.36-compliance-with-policies` · framework **iso27001** · severity **medium** · Organisational Controls

## What this control checks

ISO/IEC 27001:2022 A.5.36 requires regular review of compliance with the information security policy, standards, and procedures. Concord verifies a cosigned attestation of the review process, its coverage, and how exceptions are tracked.

## Why it matters

Policies that are never checked for compliance decay into shelfware; A.5.36 keeps them operative.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no policy_compliance_review attestation collected
- attestation kind is <value>, expected "policy_compliance_review"
- policy_compliance_review attestation missing required field: <value>
- policy_compliance_review review is overdue (next_review_due=<value>)
- policy_compliance_review review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.5.36-compliance-with-policies
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.5.36"
  nist_800_53:
  - "CA-2"
  - "PM-14"
```
