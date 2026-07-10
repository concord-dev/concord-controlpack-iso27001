# Background screening is done on candidates per legal requirements

`ISO27001-A.6.1-screening` · framework **iso27001** · severity **medium** · People Controls

## What this control checks

ISO/IEC 27001:2022 A.6.1 requires background verification checks on candidates proportional to business requirements and risk. Concord verifies a cosigned attestation of the screening process, the roles in scope, and legal compliance of the screening.

## Why it matters

Pre-employment screening is a primary insider-threat control and a common A.6.1 audit finding when undocumented.

## Evidence

Collected from the `attestation` source (`policy_attestation` evidence type).

## What a failure looks like

This control reports a finding when any of the following hold:

- no background_screening attestation collected
- attestation kind is <value>, expected "background_screening"
- background_screening attestation missing required field: <value>
- background_screening review is overdue (next_review_due=<value>)
- background_screening review due within 30 days (<value>)

## Remediation

Bring each affected resource or attestation listed under *What a failure looks like* into compliance, then re-collect evidence. Estimated effort: **2d**. Automated fix available: **false**.

## How to re-verify

```
concord check --controls <pack>/controls --framework iso27001 --control-id ISO27001-A.6.1-screening
```

A passing run reports this control green; in CI, `concord gate` exits non-zero while it fails.

## Cross-framework mappings

```
  iso27001:
  - "A.6.1"
  nist_800_53:
  - "PS-3"
```
